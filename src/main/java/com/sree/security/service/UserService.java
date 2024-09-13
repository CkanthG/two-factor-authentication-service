package com.sree.security.service;

import com.sree.security.dto.AuthenticateDTO;
import com.sree.security.dto.AuthenticationResponse;
import com.sree.security.dto.UserDTO;
import com.sree.security.dto.VerificationRequest;
import com.sree.security.entity.User;
import com.sree.security.repository.UserRepository;
import com.sree.security.tfa.TwoFactorAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorAuthenticationService twoFactorAuthenticationService;

    public AuthenticationResponse createUser(UserDTO userDTO) {
        User user = User
                .builder()
                .name(userDTO.getName())
                .email(userDTO.getEmail())
                .password(passwordEncoder.encode(userDTO.getPassword()))
                .role(userDTO.getRole())
                .tfaEnabled(userDTO.isTfaEnabled())
                .build();

        if (userDTO.isTfaEnabled()) {
            user.setSecret(twoFactorAuthenticationService.generateNewSecret());
        }

        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(savedUser);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .tfaEnabled(user.isTfaEnabled())
                .secretImageUri(twoFactorAuthenticationService.generateQrCodeImageUri(user.getSecret()))
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticateDTO authenticateDTO) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticateDTO.getEmail(),
                        authenticateDTO.getPassword()
                )
        );
        var user = userRepository.findByEmail(authenticateDTO.getEmail()).orElseThrow(
                () -> new UsernameNotFoundException("User not found")
        );
        if (user.isTfaEnabled()) {
            return AuthenticationResponse.builder().token("").tfaEnabled(true).build();
        }
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).tfaEnabled(false).build();
    }

    public AuthenticationResponse verifyCode(VerificationRequest verificationRequest) {
        var user = userRepository.findByEmail(verificationRequest.getEmail()).orElseThrow(
                () -> new UsernameNotFoundException("User not found with " + verificationRequest.getEmail())
        );
        if (twoFactorAuthenticationService.isOtpNotValid(user.getSecret(), verificationRequest.getCode())) {
            throw new BadCredentialsException("Otp is not valid");
        }
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .tfaEnabled(user.isTfaEnabled())
                .build();
    }
}
