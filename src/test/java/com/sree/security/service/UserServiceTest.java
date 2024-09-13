package com.sree.security.service;

import com.sree.security.dto.*;
import com.sree.security.entity.User;
import com.sree.security.repository.UserRepository;
import com.sree.security.tfa.TwoFactorAuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {

    @InjectMocks
    private UserService userService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private TwoFactorAuthenticationService twoFactorAuthenticationService;
    private UserDTO userDTO;
    User user;
    AuthenticationResponse authenticationResponse;
    AuthenticateDTO authenticateDTO;
    VerificationRequest verificationRequest;
    private final String token = "authenticated-token";
    private final String qrImageUri = "qr-code.png";
    private final String secret = "secret-key";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // given
        String name = "sree";
        String email = "sree@gmail.com";
        String password = "sree";
        userDTO = UserDTO.builder()
                .name(name)
                .email(email)
                .role(Role.USER)
                .password(password)
                .build();
        user = User.builder()
                .name(name)
                .email(email)
                .password(password)
                .role(Role.USER)
                .build();
        authenticationResponse = AuthenticationResponse.builder()
                .token(token)
                .tfaEnabled(true)
                .secretImageUri(qrImageUri)
                .build();
        authenticateDTO = AuthenticateDTO.builder()
                .email(email)
                .password(password)
                .build();
        String verificationCode = "123456";
        verificationRequest = VerificationRequest.builder()
                .email(email)
                .code(verificationCode)
                .build();
    }

    @Test
    void testCreateUser_WithTfaEnabled_Success() {
        // given
        user.setTfaEnabled(true);
        userDTO.setTfaEnabled(true);
        user.setSecret(secret);
        // when
        when(passwordEncoder.encode(userDTO.getPassword())).thenReturn(userDTO.getPassword());
        when(twoFactorAuthenticationService.generateNewSecret()).thenReturn(secret);
        when(userRepository.save(user)).thenReturn(user);
        when(jwtService.generateToken(user)).thenReturn(token);
        when(twoFactorAuthenticationService.generateQrCodeImageUri(secret)).thenReturn(qrImageUri);
        // then
        var actual = userService.createUser(userDTO);
        assertEquals(userDTO.isTfaEnabled(), actual.isTfaEnabled());
        // verify
        verify(passwordEncoder, times(1)).encode(userDTO.getPassword());
        verify(twoFactorAuthenticationService, times(1)).generateNewSecret();
        verify(userRepository, times(1)).save(user);
        verify(jwtService, times(1)).generateToken(user);
        verify(twoFactorAuthenticationService, times(1)).generateQrCodeImageUri(secret);
    }

    @Test
    void testCreateUser_WithoutTfaEnabled_Success() {
        // given
        user.setTfaEnabled(false);
        userDTO.setTfaEnabled(false);
        // when
        when(passwordEncoder.encode(userDTO.getPassword())).thenReturn(userDTO.getPassword());
        when(userRepository.save(user)).thenReturn(user);
        when(jwtService.generateToken(user)).thenReturn(token);
        when(twoFactorAuthenticationService.generateQrCodeImageUri(null)).thenReturn(qrImageUri);
        // then
        var actual = userService.createUser(userDTO);
        assertEquals(userDTO.isTfaEnabled(), actual.isTfaEnabled());
        // verify
        verify(passwordEncoder, times(1)).encode(userDTO.getPassword());
        verify(userRepository, times(1)).save(user);
        verify(jwtService, times(1)).generateToken(user);
        verify(twoFactorAuthenticationService, times(1)).generateQrCodeImageUri(null);
    }

    @Test
    void authenticate_WithTfaEnabled_Success() {
        // given
        user.setTfaEnabled(true);
        // when
        when(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticateDTO.getEmail(), authenticateDTO.getPassword()))
        ).thenReturn(any());
        when(userRepository.findByEmail(authenticateDTO.getEmail())).thenReturn(Optional.of(user));
        // then
        var actual = userService.authenticate(authenticateDTO);
        assertEquals(user.isTfaEnabled(), actual.isTfaEnabled());
        // verify
        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(authenticateDTO.getEmail(), authenticateDTO.getPassword())
        );
        verify(userRepository, times(1)).findByEmail(authenticateDTO.getEmail());
    }

    @Test
    void authenticate_WithoutTfaEnabled_Success() {
        // given
        user.setTfaEnabled(false);
        // when
        when(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticateDTO.getEmail(), authenticateDTO.getPassword()))
        ).thenReturn(any());
        when(userRepository.findByEmail(authenticateDTO.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(user)).thenReturn(token);
        // then
        var actual = userService.authenticate(authenticateDTO);
        assertEquals(user.isTfaEnabled(), actual.isTfaEnabled());
        assertEquals(token, actual.getToken());
        // verify
        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(authenticateDTO.getEmail(), authenticateDTO.getPassword())
        );
        verify(userRepository, times(1)).findByEmail(authenticateDTO.getEmail());
    }

    @Test
    void authenticate_ThrowsUsernameNotFoundException() {
        // when
        when(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticateDTO.getEmail(), authenticateDTO.getPassword()))
        ).thenReturn(any());
        assertThrows(
                UsernameNotFoundException.class,
                () -> userService.authenticate(authenticateDTO)
        );
    }

    @Test
    void verifyCode_WithValidData_Success() {
        // given
        user.setTfaEnabled(true);
        user.setSecret(secret);
        // when
        when(userRepository.findByEmail(verificationRequest.getEmail())).thenReturn(Optional.of(user));
        when(twoFactorAuthenticationService.isOtpNotValid(user.getSecret(), verificationRequest.getCode())).thenReturn(false);
        when(jwtService.generateToken(user)).thenReturn(token);
        // then
        var actual = userService.verifyCode(verificationRequest);
        assertEquals(user.isTfaEnabled(), actual.isTfaEnabled());
        assertEquals(token, actual.getToken());
        // verify
        verify(userRepository, times(1)).findByEmail(verificationRequest.getEmail());
        verify(twoFactorAuthenticationService, times(1)).isOtpNotValid(user.getSecret(), verificationRequest.getCode());
        verify(jwtService, times(1)).generateToken(user);
    }

    @Test
    void verifyCode_WithInValidData_ThrowsBadCredentialsException() {
        // given
        user.setTfaEnabled(true);
        user.setSecret(secret);
        // when
        when(userRepository.findByEmail(verificationRequest.getEmail())).thenReturn(Optional.of(user));
        when(twoFactorAuthenticationService.isOtpNotValid(user.getSecret(), verificationRequest.getCode())).thenReturn(true);
        assertThrows(
                BadCredentialsException.class,
                () -> userService.verifyCode(verificationRequest)
        );
    }

    @Test
    void verifyCode_WithInValidData_ThrowsUsernameNotFoundException() {
        assertThrows(
                UsernameNotFoundException.class,
                () -> userService.verifyCode(verificationRequest)
        );
    }
}