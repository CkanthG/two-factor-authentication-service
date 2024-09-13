package com.sree.security.controller;

import com.sree.security.dto.*;
import com.sree.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class TwoFactorAuthenticationController {

    private final UserService userService;

    @GetMapping("/registration")
    public String registration(Model model) {
        model.addAttribute("user", new UserDTO());
        model.addAttribute("roles", Role.values());
        return "registration";
    }

    @PostMapping("/login")
    public String userLogin(@ModelAttribute("authenticateDTO") AuthenticateDTO authenticateDTO, Model model) {
        AuthenticationResponse response = userService.authenticate(authenticateDTO);
        model.addAttribute("responseMessage", response);
        model.addAttribute("email", authenticateDTO.getEmail());
        if (response.isTfaEnabled()) {
            return "verify";
        }
        return "welcome";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/submitForm")
    public String userRegistration(@ModelAttribute("user") UserDTO userDTO, Model model) {
        var response = userService.createUser(userDTO);
        if (userDTO.isTfaEnabled()) {
            model.addAttribute("responseMessage", response);
            model.addAttribute("email", userDTO.getEmail());
        }
        model.addAttribute("message", "successfully user registered");
        return "result";
    }

    @PostMapping("/verify")
    public String userVerify(@ModelAttribute("verificationRequest") VerificationRequest verificationRequest, Model model) {
        AuthenticationResponse response = userService.verifyCode(verificationRequest);
        model.addAttribute("responseMessage", response);
        model.addAttribute("message", "successfully user loggedIn");
        return "welcome";
    }
}
