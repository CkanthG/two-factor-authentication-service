package com.sree.security.tfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TwoFactorAuthenticationServiceTest {

    private TwoFactorAuthenticationService twoFactorAuthenticationService;

    @BeforeEach
    void setUp() {
        twoFactorAuthenticationService = new TwoFactorAuthenticationService();
    }

    @Test
    void testGenerateNewSecret_WIthValidData_Success() {
        var actual = twoFactorAuthenticationService.generateNewSecret();
        assertNotNull(actual);
    }

    @Test
    void testGenerateQrCodeImageUri_WIthValidData_Success() {
        var actual = twoFactorAuthenticationService.generateQrCodeImageUri("secret");
        assertNotNull(actual);
    }

    @Test
    void testIsOtpValid_WIthValidData_Success() {
        var actual = twoFactorAuthenticationService.isOtpValid("secret", "123456");
        assertFalse(actual);
    }

    @Test
    void testIsOtpNotValid_WIthValidData_Success() {
        var actual = twoFactorAuthenticationService.isOtpNotValid("secret", "123456");
        assertTrue(actual);
    }
}