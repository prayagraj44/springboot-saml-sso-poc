package com.checkwithprayag.saml.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SAMLMaintenanceController {

    @GetMapping("/ping-sso-login")
    public String samlLoginTest() {
        return "SAML SSO Login Successful!";
    }

    @PostMapping("/ping-sso-logout") // <- POST method since default Saml2LogoutConfigurer config is hardcoded to POST
    public String samlLogoutTest() {
        return "SAML SSO Login Successful!";
    }
}