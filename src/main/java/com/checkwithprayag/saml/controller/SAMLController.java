package com.checkwithprayag.saml.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SAMLController {

    @GetMapping("/test-saml-sso")
    public String samlLogin() {
        return "SAML Login Successful!";
    }
}