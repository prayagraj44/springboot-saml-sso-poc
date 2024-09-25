package com.checkwithprayag.saml.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class SAMLMaintenanceController {

    @GetMapping("/ping-sso-login")
    public String samlLoginTest() {
        return "SAML SSO Login Successful!";
    }

    @PostMapping("/ping-sso-logout") // <- POST method since default Saml2LogoutConfigurer config is hardcoded to POST
    public void samlLogoutTest() {
        System.out.println("logged-out");
    }

    @GetMapping("/load-saml-testing-page")
    public String loadSamlTestPage(){
        return "saml-testing-page.html";
    }
}