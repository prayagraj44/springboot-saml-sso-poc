package com.checkwithprayag.saml.config;

import org.opensaml.security.x509.X509Support;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .saml2Login(saml2 -> saml2.relyingPartyRegistrationRepository(relyingPartyRegistrations()))
                .saml2Logout(Customizer.withDefaults()) // for slo saml2
                .logout(logout-> logout.logoutSuccessUrl("/login"))  // any redirect url after successful logout
                .saml2Metadata(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        Resource signingCertResource = new ClassPathResource("public-cert.crt");
        Resource signingKeyResource = new ClassPathResource("private-key.key");

        try (
                InputStream is = signingKeyResource.getInputStream();
                InputStream certIS = signingCertResource.getInputStream();
        ) {
            X509Certificate rpCertificate = X509Support.decodeCertificate(certIS.readAllBytes());
            RSAPrivateKey rpKey = RsaKeyConverters.pkcs8().convert(is);
            final Saml2X509Credential rpSigningCredentials = Saml2X509Credential.signing(rpKey, rpCertificate);

            String apCertString = "MIICpTCCAY0CBgGRxlxSUjANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtwcmF5YWdyZWFsbTAeFw0yNDA5MDYwODAyMDRaFw0zNDA5MDYwODAzNDRaMBYxFDASBgNVBAMMC3ByYXlhZ3JlYWxtMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1SeNn9ms+sKnx0WXQotLI8titP+ROsLgp3YT+2p2sfI5TAQyLTkQ2mf1zVWa/tXsfh3Cgy88sKuazJf9A/Xt5ehyiW+s7+CpQYoImajFso8QhQ1TeU+uWByioGvprtRrphCcQbqKbZQGerNSiBilm6jipTYDxw9jgLEcaVEHgaFeYL6zRPhR7wsEbcc7RCp9t3FdL2y0XwQfOOGlOeLADDAWpwG0kWSfeOSi+q5719tY/zyKi1v0yV7IOHbPS1KTFbKl1DVq/MsoiGxhqiPJVXDIIY1u96QDo8HKMhoo2SoBN33EavmZWWwPKRNRqY1xMEaSlntPiXFzD4NSoU8tBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB9is9Uedtx6yDSKPYmP2+jevqrT3s4MqotINg7FL4ei7yB37voteBZ+kGhthAJEksI71tDn3oU3HMKPBhPHLtSMJvOGLBIEbfMOjeHXZJQuAvf222DikcHctrUXgiyj1jCSDGUkD86frghJAy61Dn1WRkbXpOPqcRJZEWNEkC6CInksWzkcDRLq67bIqWq+6TLxv1YM2kYK1i0YayQTvSkyFTZ3soQMRQXWI67hp/Xas27VJrRVyDsqyyA0fQcrL22WB+gYpfuE1M6PDG49Z4kNlmwMb3OSg9Tp4m7u2xRWA87X8RAcj1nPP7LVC7W2Yge0IgbUHtVpGIbjsTMN8gA";

            X509Certificate apCert = X509Support.decodeCertificate(apCertString);
            Saml2X509Credential apCredential = Saml2X509Credential.verification(apCert);

            RelyingPartyRegistration registration = RelyingPartyRegistrations
                    .fromMetadataLocation("http://localhost:9999/realms/prayagrealm/protocol/saml/descriptor")
                    .entityId("checkwithprayag-saml-app")
                    .registrationId("keycloak-9999")
                    .signingX509Credentials(c -> c.add(rpSigningCredentials))
                    .assertingPartyDetails(party -> party
                            .wantAuthnRequestsSigned(true)
                            .singleSignOnServiceBinding(Saml2MessageBinding.POST) //in some cases getting issue of cert not getting included in authn request xml after adding this it should resolve
                            .verificationX509Credentials(c -> c.add(apCredential))
                    )
                    .assertionConsumerServiceLocation("http://localhost:8888/login/saml2/sso/keycloak") // <- default asc url for spring-security-saml2-service-provider
                    .singleLogoutServiceLocation("http://localhost:8888/logout/saml2/slo")  // <- default slo  url for spring-security-saml2-service-provider
                    .build();
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

}

