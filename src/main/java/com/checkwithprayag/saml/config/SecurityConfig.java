package com.checkwithprayag.saml.config;

import org.opensaml.security.x509.X509Support;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/ping").permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers("**").authenticated()
                )
                .logout(logout -> logout
                        .logoutUrl("/")
                )
                .saml2Login(withDefaults())
                .saml2Logout(withDefaults());
        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
        Resource signingCertResource = new ClassPathResource("public-cert.crt");
        Resource signingKeyResource = new ClassPathResource("private-key.key");

        try (
                InputStream is = signingKeyResource.getInputStream();
                InputStream certIS = signingCertResource.getInputStream();
        ) {
            X509Certificate rpCertificate = X509Support.decodeCertificate(certIS.readAllBytes());
            RSAPrivateKey rpKey = RsaKeyConverters.pkcs8().convert(is);
            final Saml2X509Credential rpSigningCredentials = Saml2X509Credential.signing(rpKey, rpCertificate);

            String apCertString =  "MIICmzCCAYMCBgGRxllLrjANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwOTA2MDc1ODQ2WhcNMzQwOTA2MDgwMDI2WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMUOVookEWSbzTVP1NX2ZIS1HrjMsF8TKyPOYnVcf/fFgGga+rp2DucAJkSb/5hGrn+xGYoQVI+kLHwwsss/bQpNShA6Lzp5WsZpvfR5XEjEBYBRtkL2uI+SOCwe76dlV5G9OYuHQfp/1q93Mi8Aj/+BNZ4YJaKrVci2PmYR/wkcpO1QYuU5mxu+kaYKKEiuglb25YVNjfgOmIfe6+jYSmvbZWq8ABC3w0+GuB9f83dfRER7W1101nxPyUDe+ncrHnrCpmJyUo19X1zwjMGDP55tpZonrbAZwnZbDH2DLcRZHtnqePWABIbLRn4MML57WRJMcHbLtgik4ZiBrmBgYzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABc5Zsbtmu4ZujNcamOld2yMWNS23v71tiFBZ5AugwgpNPnFdFCGBlLa4wzMqlWSsIsHBTYbEriOO6eH0SHc/OKPoFfJLsLlgPfy21Aq6usuU4RWvG9eX7baCmehRh/Lv0JsK2OoBL5HmauwQwYY5vbOyRIzbYXVut/hamZ5hmbCaUR47sTKLHxjIylOEhQ62P99l4zWokU8ZVmvPC7Ubbsquysg9pbEk3SNY2XWoJIt2mLlqdk274uDvEqFZHEItNrHiVvU8/HvrlAX+zyQM+CyYDGVoJf2AYF61XQCsnLBioIVrPU2sHg8oxfXWIZ1pwIlNTOVdtN71XsxIyyFjxs=";

            X509Certificate apCert = X509Support.decodeCertificate(apCertString.getBytes());
            Saml2X509Credential apCredential = Saml2X509Credential.verification(apCert);

            RelyingPartyRegistration registration = RelyingPartyRegistrations
                    .fromMetadataLocation("metadataLocation")
                    .registrationId("saml-app")
                    .singleLogoutServiceLocation("{baseUrl}/logout/saml2/slo")
                    .signingX509Credentials(c -> c.add(rpSigningCredentials))
                    .assertingPartyDetails(party -> party
                            .wantAuthnRequestsSigned(true)
                            .verificationX509Credentials(c -> c.add(apCredential))
                    )
                    .build();
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        }
    }

//
//        @Bean
//    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
//        RelyingPartyRegistration registration = RelyingPartyRegistration
//                .withRegistrationId("keycloak")
//                .assertionConsumerServiceLocation("http://localhost:8080/login/saml2/sso/keycloak")
//                .entityId("http://localhost:8080/realms/master")
//                .("http://localhost:8080/realms/master/protocol/saml")
//                .signingX509Credentials(c -> c.addSigningX509Credential(
//                        X509Credential.builder()
//                                .privateKey("classpath:private.key")
//                                .certificate("classpath:public-cert.crt")
//                                .build()
//                ))
//                .build();
//
//        return new InMemoryRelyingPartyRegistrationRepository(registration);
//    }
}

