# springboot-saml-sso-poc
This repository demonstrates the integration of SAML SSO with a Spring Boot application. It provides a step-by-step implementation guide for setting up secure authentication using SAML 2.0 protocol, ideal for enterprise-level identity management


#gemerae 
openssl req -newkey rsa:2048 -nodes -keyout rp-key.key -x509 -days 365 -out rp-certificate.crt


##start keycloack locally on windows with given port in dev mode
bin\kc.bat start-dev --http-port=9999

##linux or wsl2 or git bash win
./bin/kc.sh start-dev --http-port=9999
