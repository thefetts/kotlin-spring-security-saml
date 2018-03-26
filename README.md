## Spring Security SAML Example
Configuration heavily informed by [this repo](https://github.com/vdenotaris/spring-boot-security-saml-sample)


## Setting up local SSO IDP
1. Make sure you have node installed
1. `git clone https://github.com/mcguinness/saml-idp.git`
1. `cd saml-idp`
1. `rm package-lock.json`
1. `npm install`
1. `openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Identity Provider' -keyout idp-private-key.pem -out idp-public-cert.pem -days 7300`
1. `node app.js --acs "http://localhost:8080" --aud "http://localhost:8080"`


## Generate a keystore
1. `keytool -genkey -alias spring -keyalg RSA -keystore KeyStore.jks -keysize 2048`
