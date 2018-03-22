package com.thefetts.kotlinsaml

import org.opensaml.util.resource.ClasspathResource
import org.opensaml.util.resource.Resource
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.context.SAMLContextProviderLB
import org.springframework.security.saml.metadata.MetadataGenerator
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import java.net.URI

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
@Profile("local_sso")
class LocalSAMLSecurityConfig : SAMLSecurityConfig() {
    override val samlFederationMetadata: Resource = ClasspathResource("/saml/local_federation_metadata.xml")

    override fun contextProvider(): SAMLContextProviderImpl {
        val samlContextProviderLB = SAMLContextProviderLB()
        samlContextProviderLB.setScheme("http")
        samlContextProviderLB.setServerName("localhost")
        samlContextProviderLB.setServerPort(8080)
        samlContextProviderLB.setIncludeServerPortInRequestURL(true)
        samlContextProviderLB.setContextPath("")
        return samlContextProviderLB
    }

    override fun metadataGenerator(): MetadataGenerator {
        val metadataGenerator = MetadataGenerator()
        val url = "http://localhost:8080"
//        metadataGenerator.id = url
        metadataGenerator.entityBaseURL = url
        metadataGenerator.entityId = url
        metadataGenerator.extendedMetadata = extendedMetadata()
        metadataGenerator.isIncludeDiscoveryExtension = false
        metadataGenerator.setKeyManager(keyManager())
        return metadataGenerator
    }

    override fun successRedirectHandler(): SavedRequestAwareAuthenticationSuccessHandler {
        val successRedirectHandler = SavedRequestAwareAuthenticationSuccessHandler()
        successRedirectHandler.setDefaultTargetUrl("/notUsedItSeems")
        successRedirectHandler.setRedirectStrategy(LocalRedirectStrategy())
        return successRedirectHandler
    }
}

class LocalRedirectStrategy : DefaultRedirectStrategy() {
    override fun calculateRedirectUrl(contextPath: String, url: String): String {
        val uri = URI(url)
        return "${uri.scheme}://${uri.authority}/landing"
    }
}
