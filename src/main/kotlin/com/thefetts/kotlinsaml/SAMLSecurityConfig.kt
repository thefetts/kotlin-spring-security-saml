package com.thefetts.kotlinsaml

import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider
import org.opensaml.util.resource.ClasspathResource
import org.opensaml.util.resource.Resource
import org.opensaml.xml.parse.StaticBasicParserPool
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.saml.SAMLAuthenticationProvider
import org.springframework.security.saml.SAMLBootstrap
import org.springframework.security.saml.SAMLEntryPoint
import org.springframework.security.saml.SAMLProcessingFilter
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.context.SAMLContextProviderLB
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.key.KeyManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.CachingMetadataManager
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate
import org.springframework.security.saml.metadata.MetadataGenerator
import org.springframework.security.saml.metadata.MetadataGeneratorFilter
import org.springframework.security.saml.processor.HTTPPostBinding
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding
import org.springframework.security.saml.processor.SAMLBinding
import org.springframework.security.saml.processor.SAMLProcessorImpl
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.websso.*
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import java.util.*

@Configuration
class SAMLSecurityConfig : WebSecurityConfigurerAdapter() {

    val samlFederationMetadata: Resource = ClasspathResource("/saml/local_federation_metadata.xml")

    @Autowired
    private lateinit var samlUserDetailsServiceImpl: SAMLUserDetailsServiceImpl

    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    fun parserPool(): StaticBasicParserPool {
        return StaticBasicParserPool()
    }

    // SAML Authentication Provider responsible for validation received SAML messages
    @Bean
    fun samlAuthenticationProvider(): SAMLAuthenticationProvider {
        val samlAuthenticationProvider = SAMLAuthenticationProvider()
        samlAuthenticationProvider.userDetails = samlUserDetailsServiceImpl
        samlAuthenticationProvider.isForcePrincipalAsString = false
        return samlAuthenticationProvider
    }

    // Provider of default SAML Context
    @Bean
    fun contextProvider(): SAMLContextProviderImpl {
        val samlContextProviderLB = SAMLContextProviderLB()
        samlContextProviderLB.setScheme("http")
        samlContextProviderLB.setServerName("localhost")
        samlContextProviderLB.setServerPort(8080)
        samlContextProviderLB.setIncludeServerPortInRequestURL(true)
        samlContextProviderLB.setContextPath("")
        return samlContextProviderLB
    }

    // Logger for SAML messages and events
    @Bean
    fun samlLogger(): SAMLDefaultLogger {
        val samlDefaultLogger = SAMLDefaultLogger()
        samlDefaultLogger.setLogMessages(true)
        return samlDefaultLogger
    }

    // SAML 2.0 WebSSO assertion consumer
    @Bean
    fun webSSOprofileConsumer(): WebSSOProfileConsumer {
        val webSSOProfileConsumerImpl = WebSSOProfileConsumerImpl()
        webSSOProfileConsumerImpl.maxAuthenticationAge = 60 * 24 * 24
        return webSSOProfileConsumerImpl
    }

    // SAML 2.0 Holder-of-key WebSSO assertion consumer
    @Bean
    fun hokWebSSOprofileConsumer(): WebSSOProfileConsumerHoKImpl {
        return WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 Web SSO profile
    @Bean
    fun webSSOprofile(): WebSSOProfile {
        return WebSSOProfileImpl()
    }

    // Central storage of cryptographic keys
    @Bean
    fun keyManager(): KeyManager {
        val loader = DefaultResourceLoader()
        val storeFile = loader.getResource("classpath:/saml/keystore.jks")
        val storePass = "secret"
        val passwords = hashMapOf("spring" to "secret")
        val defaultKey = "spring"
        return JKSKeyManager(storeFile, storePass, passwords, defaultKey)
    }

    // Entry point to initialize authentication
    @Bean
    fun samlEntryPoint(): SAMLEntryPoint {
        return SAMLEntryPoint()
    }

    @Bean
    fun ssoExtendedMetadataProvider(): ExtendedMetadataDelegate {
        val metadataProvider = ResourceBackedMetadataProvider(Timer(true), samlFederationMetadata)
        metadataProvider.parserPool = parserPool()
        return ExtendedMetadataDelegate(metadataProvider)
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    @Bean
    fun metadata(): CachingMetadataManager {
        val providers = ArrayList<MetadataProvider>()
        providers.add(ssoExtendedMetadataProvider())
        return CachingMetadataManager(providers)
    }

    // Filter automatically generates default SP metadata
    @Bean
    fun metadataGenerator(): MetadataGenerator {
        val metadataGenerator = MetadataGenerator()
        metadataGenerator.entityId = "http://localhost:8080"
        return metadataGenerator
    }

    // Processing filter for WebSSO profile messages
    @Bean
    fun samlWebSSOProcessingFilter(): SAMLProcessingFilter {
        val samlWebSSOProcessingFilter = SAMLProcessingFilter()
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager())
        return samlWebSSOProcessingFilter
    }

    @Bean
    fun metadataGeneratorFilter(): MetadataGeneratorFilter {
        return MetadataGeneratorFilter(metadataGenerator())
    }

    // Processor
    @Bean
    fun processor(): SAMLProcessorImpl {
        val bindings = ArrayList<SAMLBinding>()
        bindings.add(HTTPRedirectDeflateBinding(parserPool()))
        bindings.add(HTTPPostBinding(parserPool(), VelocityFactory.getEngine()))
        return SAMLProcessorImpl(bindings)
    }

    // Defines the web based security configuration
    override fun configure(http: HttpSecurity) {
        http
            .httpBasic()
            .authenticationEntryPoint(samlEntryPoint())
        http
            .csrf()
            .disable()
        http
            .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter::class.java)
        http
            .authorizeRequests()
            .antMatchers("/error").permitAll()
            .antMatchers("/saml/**").permitAll()
            .anyRequest().authenticated()
    }

    companion object {
        // Initialization of OpenSAML Library
        @Bean
        fun sAMLBootstrap(): SAMLBootstrap {
            return SAMLBootstrap()
        }
    }
}
