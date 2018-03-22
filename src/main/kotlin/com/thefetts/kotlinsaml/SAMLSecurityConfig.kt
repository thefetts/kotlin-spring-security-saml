package com.thefetts.kotlinsaml

import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager
import org.apache.commons.httpclient.protocol.Protocol
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory
import org.apache.velocity.app.VelocityEngine
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider
import org.opensaml.util.resource.Resource
import org.opensaml.xml.parse.ParserPool
import org.opensaml.xml.parse.StaticBasicParserPool
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.config.MethodInvokingFactoryBean
import org.springframework.context.annotation.Bean
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.saml.*
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.key.KeyManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.*
import org.springframework.security.saml.parser.ParserPoolHolder
import org.springframework.security.saml.processor.*
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.websso.*
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.util.*
import javax.annotation.PostConstruct
import javax.annotation.PreDestroy

abstract class SAMLSecurityConfig : WebSecurityConfigurerAdapter() {
    private lateinit var backgroundTaskTimer: Timer
    private lateinit var multiThreadedHttpConnectionManager: MultiThreadedHttpConnectionManager

    @Autowired
    private val samlUserDetailsServiceImpl: SAMLUserDetailsServiceImpl? = null

    @Autowired
    private lateinit var idpConfig: IDPConfig

    @PostConstruct
    fun init() {
        this.backgroundTaskTimer = Timer(true)
        this.multiThreadedHttpConnectionManager = MultiThreadedHttpConnectionManager()
    }

    @PreDestroy
    fun destroy() {
        this.backgroundTaskTimer.purge()
        this.backgroundTaskTimer.cancel()
        this.multiThreadedHttpConnectionManager.shutdown()
    }

    // Initialization of the velocity engine
    @Bean
    open fun velocityEngine(): VelocityEngine {
        return VelocityFactory.getEngine()
    }

    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    open fun parserPool(): StaticBasicParserPool {
        return StaticBasicParserPool()
    }

    @Bean(name = ["parserPoolHolder"])
    open fun parserPoolHolder(): ParserPoolHolder {
        return ParserPoolHolder()
    }

    // Bindings, encoders and decoders used for creating and parsing message
    @Bean
    open fun httpClient(): HttpClient {
        return HttpClient(this.multiThreadedHttpConnectionManager)
    }

    // SAML Authentication Provider responsible for validation received SAML messages
    @Bean
    open fun samlAuthenticationProvider(): SAMLAuthenticationProvider {
        val samlAuthenticationProvider = OurSAMLAuthenticationProvider(idpConfig.authLifetimeInSeconds)
        samlAuthenticationProvider.userDetails = samlUserDetailsServiceImpl
        samlAuthenticationProvider.isForcePrincipalAsString = false
        return samlAuthenticationProvider
    }

    // Provider of default SAML Context
    @Bean
    abstract fun contextProvider(): SAMLContextProviderImpl

    // Logger for SAML messages and events
    @Bean
    open fun samlLogger(): SAMLDefaultLogger {
        val samlDefaultLogger = SAMLDefaultLogger()
        samlDefaultLogger.setLogMessages(true)
        return samlDefaultLogger
    }

    // SAML 2.0 WebSSO assertion consumer
    @Bean
    open fun webSSOprofileConsumer(): WebSSOProfileConsumer {
        val webSSOProfileConsumerImpl = WebSSOProfileConsumerImpl()
        webSSOProfileConsumerImpl.maxAuthenticationAge = idpConfig.authLifetimeInSeconds.toLong()
        return webSSOProfileConsumerImpl
    }

    // SAML 2.0 Holder-of-key WebSSO assertion consumer
    @Bean
    open fun hokWebSSOprofileConsumer(): WebSSOProfileConsumerHoKImpl {
        return WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 Web SSO profile
    @Bean
    open fun webSSOprofile(): WebSSOProfile {
        return WebSSOProfileImpl()
    }

    // SAML 2.0 Holder-of-key Web SSO profile
    @Bean
    open fun hokWebSSOProfile(): WebSSOProfileConsumerHoKImpl {
        return WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 ECP profile
    @Bean
    open fun ecpprofile(): WebSSOProfileECPImpl {
        return WebSSOProfileECPImpl()
    }

    @Bean
    open fun logoutprofile(): SingleLogoutProfile {
        return SingleLogoutProfileImpl()
    }

    // Central storage of cryptographic keys
    @Bean
    open fun keyManager(): KeyManager {
        val loader = DefaultResourceLoader()
        val storeFile = loader.getResource("classpath:/saml/keystore.jks")
        val storePass = "secret"
        val passwords = hashMapOf("spring" to "secret")
        val defaultKey = "spring"
        return JKSKeyManager(storeFile, storePass, passwords, defaultKey)
    }

    // Setup TLS socket factory
    @Bean
    open fun tlsProtocolConfigurer(): TLSProtocolConfigurer {
        return TLSProtocolConfigurer()
    }

    @Bean
    open fun socketFactory(): ProtocolSocketFactory {
        return TLSProtocolSocketFactory(keyManager(), null, "default")
    }

    @Bean
    open fun socketFactoryProtocol(): Protocol {
        return Protocol("https", socketFactory(), 443)
    }

    @Bean
    open fun socketFactoryInitialization(): MethodInvokingFactoryBean {
        val methodInvokingFactoryBean = MethodInvokingFactoryBean()
        methodInvokingFactoryBean.targetClass = Protocol::class.java
        methodInvokingFactoryBean.targetMethod = "registerProtocol"
        val args = arrayOf("https", socketFactoryProtocol())
        methodInvokingFactoryBean.setArguments(*args)
        return methodInvokingFactoryBean
    }

    @Bean
    open fun defaultWebSSOProfileOptions(): WebSSOProfileOptions {
        val webSSOProfileOptions = WebSSOProfileOptions()
        webSSOProfileOptions.isIncludeScoping = false
        return webSSOProfileOptions
    }

    // Entry point to initialize authentication
    @Bean
    open fun samlEntryPoint(): SAMLEntryPoint {
        val samlEntryPoint = SAMLEntryPoint()
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions())
        return samlEntryPoint
    }

    // Setup advanced info about metadata
    @Bean
    open fun extendedMetadata(): ExtendedMetadata {
        val extendedMetadata = ExtendedMetadata()
        // extendedMetadata.sslHostnameVerification = "allowAll"
        extendedMetadata.isIdpDiscoveryEnabled = false
//        extendedMetadata.isSignMetadata = true
        extendedMetadata.isEcpEnabled = false
//        extendedMetadata.signingAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-share256"
        return extendedMetadata
    }

    // IDP discovery service
    @Bean
    open fun samlIDPDiscovery(): SAMLDiscovery {
        return SAMLDiscovery()
    }

    abstract val samlFederationMetadata: Resource

    @Bean
    @Qualifier("idp-ping")
    @Throws(MetadataProviderException::class)
    open fun ssoExtendedMetadataProvider(): ExtendedMetadataDelegate {
        val metadataProvider = ResourceBackedMetadataProvider(backgroundTaskTimer, samlFederationMetadata)
        metadataProvider.parserPool = parserPool()
        val extendedMetadataDelegate = ExtendedMetadataDelegate(metadataProvider, extendedMetadata())
        extendedMetadataDelegate.isMetadataTrustCheck = false
        extendedMetadataDelegate.isMetadataRequireSignature = false
        backgroundTaskTimer.purge()
        return extendedMetadataDelegate
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // Do not forget to call initialize method on providers
    @Bean
    @Qualifier("metadata")
    @Throws(MetadataProviderException::class)
    open fun metadata(): CachingMetadataManager {
        val providers = ArrayList<MetadataProvider>()
        providers.add(ssoExtendedMetadataProvider())
        return CachingMetadataManager(providers)
    }

    // Filter automatically generates default SP metadata
    @Bean
    abstract fun metadataGenerator(): MetadataGenerator

    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    @Bean
    open fun metadataDisplayFilter(): MetadataDisplayFilter {
        return MetadataDisplayFilter()
    }

    // Handler deciding where to redirect user after successful login
    @Bean
    abstract fun successRedirectHandler(): SavedRequestAwareAuthenticationSuccessHandler

    // Handler deciding where to redirect user after failed login
    @Bean
    open fun authenticationFailureHandler(): SimpleUrlAuthenticationFailureHandler {
        val failureHandler = SimpleUrlAuthenticationFailureHandler()
        failureHandler.setUseForward(true)
        failureHandler.setDefaultFailureUrl("/error")
        return failureHandler
    }

    @Bean
    @Throws(Exception::class)
    open fun samlWebSSOHoKProcessingFilter(): SAMLWebSSOHoKProcessingFilter {
        val samlWebSSOHoKProcessingFilter = SAMLWebSSOHoKProcessingFilter()
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOHoKProcessingFilter
    }

    // Processing filter for WebSSO profile messages
    @Bean
    @Throws(Exception::class)
    open fun samlWebSSOProcessingFilter(): SAMLProcessingFilter {
        val samlWebSSOProcessingFilter = SAMLProcessingFilter()
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOProcessingFilter
    }

    @Bean
    open fun metadataGeneratorFilter(): MetadataGeneratorFilter {
        val metadataGeneratorFilter = MetadataGeneratorFilter(metadataGenerator())
        metadataGeneratorFilter.isNormalizeBaseUrl = true
        return metadataGeneratorFilter
    }

    // Handler for successful logout
    @Bean
    open fun successLogoutHandler(): SimpleUrlLogoutSuccessHandler {
        val successLogoutHandler = SimpleUrlLogoutSuccessHandler()
        successLogoutHandler.setDefaultTargetUrl("/")
        return successLogoutHandler
    }

    @Bean
    open fun logoutHandler(): SecurityContextLogoutHandler {
        val logoutHandler = SecurityContextLogoutHandler()
        logoutHandler.isInvalidateHttpSession = true
        logoutHandler.setClearAuthentication(true)
        return logoutHandler
    }

    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful global logout
    @Bean
    open fun samlLogoutProcessingFilter(): SAMLLogoutProcessingFilter {
        return SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler())
    }

    // Overrides default logout processing filter with the one processing SAML messages
    @Bean
    open fun samlLogoutFilter(): SAMLLogoutFilter {
        return SAMLLogoutFilter(successLogoutHandler(),
            arrayOf<LogoutHandler>(logoutHandler()),
            arrayOf<LogoutHandler>(logoutHandler()))
    }

    // Bindings
    private fun artifactResolutionProfile(): ArtifactResolutionProfile {
        val artifactResolutionProfile = ArtifactResolutionProfileImpl(httpClient())
        artifactResolutionProfile.setProcessor(SAMLProcessorImpl(soapBinding()))
        return artifactResolutionProfile
    }

    @Bean
    open fun artifactBinding(parserPool: ParserPool, velocityEngine: VelocityEngine): HTTPArtifactBinding {
        return HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile())
    }

    @Bean
    open fun soapBinding(): HTTPSOAP11Binding {
        return HTTPSOAP11Binding(parserPool())
    }

    @Bean
    open fun httpPostBinding(): HTTPPostBinding {
        return HTTPPostBinding(parserPool(), velocityEngine())
    }

    @Bean
    open fun httpRedirectDeflateBinding(): HTTPRedirectDeflateBinding {
        return HTTPRedirectDeflateBinding(parserPool())
    }

    @Bean
    open fun httpSOAP11Binding(): HTTPSOAP11Binding {
        return HTTPSOAP11Binding(parserPool())
    }

    @Bean
    open fun httpPAOS11Binding(): HTTPPAOS11Binding {
        return HTTPPAOS11Binding(parserPool())
    }

    // Processor
    @Bean
    open fun processor(): SAMLProcessorImpl {
        val bindings = ArrayList<SAMLBinding>()
        bindings.add(httpRedirectDeflateBinding())
        bindings.add(httpPostBinding())
        bindings.add(artifactBinding(parserPool(), velocityEngine()))
        bindings.add(httpSOAP11Binding())
        bindings.add(httpPAOS11Binding())
        return SAMLProcessorImpl(bindings)
    }

    // Define security filter chain to support SSO auth by using SAML 2.0
    @Bean
    @Throws(Exception::class)
    open fun samlFilter(): FilterChainProxy {
        val chains = ArrayList<SecurityFilterChain>()

        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SSOHoK/**"), samlWebSSOHoKProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/discovery/**"), samlIDPDiscovery()))

        return FilterChainProxy(chains)
    }

    @Bean
    @Throws(Exception::class)
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    // Defines the web based security configuration
    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
            .httpBasic()
            .authenticationEntryPoint(samlEntryPoint())
        http
            .csrf()
            .disable()
        http
            .cors()
        http
            .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter::class.java)
            .addFilterAfter(samlFilter(), BasicAuthenticationFilter::class.java)
        http
            .authorizeRequests()
            .antMatchers("/error").permitAll()
            .antMatchers("/saml/**").permitAll()
            .anyRequest().authenticated()
        http
            .logout()
            .logoutSuccessUrl("/")
    }

    // Sets a custom authentication provider
    @Throws(Exception::class)
    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(samlAuthenticationProvider())
    }

    override fun configure(web: WebSecurity) {
        web
            .ignoring()
            .antMatchers("/**.chunk.js")
            .antMatchers("/**.bundle.js")
        super.configure(web)
    }

    companion object {
        // Initialization of OpenSAML Library
        @Bean
        fun sAMLBootstrap(): SAMLBootstrap {
            return SAMLBootstrap()
        }
    }
}
