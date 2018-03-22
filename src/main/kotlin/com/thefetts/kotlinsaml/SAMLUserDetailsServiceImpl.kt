package com.thefetts.kotlinsaml

import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSAnyImpl
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import org.springframework.stereotype.Service

@Service
class SAMLUserDetailsServiceImpl : SAMLUserDetailsService {
    override fun loadUserBySAML(credential: SAMLCredential): OurUserDetails {
        val userId = credential.nameID.value
        println(" ************************** User ID: $userId ************************** ")

        // Find attributes in the assertion
        val attributes = credential
            .authenticationAssertion
            .attributeStatements
            .first()
            .attributes

        // Find a specific attribute
        val displayNameNode = attributes
            .find { it.name == "displayName" }
            ?.attributeValues
            ?.first()

        // Get the string value in a variety of ways
        val displayNameValue = when (displayNameNode) {
            is XSString -> displayNameNode.value
            is XSAnyImpl -> displayNameNode.textContent
            else -> displayNameNode.toString()
        }
        println(" ************************** Display Name: $displayNameValue ************************** ")

        // Real implementation would likely go to persistence to see if anything in the credential
        // assertion exists in your persistence
        return OurUserDetails(userId, displayNameValue)
    }

}

// Some data class that defines the user that is now logged in
data class OurUserDetails(val userId: String, val displayName: String)
