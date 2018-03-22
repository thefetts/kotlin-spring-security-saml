package com.thefetts.kotlinsaml

import org.springframework.security.saml.SAMLAuthenticationProvider
import org.springframework.security.saml.SAMLCredential
import java.time.Duration
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.*

class OurSAMLAuthenticationProvider(private val lifetimeInSeconds: Int) : SAMLAuthenticationProvider() {
    override fun getExpirationDate(credential: SAMLCredential): Date {
        return toDate(LocalDateTime.now(ZoneOffset.UTC).plus(Duration.of(lifetimeInSeconds.toLong(), ChronoUnit.SECONDS)))
    }

    private fun toDate(dateTime: LocalDateTime): Date {
        return Date.from(dateTime.toInstant(ZoneOffset.UTC))
    }
}
