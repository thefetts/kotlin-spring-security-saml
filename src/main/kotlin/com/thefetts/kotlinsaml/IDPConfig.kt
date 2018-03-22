package com.thefetts.kotlinsaml

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "idp")
class IDPConfig(
        var authLifetimeInSeconds: Int = 24 * 60 * 60,
        var samlEntityId: String = "",
        var samlMetadataLocation: String = ""
)
