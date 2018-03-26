package com.thefetts.kotlinsaml

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class AppController {

    @GetMapping
    fun getLanding(@AuthenticationPrincipal user: OurUserDetails): String {
        return "Great Job! ${user.userId}"
    }
}
