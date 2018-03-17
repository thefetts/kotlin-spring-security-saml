package com.thefetts.kotlinsaml

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KotlinSAMLApplication

fun main(args: Array<String>) {
    runApplication<KotlinSAMLApplication>(*args)
}
