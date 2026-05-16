package com.skch.skch_oauth2_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.skch.skch_oauth2_server.service.CustomUserDetails;

@Configuration
public class SecurityJacksonConfig {

    // Register a Jackson Module that adds a mix-in for CustomUserDetails and
    // a NamedType so Spring Security's allowlist can deserialize stored principal
    // objects (avoids enabling default typing globally).
    @Bean
    public Module securityJacksonModule() {
        SimpleModule module = new SimpleModule("security-mixins");
        module.setMixInAnnotation(CustomUserDetails.class, CustomUserDetailsMixin.class);
        module.registerSubtypes(new NamedType(CustomUserDetails.class,
                "com.skch.skch_oauth2_server.service.CustomUserDetails"));
        return module;
    }
}