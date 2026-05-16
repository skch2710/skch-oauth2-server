package com.skch.skch_oauth2_server.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class CustomUserDetailsMixin {
    // no implementation needed; serves as Jackson mixin to expose type id mapping
}
