package com.dibros.gateway.security.config;

import com.dibros.core.token.config.TokenConfig;
import com.dibros.core.token.property.JwtConfiguration;
import com.dibros.gateway.security.filter.GatewayJwtTokenAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig extends TokenConfig{

    public SecurityConfig(JwtConfiguration jwtConfiguration) {
        this.getUrls().addAll(Arrays.asList(jwtConfiguration.getLoginUrl(), "/auth/usuarios/email-token"));
    }

    @Bean
    @Override
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {
        http.addFilterAt(new GatewayJwtTokenAuthorizationFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        return super.configure(http);
    }
}
