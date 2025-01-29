package com.dibros.gateway.security.config;

import com.dibros.core.token.config.TokenConfig;
import com.dibros.core.token.property.JwtConfiguration;
import com.dibros.gateway.security.filter.GatewayJwtTokenAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig extends TokenConfig {

    public SecurityConfig(JwtConfiguration jwtConfiguration) {
        this.getUrls().addAll(Arrays.asList(
            jwtConfiguration.getLoginUrl(), "/auth/usuarios/email-token", "/teste/notificacoes*",
            "/imagem/public/**", "/loja/anuncios/public*", "/loja/anuncios/public/*",
            "/loja/produtos/public*", "/loja/lojas/public*", "/loja/anuncios/comentarios/public/**"
        ));
    }

    @Bean
    @Override
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {
        http.addFilterAt(new GatewayJwtTokenAuthorizationFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        return super.configure(http);
    }

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    CorsWebFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration().applyPermitDefaultValues();
        config.setAllowCredentials(true);
        config.setAllowedMethods(Collections.singletonList("*"));
        config.setAllowedOriginPatterns(Collections.singletonList("*"));
        config.setExposedHeaders(Collections.singletonList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}


