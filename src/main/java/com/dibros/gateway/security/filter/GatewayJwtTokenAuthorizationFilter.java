package com.dibros.gateway.security.filter;

import com.dibros.core.token.converter.TokenConverter;
import com.dibros.core.token.property.JwtConfiguration;
import com.dibros.core.token.util.SecurityContextUtil;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class GatewayJwtTokenAuthorizationFilter implements WebFilter {

    private final JwtConfiguration jwtConfiguration;
    private final TokenConverter tokenConverter;

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        String prefix = this.jwtConfiguration.getHeader().getPrefix();

        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(AUTHORIZATION))
                .switchIfEmpty(Mono.justOrEmpty(exchange.getRequest().getQueryParams().getFirst(AUTHORIZATION)))
                .filter(auth -> auth.startsWith(prefix))
                .map(auth -> auth.substring(prefix.length()).trim())
                .flatMap(token -> Mono.fromCallable(() -> this.tokenConverter.decryptToken(token)))
                .flatMap(signedJWT -> chain.filter(this.withSignedHeader(exchange, prefix, signedJWT))
                        .contextWrite(SecurityContextUtil.setSecurityContext(signedJWT))
                )
                .onErrorResume(e -> chain.filter(exchange))
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }

    private ServerWebExchange withSignedHeader(ServerWebExchange exchange, String prefix, SignedJWT signedJWT) {
        return exchange.mutate()
                .request(r -> r.headers(h -> h.set(AUTHORIZATION, prefix + signedJWT.serialize())))
                .build();
    }

}
