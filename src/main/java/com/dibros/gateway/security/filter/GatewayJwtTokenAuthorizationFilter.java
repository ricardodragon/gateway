package com.dibros.gateway.security.filter;

import com.dibros.core.token.converter.TokenConverter;
import com.dibros.core.token.property.JwtConfiguration;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import org.springframework.lang.NonNull;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

import static com.dibros.core.token.util.SecurityContextUtil.setSecurityContext;
import static org.apache.http.HttpHeaders.AUTHORIZATION;

public class GatewayJwtTokenAuthorizationFilter implements WebFilter {

    @Nonnull
    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange request, @NonNull WebFilterChain chain){
        String authorization = request.getRequest().getHeaders().getFirst(AUTHORIZATION);
        authorization=authorization==null?request.getRequest().getQueryParams().getFirst(AUTHORIZATION):authorization;
        String prefix = new JwtConfiguration().getHeader().getPrefix();
        if (authorization == null || !authorization.startsWith(prefix))
            throw new WebClientResponseException(401, "unauthorized", request.getRequest().getHeaders(), new byte[]{}, StandardCharsets.UTF_8);

        SignedJWT signedJWT = new TokenConverter().decryptToken(authorization.replace(prefix, "").trim());

        return chain.filter(
            request.mutate().request(
                request.getRequest().mutate().header(
                    AUTHORIZATION,
                    String.format("Bearer %s", signedJWT.serialize())
                ).build()
            ).build()
        ).contextWrite(setSecurityContext(signedJWT));
    }
}
