package io.githubs.loongzh.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Configuration
public class ResourceServerConfig {
    // @formatter:off
    @Bean
    SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {
        ServerHttpSecurity.AuthorizeExchangeSpec authorizeExchange = http.authorizeExchange();

        authorizeExchange
                .pathMatchers("/messages/**").authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }
    // @formatter:on
}
