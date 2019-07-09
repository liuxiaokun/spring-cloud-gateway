package com.fred.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> Mono.just(exchange.getRequest().getRemoteAddress().getHostName());
    }

//    @Bean
//    KeyResolver tokenKeyResolver() {
//        return exchange -> Mono.just(exchange.getRequest().getQueryParams().getFirst("userId"));
//    }
//
//    @Bean
//    KeyResolver uriKeyResolver() {
//        return exchange -> Mono.just(exchange.getRequest().getPath().value());
//    }
}
