package io.githubs.loongzh.controller;

import org.springframework.web.bind.annotation.GetMapping;
import reactivefeign.spring.config.ReactiveFeignClient;
import reactor.core.publisher.Mono;

@ReactiveFeignClient(name = "fan-user")
public interface UserReactive {
    @GetMapping("/feign")
    Mono<String> feign();
}
