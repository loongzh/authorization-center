package io.githubs.loongzh.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * 测试接口
 * Created by macro on 2020/6/19.
 */
@RestController
public class HelloController {
    @Autowired
    private UserReactive userReactive;
    @GetMapping("/hello")
    public String hello() {
        return "Hello World.";
    }
    @GetMapping("/feign")
    public Mono<String> feign() {
        return userReactive.feign();
    }
}
