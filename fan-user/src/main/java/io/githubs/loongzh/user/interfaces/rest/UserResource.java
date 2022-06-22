package io.githubs.loongzh.user.interfaces.rest;

import io.githubs.loongzh.user.interfaces.dto.UserDtoExt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;


/**
 * @author fan
 * @date 2022年06月22日 18:12
 */
@RestController
public class UserResource {
    @PostMapping("test")
    public Mono<UserDtoExt> test(@RequestBody @Validated UserDtoExt dto){
        return Mono.just(dto);
    }
    @GetMapping("/feign")
    public Mono<String> feign() {
        return Mono.just( "Hello user Feign.");
    }
}
