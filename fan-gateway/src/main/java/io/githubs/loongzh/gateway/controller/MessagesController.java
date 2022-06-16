package io.githubs.loongzh.gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author fan
 * @date 2022年06月16日 14:41
 */
@RestController
public class MessagesController {

    @GetMapping("/messages")
    public String[] getMessages() {
        return new String[] {"Message 1", "Message 2", "Message 3"};
    }
}

