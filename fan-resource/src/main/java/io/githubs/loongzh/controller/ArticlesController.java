package io.githubs.loongzh.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author fan
 * @date 2022年06月14日 16:19
 */
@RestController
public class ArticlesController {
    @GetMapping("/articles")
    public String[] getArticles() {
        return new String[]{"Article 1", "Article 2", "Article 3"};
    }
}
