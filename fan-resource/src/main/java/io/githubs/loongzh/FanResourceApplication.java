package io.githubs.loongzh;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import reactivefeign.spring.config.EnableReactiveFeignClients;

/**
 * Hello world!
 *
 */

@EnableDiscoveryClient
@SpringBootApplication
@EnableReactiveFeignClients
public class FanResourceApplication
{
    public static void main( String[] args )
    {
        SpringApplication.run(FanResourceApplication.class,args);
    }
}
