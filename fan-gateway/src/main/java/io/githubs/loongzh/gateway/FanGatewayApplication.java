package io.githubs.loongzh.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 *
 *
 * CachingRouteDefinitionLocator 缓存目标
 * CompositeRouteDefinitionLocator 组合多种
 * DiscoveryClientRouteDefinitionLocator 从注册中心
 * InMemoryRouteDefinitionRepository 读取内存中的
 * PropertiesRouteDefinitionLocator 读取配置文件 GatewayProperties yml/properties
 * RouteDefinitionRepository  从存储器读取
 *
 * @Bean
 * 	@ConditionalOnMissingBean(RouteDefinitionRepository.class)
 * 	public InMemoryRouteDefinitionRepository inMemoryRouteDefinitionRepository() {
 * 		return new InMemoryRouteDefinitionRepository();
 * 	}
 * 通过上面代码，可以看到如果没有RouteDefinitionRepository的实例，
 * 则默认用InMemoryRouteDefinitionRepository。而做动态路由的关键就在这里。
 * 即通过自定义的RouteDefinitionRepository类，来提供路由配置信息。
 *
 */
@EnableDiscoveryClient
@SpringBootApplication
public class FanGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(FanGatewayApplication.class, args);
    }
}
