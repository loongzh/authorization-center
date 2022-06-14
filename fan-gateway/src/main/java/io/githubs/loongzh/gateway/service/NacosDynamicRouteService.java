package io.githubs.loongzh.gateway.service;

import org.springframework.cloud.gateway.route.RouteDefinition;

/**
 * @author fan
 * @date 2022年06月14日 10:58
 */
public interface NacosDynamicRouteService {
    /**
     * 更新路由信息
     * @param gatewayDefine
     * @return
     * @throws Exception
     */
    String update(RouteDefinition gatewayDefine);
}
