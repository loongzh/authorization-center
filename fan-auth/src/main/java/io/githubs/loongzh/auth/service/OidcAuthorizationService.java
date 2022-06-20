package io.githubs.loongzh.auth.service;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import java.util.Collection;
import java.util.List;

/**
 * Oidc 认证信息 - 管理服务<br/>
 * 注：OAuth2AuthorizationService服务接口的基础上添加了OIDC相关支持
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-02-22 15:59
 */
public interface OidcAuthorizationService extends OAuth2AuthorizationService {

    /**
     * 根据idToken查询认证信息
     *
     * @param idToken
     * @return
     */
    OAuth2Authorization findByIdToken(String idToken);

    /**
     * 查询当前sessionId对应的已登录的认证信息
     *
     * @param sessionId
     * @return
     */
    List<OAuth2Authorization> findBySessionId(String sessionId);

    /**
     * 查询当前sessionId对应的已登录的客户端注册ID
     *
     * @param sessionId
     * @return
     */
    Collection<String> findLoginRegisteredClientIdBySessionId(String sessionId);
}
