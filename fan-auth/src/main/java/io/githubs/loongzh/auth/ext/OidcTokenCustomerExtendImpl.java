package io.githubs.loongzh.auth.ext;

import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcTokenCustomer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * OIDC Token 扩展
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-03-01 08:08
 */
@Component
@Slf4j
public class OidcTokenCustomerExtendImpl extends DefaultOidcTokenCustomer.AbstractOidcTokenCustomerExtend {

    /**
     * 常量定义
     */
    private final String SCOPE_ROLES = "roles";
    private final String CLAIM_ROLES = "roles";

    /**
     * Map(用户名, 角色集合)
     */
    private Map<String, Set<String>> username2RolesMap = new HashMap<>(1);

    /**
     * Map(scope, 自定义扩展实现函数)
     */
    private Map<String, Consumer<JwtEncodingContext>> scope2ExtendFuncMap = new HashMap<>(1);


    @PostConstruct
    private void init() {
        //设置Map(scope.roles, 自定义扩展实现函数)
        this.scope2ExtendFuncMap.put(SCOPE_ROLES, this::extendRoles);

        //设置Map(用户名, 角色集合)
        this.username2RolesMap.put("luo", Stream.of("role1", "role2").collect(Collectors.toSet()));

    }

    @Override
    public void extendAccessToken(JwtEncodingContext jwtEncodingContext) {
        //若accessToken.claims.scope包含roles，则扩展accessToken.claims.roles
        jwtEncodingContext.getAuthorizedScopes().stream()
                .filter(this.scope2ExtendFuncMap::containsKey)
                .forEach(scope -> this.scope2ExtendFuncMap.get(scope).accept(jwtEncodingContext));
    }

    /**
     * 如果包含scope: roles，则附加claim.roles为用户对应的角色列表
     *
     * @param jwtEncodingContext
     */
    private void extendRoles(JwtEncodingContext jwtEncodingContext) {
        //用户ID
        String userId = jwtEncodingContext.getAuthorization().getPrincipalName();
        //查询用户角色列表 TODO
        if (!this.username2RolesMap.containsKey(userId)) {
            return;
        }
        Set<String> roles = this.username2RolesMap.get(userId);
        //扩展claims
        jwtEncodingContext.getClaims().claim(CLAIM_ROLES, roles);
        log.info("assign user {} with accessToken.claims.roles: {}", userId, roles);
    }
}
