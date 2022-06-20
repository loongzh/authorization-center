package io.githubs.loongzh.auth.ext;

import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcUserInfoMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * OIDC 用户信息 扩展
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-03-01 08:20
 */
@Slf4j
@Component
public class OidcUserInfoMapperExtendImpl implements DefaultOidcUserInfoMapper.OidcUserInfoMapperExtend {

    private static Map<String, List<String>> scope2ClaimsMap = new HashMap<>();

    static {
        scope2ClaimsMap.put(OidcScopes.PROFILE, Arrays.asList("userName"));
        scope2ClaimsMap.put(OidcScopes.PHONE, Arrays.asList("mobilePhone"));
        scope2ClaimsMap.put(OidcScopes.EMAIL, Arrays.asList("email"));
        scope2ClaimsMap.put(OidcScopes.ADDRESS, Arrays.asList("postalAddress", "postCode"));
    }


    @Override
    public void extendClaims(Map<String, Object> oidcUserInfoClaims, OidcUserInfoAuthenticationContext authenticationContext) {
        OAuth2Authorization authorization = authenticationContext.getAuthorization();
        String userId = authenticationContext.getAuthorization().getPrincipalName();
        OidcIdToken idToken = authorization.getToken(OidcIdToken.class).getToken();
        OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
        Set<String> accessTokenScopes = accessToken.getScopes();

        /** 查询并填充用户信息 */
        Map<String, Object> userInfoMap = this.buildUserInfoMap(userId);
        scope2ClaimsMap.keySet().stream()
                .filter(accessTokenScopes::contains)
                .flatMap(scope -> scope2ClaimsMap.get(scope).stream())
                .forEach(claimName -> oidcUserInfoClaims.put(claimName, userInfoMap.get(claimName)));
        log.info("extend OIDC userInfo from {}: {}", userId, userInfoMap);
    }

    /**
     * 构建用户Map
     *
     * @param userId 用户ID
     * @return Map(propName, propVal)
     */
    private Map<String, Object> buildUserInfoMap(String userId) {
        Map<String, Object> propMap = new HashMap<>();
        propMap.put("userId", userId);
        propMap.put("userName", "luohq");
        propMap.put("mobilePhone", "18888888888");
        propMap.put("email", "luohq@email.com");
        propMap.put("postalAddress", "中国辽宁省沈阳市");
        propMap.put("postCode", "110000");
        return propMap;
    }
}
