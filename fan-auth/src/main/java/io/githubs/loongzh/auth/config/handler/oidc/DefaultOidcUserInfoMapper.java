package io.githubs.loongzh.auth.config.handler.oidc;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;

import java.util.*;
import java.util.function.Function;

/**
 * 默认用户信息转换器（默认根据accessToken.scope提取相关idToken中的相关claims）
 * <br/>可根据需要实现自定义扩展OidcUserInfoMapperExtend）<br/>
 * <p>
 * 注：默认实现参考自{@link OidcUserInfoAuthenticationProvider.DefaultOidcUserInfoMapper}
 *
 * @author luohq
 * @date 2022-02-28
 */
public class DefaultOidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {


    /**
     * 自定义UserInfo扩展实现
     */
    private OidcUserInfoMapperExtend oidcUserInfoMapperExtend;

    /**
     * 构造函数
     *
     * @param oidcUserInfoMapperExtend 自定义UserInfo扩展实现
     */
    public DefaultOidcUserInfoMapper(OidcUserInfoMapperExtend oidcUserInfoMapperExtend) {
        this.oidcUserInfoMapperExtend = oidcUserInfoMapperExtend;
    }

    /**
     * scope.email相关claim
     */
    private static final List<String> EMAIL_CLAIMS = Arrays.asList(
            StandardClaimNames.EMAIL,
            StandardClaimNames.EMAIL_VERIFIED
    );
    /**
     * scope.phone相关claim
     */
    private static final List<String> PHONE_CLAIMS = Arrays.asList(
            StandardClaimNames.PHONE_NUMBER,
            StandardClaimNames.PHONE_NUMBER_VERIFIED
    );
    /**
     * scope.profile相关claim
     */
    private static final List<String> PROFILE_CLAIMS = Arrays.asList(
            StandardClaimNames.NAME,
            StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.GIVEN_NAME,
            StandardClaimNames.MIDDLE_NAME,
            StandardClaimNames.NICKNAME,
            StandardClaimNames.PREFERRED_USERNAME,
            StandardClaimNames.PROFILE,
            StandardClaimNames.PICTURE,
            StandardClaimNames.WEBSITE,
            StandardClaimNames.GENDER,
            StandardClaimNames.BIRTHDATE,
            StandardClaimNames.ZONEINFO,
            StandardClaimNames.LOCALE,
            StandardClaimNames.UPDATED_AT
    );

    /**
     * 转换UserInfo
     *
     * @param authenticationContext
     * @return
     */
    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext authenticationContext) {
        OAuth2Authorization authorization = authenticationContext.getAuthorization();
        OidcIdToken idToken = authorization.getToken(OidcIdToken.class).getToken();
        OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
        Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(idToken.getClaims(),
                accessToken.getScopes());

        if (null != this.oidcUserInfoMapperExtend) {
            this.oidcUserInfoMapperExtend.extendClaims(scopeRequestedClaims, authenticationContext);
        }

        return new OidcUserInfo(scopeRequestedClaims);
    }

    /**
     * 根据scope过滤userInfo相关claim
     *
     * @param claims
     * @param requestedScopes
     * @return
     */
    private static Map<String, Object> getClaimsRequestedByScope(Map<String, Object> claims, Set<String> requestedScopes) {
        Set<String> scopeRequestedClaimNames = new HashSet<>(32);
        scopeRequestedClaimNames.add(StandardClaimNames.SUB);

        if (requestedScopes.contains(OidcScopes.ADDRESS)) {
            scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
        }
        if (requestedScopes.contains(OidcScopes.EMAIL)) {
            scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PHONE)) {
            scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PROFILE)) {
            scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
        }

        Map<String, Object> requestedClaims = new HashMap<>(claims);
        requestedClaims.keySet().removeIf(claimName -> !scopeRequestedClaimNames.contains(claimName));

        return requestedClaims;
    }

    /**
     * 自定义Oidc UserInfo 扩展信息
     */
    public interface OidcUserInfoMapperExtend {
        /**OidcUserInfoMapperExtend
         * 扩展Oidc UserInfo Claims Map
         *
         * @param oidcUserInfoClaims
         * @param authenticationContext
         */
        void extendClaims(Map<String, Object> oidcUserInfoClaims, OidcUserInfoAuthenticationContext authenticationContext);
    }


}