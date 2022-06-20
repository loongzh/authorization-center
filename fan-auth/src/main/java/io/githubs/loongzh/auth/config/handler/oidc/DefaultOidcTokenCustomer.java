package io.githubs.loongzh.auth.config.handler.oidc;


import io.githubs.loongzh.auth.constant.Oauth2Constants;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.StringUtils;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 默认的OIDC Token定制化实现
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-02-28 16:59
 */
public class DefaultOidcTokenCustomer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    /**
     * 自定义Token扩展（默认空实现）
     */
    private AbstractOidcTokenCustomerExtend abstractOidcTokenCustomerExtend = new AbstractOidcTokenCustomerExtend() {
    };

    /**
     * Map(token类型值, 自定义扩展实现)
     */
    private Map<String, Consumer<JwtEncodingContext>> tokenTypeValue2ExtendFuncMap = new HashMap<>(3);

    /**
     * 构造函数
     *
     * @param abstractOidcTokenCustomerExtend 自定义Token扩展
     */
    public DefaultOidcTokenCustomer(AbstractOidcTokenCustomerExtend abstractOidcTokenCustomerExtend) {
        //设置非空自定义token扩展
        if (null != abstractOidcTokenCustomerExtend) {
            this.abstractOidcTokenCustomerExtend = abstractOidcTokenCustomerExtend;
        }

        //设置Map(token类型值, 自定义扩展实现)
        this.tokenTypeValue2ExtendFuncMap.put(OAuth2TokenType.ACCESS_TOKEN.getValue(), this::extendAccessTokenInner);
        this.tokenTypeValue2ExtendFuncMap.put(OAuth2TokenType.REFRESH_TOKEN.getValue(), this.abstractOidcTokenCustomerExtend::extendRefreshToken);
        this.tokenTypeValue2ExtendFuncMap.put(OidcParameterNames.ID_TOKEN, this::extendIdTokenInner);
    }

    /**
     * 内部token扩展实现
     *
     * @param jwtEncodingContext token上下文
     */
    @Override
    public void customize(JwtEncodingContext jwtEncodingContext) {
        //token类型
        OAuth2TokenType tokenType = jwtEncodingContext.getTokenType();
        //根据token类型扩展对应的token（依次扩展accessToken -> refreshToken -> idToken）
        //详细扩展逻辑参见 org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider -> authenticate）
        if(this.tokenTypeValue2ExtendFuncMap.get(tokenType.getValue()) != null){
            this.tokenTypeValue2ExtendFuncMap.get(tokenType.getValue()).accept(jwtEncodingContext);
        }
    }

    private void extendAccessTokenInner(JwtEncodingContext jwtEncodingContext) {
        String userId = jwtEncodingContext.getPrincipal().getName();
        /** 第三方登录，调用第三方用户自动注册逻辑（非OAuth2 Client第三方登录的情况均为UniLoginAuthenticationToken）  */
        if (jwtEncodingContext.getPrincipal().getClass().getName().equals("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken")) {
            String newRegUserId = this.abstractOidcTokenCustomerExtend.registerThirdUser(jwtEncodingContext);
            //重置newRegUserId
            this.resetNewRegUserIdInJwtContext(newRegUserId, jwtEncodingContext);
        }

        //调用自定义扩展
        this.abstractOidcTokenCustomerExtend.extendAccessToken(jwtEncodingContext);
    }

    /**
     * 重置claims.sub和Auth2Authorization.principalName为newRegUserId
     *
     * @param newRegUserId 新注册的用户ID
     * @param jwtEncodingContext jwt编码上下文
     */
    private void resetNewRegUserIdInJwtContext(String newRegUserId, JwtEncodingContext jwtEncodingContext) {
        try {
            //覆盖claims.sub为新注册用户ID
            jwtEncodingContext.getClaims().claim("sub", newRegUserId);

            //重置OAuth2Authorization.pincipalName
            OAuth2Authorization oAuth2Authorization = jwtEncodingContext.getAuthorization();
            Field principalNameField = OAuth2Authorization.class.getDeclaredField("principalName");
            principalNameField.setAccessible(true);
            principalNameField.set(oAuth2Authorization, newRegUserId);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new AuthenticationServiceException(ex.getMessage());
        }
    }
    /**
     * 内部idToken扩展（扩展sid）
     *
     * @param jwtEncodingContext token上下文
     */
    private void extendIdTokenInner(JwtEncodingContext jwtEncodingContext) {
        //获取登录时的sessionId（避免再次调用RequestContextHolder.getRequestAttributes().getSessionId()获取sessionId而导致额外创建新的session）
        String loginSessionId = jwtEncodingContext.getAuthorization().getAttribute(Oauth2Constants.AUTHORIZATION_ATTRS.SESSION_ID);
        if(StringUtils.hasText(loginSessionId)){
            //idToken默认添加sid
            jwtEncodingContext.getClaims().claim(Oauth2Constants.CLAIMS.SID, loginSessionId);
            //调用自定义扩展
            this.abstractOidcTokenCustomerExtend.extendIdToken(jwtEncodingContext);
        }
    }


    /**
     * 自定义扩展适配器
     */
    public static abstract class AbstractOidcTokenCustomerExtend {

        /**
         * 注册第三方用户为当前系统用户，并返回注册后的当前系统用户ID<br/>
         * 主：用注册后的用户ID作为token.claim.sub
         * @param jwtEncodingContext
         * @return
         */
        public String registerThirdUser(JwtEncodingContext jwtEncodingContext) {
            return jwtEncodingContext.getPrincipal().getName();
        }

        /**
         * 扩展IdToken
         *
         * @param jwtEncodingContext token上下文
         */
        public void extendAccessToken(JwtEncodingContext jwtEncodingContext) {
            System.out.println(jwtEncodingContext.getPrincipal());
        }

        /**
         * 扩展RefreshToken
         *
         * @param jwtEncodingContext token上下文
         */
        public void extendRefreshToken(JwtEncodingContext jwtEncodingContext) {
            System.out.println(jwtEncodingContext.getPrincipal());
        }

        /**
         * 扩展AccessToken
         *
         * @param jwtEncodingContext token上下文
         */
        public void extendIdToken(JwtEncodingContext jwtEncodingContext) {

        }
    }


}
