package io.githubs.loongzh.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;


/**
 * OAuth2 Authorization Server属性
 *
 * @author luohq
 * @date 2022-02-17 19:52
 */
@ConfigurationProperties(prefix = Oauth2ServerProps.PREFIX)
@Data
public class Oauth2ServerProps {
    /**
     * 配置前缀
     */
    public static final String PREFIX = "spring.security.oauth2.authserver";
    /**
     * OAuth2 issuer - 发布者（对应认证服务器URI）
     */
    private String issuer;
    /**
     * 认证服务登录页面URL（对应GET请求）
     */
    private String loginPageUrl = "/login";
    /**
     * 登录表单action（对应POST请求）
     */
    private String loginProcessingUrl = "/login";
    /**
     * 认证服务登录页面View
     */
    private String loginPageView = "login";
    /**
     * 是否自动配置登录页面路由（loginPageUrl -> loginPageView）<br/>
     * 注：如配置为false，则需要手动编程映射登录页，如通过Controller实现，且登录页面采用form表单形式，form.action需要与loginProcessingUrl配置一致
     */
    private Boolean autoConfigLoginPage = true;
    /**
     * 是否启用图片验证码
     */
    private Boolean enableCaptcha = false;
    /**
     * 认证服务登出确认页面URL（对应GET请求）
     */
    private String logoutPageUrl = "/logout";
    /**
     * 认证服务登出确认页面View
     */
    private String logoutPageView = "logout";
    /**
     * OAuth2 Consent确认授权页面URL（对应GET请求）
     */
    private String consentPageUrl = "/oauth2/consent";

    /**
     * 是否自动配置授权确认页面路由（consentPageUrl -> AuthorizationConsentController）<br/>
     * 注：如配置为false，则需要手动编程映射授权确认页，可参见AuthorizationConsentController实现
     */
    private Boolean autoConfigConsentPage = true;
    /**
     * 认证服务登出后默认跳转页面URL
     */
    private String logoutRedirectDefaultUrl = "/logout_status";
    /**
     * 认证服务登出后默认跳转页面View
     */
    private String logoutRedirectDefaultView = "logout_status";
    /**
     * OIDC 认证服务统一登出end_session_endpoint对应的URI
     */
    private String endSessionEndpoint = "/logout";
    /**
     * OAuth2认证接口URI
     */
    private String authorizationEndpoint = "/oauth2/authorize";
    /**
     * OAuth2 令牌接口URI
     */
    private String tokenEndpoint = "/oauth2/token";
    /**
     * OAuth2 Json Web Key公钥获取接口URI
     */
    private String jwkSetEndpoint = "/oauth2/jwks";
    /**
     * OIDC 获取用户信息接口URI
     */
    private String oidcUserInfoEndpoint = "/userinfo";
    //发现端点不可配置，按照OIDC协议取固定值
    //private String oidcOpConfigurationEndpoint = "/.well-known/openid-configuration";
    /**
     * OAuth2 检查令牌接口URI
     */
    private String tokenIntrospectionEndpoint = "/oauth2/introspect";
    /**
     * OAuth2 吊销令牌接口URI
     */
    private String tokenRevocationEndpoint = "/oauth2/revoke";
    /**
     * 认证服务用户密码编码器（支持bcrypt, pbkdf2, scrypt, argon2）
     */
    private String passwordEncoder = "bcrypt";
    /**
     * 是否开启OIDC单点登出（即开启OP端end_session_endpoint及RP端frontchannel/backchannel_logout_uri）
     */
    private Boolean enableOidcSlo = true;
    /**
     * 静态资源 - 白名单（无需认证可直接访问）
     */
    private String[] staticResourceWhiteList = {"/css/**", "/js/**", "/webjars/**", "/img/**"};
}
