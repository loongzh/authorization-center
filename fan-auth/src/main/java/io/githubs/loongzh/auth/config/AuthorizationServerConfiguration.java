package io.githubs.loongzh.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcTokenCustomer;
import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcUserInfoMapper;
import io.githubs.loongzh.auth.utils.KeyConfig;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.UUID;

/**
 * The type Authorization server configuration.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {
    @Value("${server.port}") Integer port;
    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";
    private DefaultOidcUserInfoMapper.OidcUserInfoMapperExtend oidcUserInfoMapperExtend;
    private DefaultOidcTokenCustomer.AbstractOidcTokenCustomerExtend oidcTokenCustomerExtend;

    public AuthorizationServerConfiguration(DefaultOidcUserInfoMapper.OidcUserInfoMapperExtend oidcUserInfoMapperExtend, DefaultOidcTokenCustomer.AbstractOidcTokenCustomerExtend oidcTokenCustomerExtend) {
        this.oidcUserInfoMapperExtend = oidcUserInfoMapperExtend;
        this.oidcTokenCustomerExtend = oidcTokenCustomerExtend;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,RegisteredClientRepository registeredClientRepository,
                                                                      OAuth2AuthorizationService authorizationService) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        //设置确认界面uri
        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI));
        //OIDC相关设置
        authorizationServerConfigurer
        .oidc(oidc ->
                oidc .clientRegistrationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint(userInfoEndpoint ->
                                new DefaultOidcUserInfoMapper(this.oidcUserInfoMapperExtend)

                )
        );
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        http
                //仅拦截OAuth2 Authorization Server的相关endpoint
                .requestMatcher(endpointsMatcher)
                //开启请求认证
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                //禁用OAuth2 Server相关endpoint的CSRF防御
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                //需开启OAuth2 Resource Server支持OIDC /userinfo 的Bearer accessToken鉴权（否则401）
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .apply(authorizationServerConfigurer);
        return http.build();
    }

    /**
     * 注册一个客户端应用
     *
     * @param jdbcTemplate the jdbc template
     * @return the registered client repository
     */
    @SneakyThrows
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        //         每次都会初始化  生产的话 只初始化JdbcRegisteredClientRepository
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // TODO 生产上 注册客户端需要使用接口 不应该采用下面的方式
        // only@test begin
        final String id = "10000";
        RegisteredClient registeredClient = registeredClientRepository.findById(id);
        if (registeredClient == null) {
            registeredClient = this.createRegisteredClient(id);
            registeredClientRepository.save(registeredClient);
        }
        // only@test end
        return registeredClientRepository;
    }

    private RegisteredClient createRegisteredClient(final String id) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
//               客户端ID和密码
                .clientId("felord")
//               此处为了避免频繁启动重复写入仓库
                .id(id)
//                client_secret_basic    客户端需要存明文   服务器存密文
                .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                        .encode("secret"))
//                名称 可不定义
                .clientName("felord")
//                授权方法
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.NONE);
                })
//                授权类型 PASSWORD OAUTH2.1中已移除
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/felord-client-oidc")
                .redirectUri("http://127.0.0.1:8082/authorized")
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/felord")
                .redirectUri("http://127.0.0.1:8082/foo/bar")
                .redirectUri("https://baidu.com")
//                OIDC支持
                .scope(OidcScopes.OPENID)
//                其它Scope
                .scope("message.read")
                .scope("userinfo")
                .scope("message.write")
//                JWT的配置项 包括TTL  是否复用refreshToken等等
                .tokenSettings(TokenSettings.builder().build())
//                配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true).build())
                .build();
    }


    /**
     * 授权服务
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered client repository
     * @return the o auth 2 authorization service
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate,
                registeredClientRepository);
    }

    /**
     * Authorization consent service o auth 2 authorization consent service.
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered client repository
     * @return the o auth 2 authorization consent service
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate,
                registeredClientRepository);
    }
    /**
     * 自定义JWT编码上下文<br/>
     * 填充jwt.claims.sid为当前OP sessionId
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomer() {
        return new DefaultOidcTokenCustomer(this.oidcTokenCustomerExtend);
    }

    @SneakyThrows
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(KeyConfig.getVerifierKey()).build();
    }
    /**
     * 加载JWK资源
     *
     * @return the jwk source
     */
    @SneakyThrows
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
    private static RSAKey generateRsa(){
        return new RSAKey.Builder(KeyConfig.getVerifierKey())
                .privateKey(KeyConfig.getSingerKey())
                .keyID(UUID.randomUUID().toString())
                .build();
    }
    /**
     * 配置 OAuth2.0 provider元信息
     *
     * @return the provider settings
     */
    @Bean
    public ProviderSettings providerSettings() {
        //TODO 生产应该使用域名
        return ProviderSettings.builder().issuer("http://localhost:" + port).build();
    }
}
