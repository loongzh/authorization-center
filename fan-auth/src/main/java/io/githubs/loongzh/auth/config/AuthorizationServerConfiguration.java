package io.githubs.loongzh.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcTokenCustomer;
import io.githubs.loongzh.auth.config.handler.oidc.DefaultOidcUserInfoMapper;
import io.githubs.loongzh.auth.config.handler.oidc.OidcCustomProviderConfigurationEndpointFilter;
import io.githubs.loongzh.auth.constant.Oauth2Constants;
import io.githubs.loongzh.auth.service.JdbcOidcAuthorizationService;
import io.githubs.loongzh.auth.service.OidcAuthorizationService;
import io.githubs.loongzh.auth.utils.KeyConfig;
import io.githubs.loongzh.auth.utils.ObjectPostProcessorUtils;
import lombok.SneakyThrows;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.oauth2.server.authorizationauthorization.authentication.OAuth2CustomAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorizationauthorization.authentication.OAuth2CustomClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorizationauthorization.web.authentication.PublicClientRefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

/**
 * The type Authorization server configuration.
 */
@EnableConfigurationProperties(Oauth2ServerProps.class)
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {
    private DefaultOidcUserInfoMapper.OidcUserInfoMapperExtend oidcUserInfoMapperExtend;
    private DefaultOidcTokenCustomer.AbstractOidcTokenCustomerExtend oidcTokenCustomerExtend;
    private Oauth2ServerProps oauth2ServerProps;
    public AuthorizationServerConfiguration(Oauth2ServerProps oauth2ServerProps,DefaultOidcUserInfoMapper.OidcUserInfoMapperExtend oidcUserInfoMapperExtend, DefaultOidcTokenCustomer.AbstractOidcTokenCustomerExtend oidcTokenCustomerExtend) {
        this.oauth2ServerProps=oauth2ServerProps;
        this.oidcUserInfoMapperExtend = oidcUserInfoMapperExtend;
        this.oidcTokenCustomerExtend = oidcTokenCustomerExtend;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,RegisteredClientRepository registeredClientRepository,
                                                                      OAuth2AuthorizationService authorizationService) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        //??????????????????uri
        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage(this.oauth2ServerProps.getConsentPageUrl()));
        //OIDC????????????
        authorizationServerConfigurer
        .oidc(oidc ->
                oidc .clientRegistrationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint(userInfoEndpoint ->
                                new DefaultOidcUserInfoMapper(this.oidcUserInfoMapperExtend)

                )
        )
        //??????OidcProviderConfigurationEndpointFilter???????????????OidcOpConfigurationEndpointFilter
        .withObjectPostProcessor(ObjectPostProcessorUtils.objectPostReturnNewObj(
                OncePerRequestFilter.class,
                OidcProviderConfigurationEndpointFilter.class,
                new OidcCustomProviderConfigurationEndpointFilter(this.providerSettings())))
        //??????Oauth2 client?????? ??????????????? - ??????RefreshToken??????client_secret??????
        .withObjectPostProcessor(ObjectPostProcessorUtils.objectPostAppendHandle(
        OncePerRequestFilter.class,
        OAuth2ClientAuthenticationFilter.class,
        oAuth2ClientAuthenticationFilter -> {
            //??????Oauth2 client?????? ???????????????request -> OAuth2ClientAuthenticationToken
            oAuth2ClientAuthenticationFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(
                    Arrays.asList(
                            new JwtClientAssertionAuthenticationConverter(),
                            new ClientSecretBasicAuthenticationConverter(),
                            new ClientSecretPostAuthenticationConverter(),
                            /** ???????????????RefreshToken?????????????????????????????????client_secret??????token??? */
                            new PublicClientRefreshTokenAuthenticationConverter(),
                            new PublicClientAuthenticationConverter())));
        }))
        //??????OAuth2 Token?????? ????????????????????? - ??????refresh_token?????????client_secret???????????????PKCE code?????????
        .withObjectPostProcessor(ObjectPostProcessorUtils.objectPostReturnNewObj(
                AuthenticationProvider.class,
                JwtClientAssertionAuthenticationProvider.class,
                new OAuth2CustomClientAuthenticationProvider(registeredClientRepository, authorizationService)))
        //??????OAuth2 Token?????? - ?????????PKCE??????????????????refresh_token
        .withObjectPostProcessor(ObjectPostProcessorUtils.objectPostConvertObj(
                AuthenticationProvider.class,
                OAuth2AuthorizationCodeAuthenticationProvider.class,
                oAuth2AuthorizationCodeAuthenticationProvider -> new OAuth2CustomAuthorizationCodeAuthenticationProvider(authorizationService, http.getSharedObject(JwtEncoder.class))));
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        http
                //?????????OAuth2 Authorization Server?????????endpoint
                .requestMatcher(endpointsMatcher)
                //??????????????????
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                //??????OAuth2 Server??????endpoint???CSRF??????
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                //?????????OAuth2 Resource Server??????OIDC /userinfo ???Bearer accessToken???????????????401???
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .apply(authorizationServerConfigurer);
        return http.build();
    }

    /**
     * ???????????????????????????
     *
     * @param jdbcTemplate the jdbc template
     * @return the registered client repository
     */
    @SneakyThrows
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        //         ?????????????????????  ???????????? ????????????JdbcRegisteredClientRepository
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // TODO ????????? ????????????????????????????????? ??????????????????????????????
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
//               ?????????ID?????????
                .clientId("felord")
//               ????????????????????????????????????????????????
                .id(id)
//                client_secret_basic    ????????????????????????   ??????????????????
                .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                        .encode("secret"))
//                ?????? ????????????
                .clientName("felord")
//                ????????????
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    clientAuthenticationMethods.add(ClientAuthenticationMethod.NONE);
                })
//                ???????????? PASSWORD OAUTH2.1????????????
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                ????????????????????????????????????????????? ??????????????????IP????????????  ???????????? localhost
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/felord-client-oidc")
                .redirectUri("http://127.0.0.1:8082/authorized")
                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/felord")
                .redirectUri("http://127.0.0.1:8082/foo/bar")
                .redirectUri("https://baidu.com")
//                OIDC??????
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PHONE)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.PROFILE)
                //??????PKCE???????????????client_secret?????????refresh_token
                .scope(OIDCScopeValue.OFFLINE_ACCESS.getValue())
                .scope("message.read")
                .scope("userinfo")
                .scope("message.write")
//                JWT???????????? ??????TTL  ????????????refreshToken??????
                .tokenSettings(TokenSettings.builder().build())
//                ???????????????????????????????????????????????????????????? ????????????????????????
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        //.requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        //accessToken?????????????????????????????????????????????5?????????
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        //refreshToken?????????????????????????????????????????????60?????????
                        .refreshTokenTimeToLive(Duration.ofMinutes(60))
                        //????????????token??????????????????????????????refreshToken?????????true?????????refreshToken??????
                        //true??????????????????refreshToken???false???????????????refreshToken???????????????
                        .reuseRefreshTokens(false)
                        //??????idToken???????????? TODO ?????? OidcClientRegistrationEndpointFilter ??????
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        //??????PKCE???????????????client_secret?????????refresh_token??????
                        .setting(Oauth2Constants.TOKEN_SETTINGS.ALLOW_PUBLIC_CLIENT_REFRESH_TOKEN, true)
                        //??????idToken??????????????????30???????????????????????????????????????JwtUtils.idTokenClaims??????
                        //??????code????????????5???????????????????????????????????????OAuth2AuthorizationCodeRequestAuthenticationProvider.generateAuthorizationCode
                        //??????session?????? > refreshToken????????????
                        //TODO ??????session??????  remember-me??????
                        .build())
                .build();
    }


    /**
     * ????????????
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered client repository
     * @return the o auth 2 authorization service
     */
//    @Bean
//    public OAuth2AuthorizationService authorizationService(
//            JdbcTemplate jdbcTemplate,
//            RegisteredClientRepository registeredClientRepository) {
//        return new JdbcOAuth2AuthorizationService(jdbcTemplate,
//                registeredClientRepository);
//    }
    @Bean
    public OidcAuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOidcAuthorizationService(jdbcTemplate, registeredClientRepository);
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
     * ?????????JWT???????????????<br/>
     * ??????jwt.claims.sid?????????OP sessionId
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
     * ??????JWK??????
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
     * ?????? OAuth2.0 provider?????????
     *
     * @return the provider settings
     */
    @Bean
    public ProviderSettings providerSettings() {
        //TODO ????????????????????????
        return ProviderSettings.builder().issuer(this.oauth2ServerProps.getIssuer())
                .setting(Oauth2Constants.PROVIDER_SETTINGS.END_SESSION_ENDPOINT, this.oauth2ServerProps.getEndSessionEndpoint())
                .authorizationEndpoint(this.oauth2ServerProps.getAuthorizationEndpoint())
                .tokenEndpoint(this.oauth2ServerProps.getTokenEndpoint())
                .jwkSetEndpoint(this.oauth2ServerProps.getJwkSetEndpoint())
                .oidcUserInfoEndpoint(this.oauth2ServerProps.getOidcUserInfoEndpoint())
                .tokenIntrospectionEndpoint(this.oauth2ServerProps.getTokenIntrospectionEndpoint())
                .tokenRevocationEndpoint(this.oauth2ServerProps.getTokenRevocationEndpoint())
                .build();
    }
}
