package io.githubs.loongzh.auth.config.handler.oidc;

import io.githubs.loongzh.auth.constant.Oauth2Constants;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

/**
 * Oidc发现端点 - 自定义增强实现
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-03-02
 * @see OidcProviderConfiguration
 * @see ProviderSettings
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">4.1. OpenID Provider Configuration Request</a>
 * @see org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter
 */
public final class OidcCustomProviderConfigurationEndpointFilter extends OncePerRequestFilter {
    /**
     * The default endpoint {@code URI} for OpenID Provider Configuration requests.
     */
    private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

    private final ProviderSettings providerSettings;
    private final RequestMatcher requestMatcher;
    private final OidcProviderConfigurationHttpMessageConverter providerConfigurationHttpMessageConverter =
            new OidcProviderConfigurationHttpMessageConverter();

    public OidcCustomProviderConfigurationEndpointFilter(ProviderSettings providerSettings) {
        Assert.notNull(providerSettings, "providerSettings cannot be null");
        this.providerSettings = providerSettings;
        this.requestMatcher = new AntPathRequestMatcher(
                DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI,
                HttpMethod.GET.name()
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String issuer = ProviderContextHolder.getProviderContext().getIssuer();
        OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
                .issuer(issuer)
                .authorizationEndpoint(asUrl(issuer, this.providerSettings.getAuthorizationEndpoint()))
                .tokenEndpoint(asUrl(issuer, this.providerSettings.getTokenEndpoint()))
                .tokenEndpointAuthenticationMethods(clientAuthenticationMethods())
                .jwkSetUrl(asUrl(issuer, this.providerSettings.getJwkSetEndpoint()))
                .userInfoEndpoint(asUrl(issuer, this.providerSettings.getOidcUserInfoEndpoint()))
                .responseType(OAuth2AuthorizationResponseType.CODE.getValue())
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .grantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
                .subjectType("public")
                .idTokenSigningAlgorithm(SignatureAlgorithm.RS256.getName())
                .scope(OidcScopes.OPENID)
                /** 扩展自定义endpoint */
                .claim(Oauth2Constants.PROVIDER_SETTINGS.END_SESSION_ENDPOINT, asUrl(issuer, providerSettings.getSetting(Oauth2Constants.PROVIDER_SETTINGS.END_SESSION_ENDPOINT)))
                .build();

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.providerConfigurationHttpMessageConverter.write(
                providerConfiguration, MediaType.APPLICATION_JSON, httpResponse);
    }

    private static Consumer<List<String>> clientAuthenticationMethods() {
        return (authenticationMethods) -> {
            authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
            authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
            //authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
            //authenticationMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
            authenticationMethods.add(ClientAuthenticationMethod.NONE.getValue());
        };
    }

    private static String asUrl(String issuer, String endpoint) {
        return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
    }
}
