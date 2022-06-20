package org.springframework.security.oauth2.server.authorizationauthorization.authentication;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.springframework.security.oauth2.server.authorizationauthorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;


/**
 * OAuth 2.0 Authorization Code Grant - 认证器（RP通过code换token）<br/>
 * 注：扩展支持在PKCE模式下也生成refresh_token
 *
 * @author luohq
 * @date 2022-03-10
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public final class OAuth2CustomAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
			new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE =
			new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2CustomAuthorizationCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	/**
	 * Sets the {@link OAuth2TokenCustomizer} that customizes the
	 * {@link JwtEncodingContext.Builder#headers(Consumer) headers} and/or
	 * {@link JwtEncodingContext.Builder#claims(Consumer) claims} for the generated {@link Jwt}.
	 *
	 * @param jwtCustomizer the {@link OAuth2TokenCustomizer} that customizes the headers and/or claims for the generated {@code Jwt}
	 */
	public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Sets the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}.
	 *
	 * @param refreshTokenGenerator the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}
	 */
	public void setRefreshTokenGenerator(Supplier<String> refreshTokenGenerator) {
		Assert.notNull(refreshTokenGenerator, "refreshTokenGenerator cannot be null");
		this.refreshTokenGenerator = refreshTokenGenerator;
	}

	@Deprecated
	protected void setProviderSettings(ProviderSettings providerSettings) {
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(OAuth2AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
				authorization.getToken(OAuth2AuthorizationCode.class);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());

		if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
			if (!authorizationCode.isInvalidated()) {
				// Invalidate the authorization code given that a different client is attempting to use it
				authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());
				this.authorizationService.save(authorization);
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
				!authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!authorizationCode.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		String issuer = ProviderContextHolder.getProviderContext().getIssuer();
		Set<String> authorizedScopes = authorization.getAttribute(
				OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);

		JwsHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, authorization.getPrincipalName(),
				authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorization(authorization)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JwsHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(JwtEncoderParameters.from(headers, claims));

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), authorizedScopes);

		/** =========== 修改逻辑 - 开始 =========== **/
		OAuth2RefreshToken refreshToken =null;
		try{
			refreshToken=generateRefreshToken(registeredClient.getTokenSettings().getRefreshTokenTimeToLive());
		}catch (Exception ig){}
		/** =========== 修改逻辑 - 结束 =========== **/

		Jwt jwtIdToken = null;
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
			String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);

			headersBuilder = JwtUtils.headers();
			claimsBuilder = JwtUtils.idTokenClaims(
					registeredClient, issuer, authorization.getPrincipalName(), nonce);

			// @formatter:off
			context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
					.registeredClient(registeredClient)
					.principal(authorization.getAttribute(Principal.class.getName()))
					.authorization(authorization)
					.authorizedScopes(authorizedScopes)
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.authorizationGrant(authorizationCodeAuthentication)
					.build();
			// @formatter:on

			this.jwtCustomizer.customize(context);

			headers = context.getHeaders().build();
			claims = context.getClaims().build();
			jwtIdToken = this.jwtEncoder.encode(JwtEncoderParameters.from(headers, claims));
		}

		OidcIdToken idToken;
		if (jwtIdToken != null) {
			idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
					jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
		} else {
			idToken = null;
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims())
				);
		if (refreshToken != null) {
			authorizationBuilder.refreshToken(refreshToken);
		}
		if (idToken != null) {
			authorizationBuilder
					.token(idToken,
							(metadata) ->
									metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		authorization = authorizationBuilder.build();
		// @formatter:on

		// Invalidate the authorization code as it can only be used once
		authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());

		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);
		return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
	}

}
