package io.githubs.loongzh.auth.config.handler.oidc;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.BackChannelLogoutRequest;
import io.githubs.loongzh.auth.config.Oauth2ServerProps;
import io.githubs.loongzh.auth.constant.Oauth2Constants;
import io.githubs.loongzh.auth.enums.LoginStateEnum;
import io.githubs.loongzh.auth.service.OidcAuthorizationService;
import io.githubs.loongzh.auth.utils.Jwks;
import lombok.SneakyThrows;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * OIDC Logout Handler
 *
 * @author luohq
 * @date 2022-02-21 19:47
 */
public class OidcEndSessionSingleLogoutSuccessHandler implements LogoutSuccessHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Client????????????DAO
     */
    private RegisteredClientRepository registeredClientRepository;
    /**
     * ????????????DAO
     */
    private OidcAuthorizationService oidcAuthorizationService;
    /**
     * OAuth2??????????????????????????????
     */
    private Oauth2ServerProps oauth2ServerProps;

    /**
     * RSA??????
     */
    private RSAKey rsaJWK;
    /**
     * JWS?????????????????????RSAKey.privateKey?????????
     */
    private JWSSigner signer;

    /**
     * state??????uri??????
     */
    private final String STATE_PARAMETER_FORMAT = "%s?state=%s";

    /**
     * ????????????
     */
    @SneakyThrows
    public OidcEndSessionSingleLogoutSuccessHandler(RegisteredClientRepository registeredClientRepository,
                                                    OidcAuthorizationService oidcAuthorizationService,
                                                    Oauth2ServerProps oauth2ServerProps) {
        this.registeredClientRepository = registeredClientRepository;
        this.oidcAuthorizationService = oidcAuthorizationService;
        this.oauth2ServerProps = oauth2ServerProps;

        // Create RSA-signer with the private key
        rsaJWK = Jwks.convertRsaKey();
        signer = new RSASSASigner(rsaJWK);
    }

    /**
     * Requires the request to be passed in.
     *
     * @param request        from which to obtain a HTTP session (cannot be null)
     * @param response       not used (can be <code>null</code>)
     * @param authentication not used (can be <code>null</code>)
     */
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //??????OIDC SLO????????????frontchannel/backchannel?????????????????????post_logout_redirect_uri?????????
        if (this.oauth2ServerProps.getEnableOidcSlo()) {
            this.onLogoutSuccessOidcEndpoint(request, response, authentication);
            return;
        }
        //?????????OIDC SLO??????????????????post_logout_redirect_uri?????????
        this.simplePostLogoutRedirectUri(request, response, authentication);

    }

    /**
     * ?????????????????????post_logout_redirect_uri?????????
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    private void simplePostLogoutRedirectUri(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        redirectPostLogoutRedirectUri(request, response, null);
    }


    /**
     * OIDC SLO????????????frontchannel/backchannel?????????????????????post_logout_redirect_uri?????????
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    public void onLogoutSuccessOidcEndpoint(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        //???????????? id_token_hint & post_logout_redirect_uri
        String idTokenHint = request.getParameter("id_token_hint");
        if (!StringUtils.hasText(idTokenHint)) {
            logger.error("id_token_hint should not empty for OIDC end_session_point!");
            response400(response);
            return;
        }
        //??????idToken????????????RP????????????????????????????????????idToken???
        OAuth2Authorization curOauth2Authorization = this.oidcAuthorizationService.findByIdToken(idTokenHint);
        if (null == curOauth2Authorization) {
            logger.error("Can not find OAuth2Authentication for idToken!");
            response400(response);
        }
        //????????????RP???Client????????????
        RegisteredClient curRegisteredClient = this.registeredClientRepository.findById(curOauth2Authorization.getRegisteredClientId());
        String curLoginSessionId = curOauth2Authorization.getAttribute(Oauth2Constants.AUTHORIZATION_ATTRS.SESSION_ID);


        //????????????session?????????RP?????????????????????OAuth2Authorization
        List<OAuth2Authorization> curSessionOauth2AuthorizationList = this.oidcAuthorizationService.findBySessionId(curLoginSessionId);
        Map<String, OAuth2Authorization> regClientId2AuthInfoMap = curSessionOauth2AuthorizationList.stream()
                .collect(Collectors.toMap(OAuth2Authorization::getRegisteredClientId, Function.identity()));

        /** ???????????????????????? */
        curSessionOauth2AuthorizationList.forEach(oauth2Authorization -> {
            oauth2Authorization = OAuth2Authorization.from(oauth2Authorization)
                    //TODO ??????token????????????
                    .attribute(Oauth2Constants.AUTHORIZATION_ATTRS.LOGIN_STATE, LoginStateEnum.LOGOUT.getCode())
                    .build();
            this.oidcAuthorizationService.save(oauth2Authorization);
        });

        //??????RP?????????????????????RegisteredClientId
        Collection<String> otherRegisteredClientIdList = curSessionOauth2AuthorizationList.stream()
                .filter(regClient -> !curOauth2Authorization.getRegisteredClientId().equals(regClient.getRegisteredClientId()))
                .map(OAuth2Authorization::getRegisteredClientId)
                .collect(Collectors.toSet());
        if (CollectionUtils.isEmpty(otherRegisteredClientIdList)) {
            logger.info("Not exist other login RP for the same session id and redirect to post_logout_redirect_uri!");
            redirectPostLogoutRedirectUri(request, response, curRegisteredClient);
            return;
        }


        //??????clientRegistrationId?????????ClientRegistration?????? TODO ?????? - ??????????????????
        List<RegisteredClient> registeredClientList = otherRegisteredClientIdList.stream()
                .map(this.registeredClientRepository::findById)
                .filter(regClient -> null != regClient)
                .collect(Collectors.toList());

        /** frontchannel_logout_uri?????? */
        List<String> frontChannelLogoutUriList = registeredClientList.stream()
                .filter(registeredClient -> null != registeredClient.getClientSettings() && StringUtils.hasText(registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI)))
                .map(registeredClient -> {
                    String frontChannelLogoutUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI);
                    String iss = this.oauth2ServerProps.getIssuer();
                    String sid = curLoginSessionId;
                    return String.format(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI_FORMAT, frontChannelLogoutUri, iss, sid);
                }).collect(Collectors.toList());

        /** ??????backchannel_logout_uri?????? ?????????backchannel???????????? */
        registeredClientList.stream()
                .filter(registeredClient -> null != registeredClient.getClientSettings() && StringUtils.hasText(registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.BACKCHANNEL_LOGOUT_URI)))
                .forEach(registeredClient -> {
                    String backChannelLogoutUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.BACKCHANNEL_LOGOUT_URI);
                    //???????????????logout_token
                    JWT logoutToken = this.generateLogoutToken(registeredClient, regClientId2AuthInfoMap.get(registeredClient.getId()));
                    /** ??????backchannel???????????? */
                    this.sendBackChannelLogoutRequest(backChannelLogoutUri, logoutToken);
                });
        /** ???????????????SLO?????? */
        if (!CollectionUtils.isEmpty(frontChannelLogoutUriList)) {
            this.generateSingleLogoutPageHtml(response, this.determinePostLogoutRedirectUri(request, curRegisteredClient), frontChannelLogoutUriList);
            return;
        }

        /** ????????????????????????RP??????????????????post_logout_redirect_uri */
        redirectPostLogoutRedirectUri(request, response, curRegisteredClient);
    }


    /**
     * ??????LogoutToken
     *
     * @param registeredClient ?????????????????????
     * @param oAuth2Authorization ??????????????????
     *
     * @return
     * @throws JOSEException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    @SneakyThrows
    private JWT generateLogoutToken(RegisteredClient registeredClient, OAuth2Authorization oAuth2Authorization) {
        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(this.oauth2ServerProps.getIssuer())
                .subject(oAuth2Authorization.getPrincipalName())
                .audience(registeredClient.getClientId())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + registeredClient.getTokenSettings().getAccessTokenTimeToLive().toMillis()))
                //.jwtID()
                .claim(Oauth2Constants.CLAIMS.SID, oAuth2Authorization.getAttribute(Oauth2Constants.AUTHORIZATION_ATTRS.SESSION_ID))
                .claim(Oauth2Constants.CLAIMS.EVENTS, Oauth2Constants.CLAIMS.EVENTS_VALUE)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.rsaJWK.getKeyID()).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(this.signer);
        return signedJWT;
    }

    /**
     * ??????backchannel????????????
     *
     * @param backChannelLogoutUri back channel??????URI
     * @param logoutToken ??????token
     */
    private void sendBackChannelLogoutRequest(String backChannelLogoutUri, JWT logoutToken) {
        try {
            URI backChannelLogoutEndpointForRP = new URI(backChannelLogoutUri);
            BackChannelLogoutRequest backChannelLogoutRequest = new BackChannelLogoutRequest(backChannelLogoutEndpointForRP, logoutToken);
            HTTPResponse httpResponse = backChannelLogoutRequest.toHTTPRequest().send();
            if (httpResponse.indicatesSuccess()) {
                logger.info(String.format("send backchannel_logout_uri %s success with status_code %d!", backChannelLogoutUri, httpResponse.getStatusCode()));
            } else {
                logger.info(String.format("send backchannel_logout_uri %s failed with status_code %d!", backChannelLogoutUri, httpResponse.getStatusCode()));
            }
        } catch (Throwable e) {
            logger.error(String.format("send backchannel_logout_uri %s exception!", backChannelLogoutUri), e);
        }
    }


    /**
     * ??????query?????????client?????????server??????????????????post_logout_redirect_uri
     *
     * @param request
     * @param registeredClient
     * @return
     */
    private String determinePostLogoutRedirectUri(HttpServletRequest request, RegisteredClient registeredClient) {
        //???????????? post_logout_redirect_uri
        String postLogoutRedirectUri = request.getParameter(Oauth2Constants.OIDC_PARAMETERS.POST_LOGOUT_REDIRECT_URI);
        //????????????state????????????????????????redirect uri???
        String state = request.getParameter(OAuth2ParameterNames.STATE);

        //??????RegisteredClient.clientSetting.post_logout_redirect_uri
        if (!StringUtils.hasText(postLogoutRedirectUri) && null != registeredClient) {
            postLogoutRedirectUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.POST_LOGOUT_REDIRECT_URI);
        }
        if (!StringUtils.hasText(postLogoutRedirectUri)) {
            //?????????????????????????????????post_logout_redirect_uri_db
            postLogoutRedirectUri = this.oauth2ServerProps.getLogoutRedirectDefaultUrl();
        }
        if (StringUtils.hasText(state)) {
            postLogoutRedirectUri = String.format(STATE_PARAMETER_FORMAT, postLogoutRedirectUri, state);
        }
        return postLogoutRedirectUri;
    }


    /**
     * ????????????post_logout_redirect_uri
     *
     * @param request
     * @param response
     * @param registeredClient
     * @throws IOException
     */
    private void redirectPostLogoutRedirectUri(HttpServletRequest request, HttpServletResponse response, RegisteredClient registeredClient) throws IOException {
        response.sendRedirect(this.determinePostLogoutRedirectUri(request, registeredClient));
    }


    /**
     * ??????SLO??????<br/>
     * <ol>
     *     <li>??????frontchannel_logout_uri??????iframe</li>
     *     <li>?????????????????????iframe.src????????????????????????????????????post_logout_redirect_uri</li>
     * </ol>
     *
     * @param response
     * @param postLogoutRedirectUri
     * @param frontChannelLogoutUriList
     * @throws IOException
     */
    private void generateSingleLogoutPageHtml(HttpServletResponse response, String postLogoutRedirectUri, List<String> frontChannelLogoutUriList) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n");
        sb.append("<html lang=\"en\">\n");
        sb.append("  <head>\n");
        sb.append("    <meta charset=\"utf-8\">\n");
        sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
        sb.append("    <meta name=\"description\" content=\"\">\n");
        sb.append("    <meta name=\"author\" content=\"\">\n");
        /** ??????????????? */
        sb.append("    <meta http-equiv=\"refresh\" content=\"0;url=" + postLogoutRedirectUri + "\"> </head>\n");
        sb.append("    <title>????????????</title>\n");
        sb.append("  </head>\n");
        sb.append("  <body>\n");
        /** ????????????iframe.src=frontchannel_logout_uri */
        frontChannelLogoutUriList.forEach(frontChannelLogoutUri -> {
            sb.append("     <iframe src='" + frontChannelLogoutUri + "' style='display:none'></iframe>\n");
        });
        sb.append("</body>");
        sb.append("</html>");
        String frontLogoutPageHtml = sb.toString();
        response.setContentType("text/html;charset=UTF-8");
        response.setContentLength(frontLogoutPageHtml.getBytes(StandardCharsets.UTF_8).length);
        response.getWriter().write(frontLogoutPageHtml);
    }

    /**
     * ??????400??????
     *
     * @param response
     * @throws IOException
     */
    private void response400(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.getWriter().flush();
    }
}