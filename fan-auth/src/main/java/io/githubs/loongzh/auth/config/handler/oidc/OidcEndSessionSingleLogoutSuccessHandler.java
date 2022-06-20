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
     * Client注册信息DAO
     */
    private RegisteredClientRepository registeredClientRepository;
    /**
     * 认证信息DAO
     */
    private OidcAuthorizationService oidcAuthorizationService;
    /**
     * OAuth2认证服务器端配置属性
     */
    private Oauth2ServerProps oauth2ServerProps;

    /**
     * RSA密钥
     */
    private RSAKey rsaJWK;
    /**
     * JWS签名对象（根据RSAKey.privateKey生成）
     */
    private JWSSigner signer;

    /**
     * state参数uri模版
     */
    private final String STATE_PARAMETER_FORMAT = "%s?state=%s";

    /**
     * 构造函数
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
        //开启OIDC SLO，则执行frontchannel/backchannel登出，最后根据post_logout_redirect_uri重定向
        if (this.oauth2ServerProps.getEnableOidcSlo()) {
            this.onLogoutSuccessOidcEndpoint(request, response, authentication);
            return;
        }
        //未开启OIDC SLO，则直接根据post_logout_redirect_uri重定向
        this.simplePostLogoutRedirectUri(request, response, authentication);

    }

    /**
     * 登出后根据参数post_logout_redirect_uri重定向
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
     * OIDC SLO，则执行frontchannel/backchannel登出，最后根据post_logout_redirect_uri重定向
     *
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    public void onLogoutSuccessOidcEndpoint(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        //获取参数 id_token_hint & post_logout_redirect_uri
        String idTokenHint = request.getParameter("id_token_hint");
        if (!StringUtils.hasText(idTokenHint)) {
            logger.error("id_token_hint should not empty for OIDC end_session_point!");
            response400(response);
            return;
        }
        //根据idToken查询当前RP认证信息（查询并验证验证idToken）
        OAuth2Authorization curOauth2Authorization = this.oidcAuthorizationService.findByIdToken(idTokenHint);
        if (null == curOauth2Authorization) {
            logger.error("Can not find OAuth2Authentication for idToken!");
            response400(response);
        }
        //查询当前RP的Client注册信息
        RegisteredClient curRegisteredClient = this.registeredClientRepository.findById(curOauth2Authorization.getRegisteredClientId());
        String curLoginSessionId = curOauth2Authorization.getAttribute(Oauth2Constants.AUTHORIZATION_ATTRS.SESSION_ID);


        //属于同一session的其他RP对应的认证信息OAuth2Authorization
        List<OAuth2Authorization> curSessionOauth2AuthorizationList = this.oidcAuthorizationService.findBySessionId(curLoginSessionId);
        Map<String, OAuth2Authorization> regClientId2AuthInfoMap = curSessionOauth2AuthorizationList.stream()
                .collect(Collectors.toMap(OAuth2Authorization::getRegisteredClientId, Function.identity()));

        /** 批量更新登出状态 */
        curSessionOauth2AuthorizationList.forEach(oauth2Authorization -> {
            oauth2Authorization = OAuth2Authorization.from(oauth2Authorization)
                    //TODO 更新token无效状态
                    .attribute(Oauth2Constants.AUTHORIZATION_ATTRS.LOGIN_STATE, LoginStateEnum.LOGOUT.getCode())
                    .build();
            this.oidcAuthorizationService.save(oauth2Authorization);
        });

        //其他RP对应的已登录的RegisteredClientId
        Collection<String> otherRegisteredClientIdList = curSessionOauth2AuthorizationList.stream()
                .filter(regClient -> !curOauth2Authorization.getRegisteredClientId().equals(regClient.getRegisteredClientId()))
                .map(OAuth2Authorization::getRegisteredClientId)
                .collect(Collectors.toSet());
        if (CollectionUtils.isEmpty(otherRegisteredClientIdList)) {
            logger.info("Not exist other login RP for the same session id and redirect to post_logout_redirect_uri!");
            redirectPostLogoutRedirectUri(request, response, curRegisteredClient);
            return;
        }


        //查询clientRegistrationId对应的ClientRegistration信息 TODO 优化 - 支持批量查询
        List<RegisteredClient> registeredClientList = otherRegisteredClientIdList.stream()
                .map(this.registeredClientRepository::findById)
                .filter(regClient -> null != regClient)
                .collect(Collectors.toList());

        /** frontchannel_logout_uri列表 */
        List<String> frontChannelLogoutUriList = registeredClientList.stream()
                .filter(registeredClient -> null != registeredClient.getClientSettings() && StringUtils.hasText(registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI)))
                .map(registeredClient -> {
                    String frontChannelLogoutUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI);
                    String iss = this.oauth2ServerProps.getIssuer();
                    String sid = curLoginSessionId;
                    return String.format(Oauth2Constants.CLIENT_SETTINGS.FRONTCHANNEL_LOGOUT_URI_FORMAT, frontChannelLogoutUri, iss, sid);
                }).collect(Collectors.toList());

        /** 提取backchannel_logout_uri列表 并发送backchannel登出请求 */
        registeredClientList.stream()
                .filter(registeredClient -> null != registeredClient.getClientSettings() && StringUtils.hasText(registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.BACKCHANNEL_LOGOUT_URI)))
                .forEach(registeredClient -> {
                    String backChannelLogoutUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.BACKCHANNEL_LOGOUT_URI);
                    //生成对应的logout_token
                    JWT logoutToken = this.generateLogoutToken(registeredClient, regClientId2AuthInfoMap.get(registeredClient.getId()));
                    /** 发送backchannel登出请求 */
                    this.sendBackChannelLogoutRequest(backChannelLogoutUri, logoutToken);
                });
        /** 重定向前端SLO页面 */
        if (!CollectionUtils.isEmpty(frontChannelLogoutUriList)) {
            this.generateSingleLogoutPageHtml(response, this.determinePostLogoutRedirectUri(request, curRegisteredClient), frontChannelLogoutUriList);
            return;
        }

        /** 最后重定向会当前RP的登出回调页post_logout_redirect_uri */
        redirectPostLogoutRedirectUri(request, response, curRegisteredClient);
    }


    /**
     * 生成LogoutToken
     *
     * @param registeredClient 客户端注册信息
     * @param oAuth2Authorization 当前认证信息
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
     * 发送backchannel登出请求
     *
     * @param backChannelLogoutUri back channel登出URI
     * @param logoutToken 登出token
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
     * 根据query参数、client配置、server默认配置决定post_logout_redirect_uri
     *
     * @param request
     * @param registeredClient
     * @return
     */
    private String determinePostLogoutRedirectUri(HttpServletRequest request, RegisteredClient registeredClient) {
        //获取参数 post_logout_redirect_uri
        String postLogoutRedirectUri = request.getParameter(Oauth2Constants.OIDC_PARAMETERS.POST_LOGOUT_REDIRECT_URI);
        //获取参数state，若存在则附加到redirect uri上
        String state = request.getParameter(OAuth2ParameterNames.STATE);

        //获取RegisteredClient.clientSetting.post_logout_redirect_uri
        if (!StringUtils.hasText(postLogoutRedirectUri) && null != registeredClient) {
            postLogoutRedirectUri = registeredClient.getClientSettings().getSetting(Oauth2Constants.CLIENT_SETTINGS.POST_LOGOUT_REDIRECT_URI);
        }
        if (!StringUtils.hasText(postLogoutRedirectUri)) {
            //获取客户端注册信息中的post_logout_redirect_uri_db
            postLogoutRedirectUri = this.oauth2ServerProps.getLogoutRedirectDefaultUrl();
        }
        if (StringUtils.hasText(state)) {
            postLogoutRedirectUri = String.format(STATE_PARAMETER_FORMAT, postLogoutRedirectUri, state);
        }
        return postLogoutRedirectUri;
    }


    /**
     * 重定向到post_logout_redirect_uri
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
     * 生成SLO页面<br/>
     * <ol>
     *     <li>根据frontchannel_logout_uri生成iframe</li>
     *     <li>页面加载完成（iframe.src均发送完成）触发重定向到post_logout_redirect_uri</li>
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
        /** 自动重定向 */
        sb.append("    <meta http-equiv=\"refresh\" content=\"0;url=" + postLogoutRedirectUri + "\"> </head>\n");
        sb.append("    <title>统一登出</title>\n");
        sb.append("  </head>\n");
        sb.append("  <body>\n");
        /** 生成多个iframe.src=frontchannel_logout_uri */
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
     * 发送400响应
     *
     * @param response
     * @throws IOException
     */
    private void response400(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.getWriter().flush();
    }
}