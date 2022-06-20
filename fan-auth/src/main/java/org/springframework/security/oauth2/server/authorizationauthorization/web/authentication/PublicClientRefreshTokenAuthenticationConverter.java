package org.springframework.security.oauth2.server.authorizationauthorization.web.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;


/**
 * 自定义refresh_token请求解析器（支持不提供client_secret访问）
 *
 * @author luohq
 * @date 2022-03-10
 * @see org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter
 */
public final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        /** 是否是refresh_token流程 且 client_id非空 */
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType) || !StringUtils.hasText(clientId)) {
            return null;
        }
        Map<String, Object> additionalParameters = this.getAdditionalParameters(request, OAuth2ParameterNames.CLIENT_ID, OAuth2ParameterNames.REFRESH_TOKEN);
        return new OAuth2ClientAuthenticationToken(clientId,StringUtils.hasText(clientSecret)?ClientAuthenticationMethod.CLIENT_SECRET_POST:ClientAuthenticationMethod.NONE, null, additionalParameters);
    }

    /**
     * 获取额外参数
     *
     * @param request    请求
     * @param exclusions 排除的参数名称
     * @return 额外参数Map
     */
    private Map<String, Object> getAdditionalParameters(HttpServletRequest request, String... exclusions) {
        Map<String, Object> parameters = new HashMap<>(OAuth2EndpointUtils.getParameters(request).toSingleValueMap());
        for (String exclusion : exclusions) {
            parameters.remove(exclusion);
        }
        return parameters;
    }

}