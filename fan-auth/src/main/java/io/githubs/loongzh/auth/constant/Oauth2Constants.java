package io.githubs.loongzh.auth.constant;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 常量定义
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-02-21 10:35
 */
public class Oauth2Constants {
    public static final String SPACE = " ";

    public static final class OIDC_PARAMETERS {
        public static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    }

    public static final class PROVIDER_SETTINGS {
        public static final String END_SESSION_ENDPOINT = "end_session_endpoint";
    }

    public static final class TOKEN_SETTINGS {
        public static final String ALLOW_PUBLIC_CLIENT_REFRESH_TOKEN = "settings.token.allow-public-client-refresh-token";
    }

    public static final class CLIENT_SETTINGS {
        public static final String FRONTCHANNEL_LOGOUT_URI = "settings.client.frontchannel_logout_uri";
        public static final String FRONTCHANNEL_LOGOUT_URI_FORMAT = "%s?iss=%s&sid=%s";
        public static final String BACKCHANNEL_LOGOUT_URI = "settings.client.backchannel_logout_uri";
        public static final String POST_LOGOUT_REDIRECT_URI = "settings.client.post_logout_redirect_uri";
    }

    public static final class CLAIMS {
        public static final String SID = "sid";
        public static final String EVENTS = "events";
        public static final Map<String, Map<String, String>> EVENTS_VALUE = new HashMap<>();

        static {
            EVENTS_VALUE.put("http://schemas.openid.net/event/backchannel-logout", Collections.EMPTY_MAP);
        }
    }

    public static final class AUTHORIZATION_ATTRS {
        public static final String SESSION_ID = "session_id";
        public static final String LOGIN_STATE = "login_state";
    }

}
