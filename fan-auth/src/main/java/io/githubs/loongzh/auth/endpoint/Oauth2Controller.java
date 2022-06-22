package io.githubs.loongzh.auth.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.githubs.loongzh.auth.constant.Oauth2Constants;
import io.githubs.loongzh.auth.utils.KeyConfig;
import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.*;

/**
 * @author fan
 * @date 2022年06月18日 14:11
 */
@RestController
public class Oauth2Controller {

    /**
     * Client注册信息 - 仓库
     */
    private final RegisteredClientRepository registeredClientRepository;
    /**
     * 认证Consent信息 - 服务
     */
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public Oauth2Controller(RegisteredClientRepository registeredClientRepository,
                                          OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }
    @GetMapping("login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }
    //通过Token退出
    @GetMapping("logout-web")
    public ModelAndView logoutWeb() {
        //根据Token_Value获取Session和UserAccount，删除相关记录。
        return new ModelAndView("logout");
    }
    //通过Session退出
    @GetMapping("logout-spa")
    public ModelAndView logoutSpa() {
        //根据Token_Value获取Session和UserAccount，删除相关记录。
        return new ModelAndView("logout");
    }
//    @RequestMapping("/oauth2/consent")
//    public ModelAndView consent(@RequestParam String scope, @RequestParam String client_id, @RequestParam String state, Authentication authentication, Model model) {
//        model.addAttribute("scopes", scope.split(" "));
//        model.addAttribute("clientId", client_id);
//        model.addAttribute("state", state);
//        return new ModelAndView("consent");
//    }
    /**
     * Consent页面（确认请求scope的页面）
     *
     * @param principal 用户信息
     * @param model     model
     * @param clientId  客户端ID
     * @param scope     请求范围
     * @param state     state参数
     * @return Consent页面
     */
    @GetMapping(value = "/oauth2/consent")
    public ModelAndView consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {

        /** 移除已经授权过的scope */
        //待授权的scope
        Set<String> scopesToApprove = new HashSet<>();
        //之前已经授权过的scope
        Set<String> previouslyApprovedScopes = new HashSet<>();
        //获取客户端注册信息
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        //获取当前Client下用户之前的consent信息
        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());
        //当前Client下用户已经授权的scope
        Set<String> authorizedScopes = Optional.ofNullable(currentAuthorizationConsent)
                .map(OAuth2AuthorizationConsent::getScopes)
                .orElse(Collections.emptySet());
        //遍历请求的scope，提取之前已授权过 和 待授权的scope
        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, Oauth2Constants.SPACE)) {
            if (authorizedScopes.contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else if (!OidcScopes.OPENID.equals(requestedScope)) {
                scopesToApprove.add(requestedScope);
            }
        }

        //输出信息指consent页面
        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());
        return new ModelAndView("consent");
    }

    /**
     * 根据scope生成相关权限描述
     *
     * @param scopes scope集合
     * @return scope描述集合
     */
    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));
        }
        return scopeWithDescriptions;
    }

    /**
     * 权限描述信息
     */
    @Data
    public static class ScopeWithDescription {
        private static final String DEFAULT_DESCRIPTION = "未知SCOPE - 无法确认相关权限信息，请谨慎授予权限！";
        private static final Map<String, String> SCOPE_DESCRIPTION_MAP = new HashMap<>();

        static {
            SCOPE_DESCRIPTION_MAP.put(
                    "openid",
                    "当前应用将使用OIDC认证"
            );
            SCOPE_DESCRIPTION_MAP.put(
                    "profile",
                    "当前应用将读取你的身份信息"
            );
            SCOPE_DESCRIPTION_MAP.put(
                    "phone",
                    "当前应用将读取你的电话号码"
            );
            SCOPE_DESCRIPTION_MAP.put(
                    "email",
                    "当前应用将读取你的电子邮件信息"
            );
            SCOPE_DESCRIPTION_MAP.put(
                    "roles",
                    "当前应用将读取你的用户角色信息"
            );
            SCOPE_DESCRIPTION_MAP.put(
                    "offline_access",
                    "当前应用将支持刷新令牌流程"
            );
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = SCOPE_DESCRIPTION_MAP.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }
}
