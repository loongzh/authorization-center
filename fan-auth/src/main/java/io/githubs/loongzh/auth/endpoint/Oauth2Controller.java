package io.githubs.loongzh.auth.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.githubs.loongzh.auth.config.token.KeyConfig;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.Map;

/**
 * @author fan
 * @date 2022年06月18日 14:11
 */
@RestController
public class Oauth2Controller {
    @GetMapping("/rsa/publicKey")
    public Map<String, Object> getKey()
    {
        RSAKey key  = new RSAKey.Builder(KeyConfig.getVerifierKey()).build();
        return new JWKSet(key).toJSONObject();
    }
    @GetMapping("login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }
    @RequestMapping("/oauth2/consent")
    public ModelAndView consent(@RequestParam String scope, @RequestParam String client_id, @RequestParam String state, Authentication authentication, Model model) {
        model.addAttribute("scopes", scope.split(" "));
        model.addAttribute("clientId", client_id);
        model.addAttribute("state", state);
        return new ModelAndView("consent");
    }
}
