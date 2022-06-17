package io.githubs.loongzh.auth;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.githubs.loongzh.auth.config.token.KeyConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class UserController {
    @GetMapping("/user")
    public Principal getCurrentUser(Principal principal) {
        return principal;
    }

    @GetMapping("/rsa/publicKey")
    public Map<String, Object> getKey()
    {
        RSAKey key  = new RSAKey.Builder(KeyConfig.getVerifierKey()).build();
        return new JWKSet(key).toJSONObject();
    }
}
