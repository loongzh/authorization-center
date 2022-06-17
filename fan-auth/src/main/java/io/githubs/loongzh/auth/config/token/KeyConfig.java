package io.githubs.loongzh.auth.config.token;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author fan
 * @date 2022年06月17日 14:14
 */
@Slf4j
public class KeyConfig {
    private static  final String KEY_STORE_FILE="jwt.jks";
    private static  final String KEY_STORE_PASSWORD="123qwe...";
    private static  final String KEY_ALIAS="jwt";
    private static  final KeyStoreKeyFactory KEY_STORE_KEY_FACTORY=
            new KeyStoreKeyFactory(new ClassPathResource(KEY_STORE_FILE),
                    KEY_STORE_PASSWORD.toCharArray());
    public static RSAPublicKey getVerifierKey(){
        return (RSAPublicKey)getKeyPair().getPublic();
    }
    public static RSAPrivateKey getSingerKey(){
        return (RSAPrivateKey) getKeyPair().getPrivate();
    }
    public static KeyPair getKeyPair(){
        return KEY_STORE_KEY_FACTORY.getKeyPair(KEY_ALIAS);
    }
}
