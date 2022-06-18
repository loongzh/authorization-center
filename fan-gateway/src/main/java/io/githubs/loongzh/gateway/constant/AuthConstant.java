package io.githubs.loongzh.gateway.constant;

/**
 * @author fan
 * @date 2022年06月18日 16:03
 */
public class AuthConstant {
    public static final String AUTHORITY_PREFIX = "SCOPE_";
    public static final String AUTHORITY_CLAIM_NAME = "authorities";
    public static final String USER_TOKEN_HEADER="user";
    public static final String JWT_TOKEN_HEADER="Authorization";
    public static final String JWT_TOKEN_PREFIX="Bearer ";
    public static final  String TOKEN_BLACKLIST_PREFIX = "auth:token:blacklist:";

}
