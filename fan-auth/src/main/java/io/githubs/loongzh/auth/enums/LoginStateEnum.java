package io.githubs.loongzh.auth.enums;

/**
 * 登录状态枚举
 *
 * @author luohq
 * @version 1.0.0
 * @date 2022-02-21 11:10
 */
public enum LoginStateEnum {
    LOGIN(1, "已登录"),
    LOGOUT(2, "已登出");

    /**
     * 登录状态
     */
    private Integer code;
    /**
     * 登录状态描述
     */
    private String desc;

    LoginStateEnum(Integer code, String desc) {
        this.code = code;
        this.desc = desc;
    }

    public Integer getCode() {
        return code;
    }

    public String getDesc() {
        return desc;
    }
}
