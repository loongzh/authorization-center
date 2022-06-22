package io.githubs.loongzh.user.interfaces.dto;

import io.githubs.loongzh.common.user.dto.UserDto;

import javax.validation.constraints.NotEmpty;

/**
 * @author fan
 * @date 2022年06月22日 18:12
 */
public class UserDtoExt extends UserDto {
    @NotEmpty(message = "用户名不能为空")
    @Override
    public String getUsername() {
        return super.getUsername();
    }
    @NotEmpty(message = "密码不能为空")
    @Override
    public String getPassword() {
        return super.getPassword();
    }


    @NotEmpty(message = "空测试")
    private String str;
}
