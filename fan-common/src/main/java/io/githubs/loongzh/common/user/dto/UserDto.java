package io.githubs.loongzh.common.user.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

/**
 * @author fan
 * @date 2022年06月22日 18:25
 */
@Getter
@Setter
public class UserDto {
    private UUID id;
    private String username;
    private String password;
    private String phone;
}
