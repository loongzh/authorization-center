/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.githubs.loongzh.auth.config;

import io.githubs.loongzh.auth.config.handler.oidc.OidcEndSessionSingleLogoutSuccessHandler;
import io.githubs.loongzh.auth.service.OidcAuthorizationService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


/**
 * @author felord.cn
 */
@EnableConfigurationProperties(Oauth2ServerProps.class)
@EnableWebSecurity
public class DefaultSecurityConfig  {
    /**
     * OAuth2认证服务器端配置属性
     */
    private Oauth2ServerProps oauth2ServerProps;
    /**
     * Client注册信息DAO
     */
    private RegisteredClientRepository registeredClientRepository;
    /**
     * 认证信息DAO
     */
    private OidcAuthorizationService oidcAuthorizationService;

    public DefaultSecurityConfig(Oauth2ServerProps oauth2ServerProps, RegisteredClientRepository registeredClientRepository, OidcAuthorizationService oidcAuthorizationService) {
        this.oauth2ServerProps = oauth2ServerProps;
        this.registeredClientRepository = registeredClientRepository;
        this.oidcAuthorizationService = oidcAuthorizationService;
    }
    @Bean
    SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(form ->
                        form.loginPage(this.oauth2ServerProps.getLoginPageUrl())
                                .loginProcessingUrl(this.oauth2ServerProps.getLoginPageUrl())
                )
                //登出配置
                .logout(logout -> logout
                        .logoutUrl(this.oauth2ServerProps.getLogoutPageUrl())
                        //登出成功处理器 - 支持OIDC SLO
                        .logoutSuccessHandler(new OidcEndSessionSingleLogoutSuccessHandler(registeredClientRepository, oidcAuthorizationService, this.oauth2ServerProps))
                )
                .authorizeRequests(requests ->
                        requests.antMatchers(this.oauth2ServerProps.getLoginPageUrl()).permitAll()
                                .anyRequest().authenticated()
                ).oauth2ResourceServer().jwt();
    return http.build();
    }
    /**
     * Users user details service.
     *
     * @return the user details service
     */
// @formatter:off
    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("fan")
                .password("password")
                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
    // @formatter:on


    /**
     * Web security customizer web security customizer.
     *
     * @return the web security customizer
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .antMatchers("/actuator/health")
                .antMatchers("/css/**")
                .antMatchers("/js/**")
                .antMatchers("/images/**");
    }
    /**
     * 设置密码解析器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return  PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
