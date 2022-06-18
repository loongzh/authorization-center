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

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


/**
 * @author felord.cn
 */
@EnableWebSecurity
public class DefaultSecurityConfig  {
    @Bean
    SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(form ->
                        form.loginPage("/login")
                                .loginProcessingUrl("/login")
                )
                .authorizeRequests(requests ->
                        requests.antMatchers("/login").permitAll()
                                .antMatchers("/oauth2/user").hasAnyAuthority("SCOPE_userinfo")
                                .antMatchers("/resource/hello").hasAnyAuthority("SCOPE_userinfo")
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
                .antMatchers("/rsa/publicKey")
                .antMatchers("/css/**")
                .antMatchers("/js/**")
                .antMatchers("/images/**");
    }
}
