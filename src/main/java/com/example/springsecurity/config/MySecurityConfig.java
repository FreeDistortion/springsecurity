package com.example.springsecurity.config;

import com.example.springsecurity.service.CustomerSecurityDetailService;
import com.example.springsecurity.service.MyAuthenticationProvider;
import com.example.springsecurity.service.security.handler.MyFailureHandler;
import com.example.springsecurity.service.security.handler.MySuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 설정 파일로 인식
@EnableWebSecurity(debug = false)
@Configuration

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MySecurityConfig {

    // 원래는 생성자로 엮어서 Autowired 하던가, RequiredArgsConstructor로 하는 게 맞음.

    @Autowired
    CustomerSecurityDetailService service;

    @Autowired
    MySuccessHandler mySuccessHandler;

    @Autowired
    MyFailureHandler myFailureHandler;

    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new MyAuthenticationProvider(service,passwordEncoder());
    }
    /*
    // Only customize UserDetailService
    @Bean
    public AuthenticationProvider authenticationProvider(){
        // DB연동으로 인증처리를 수행하는 provider.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(service);
        return provider;
    }
    */


    // InMemoryUserDetailsManager: 메모리로 사용자를 관리할 수 있도록 설정할 수 있는 객체
    /*
    @Bean
    public InMemoryUserDetailsManager createuser() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("bts1")
                .password("1234")
                .roles("USER")
                .build();
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("1234")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
    */

    // 권한 설정 - 권한에 대한 계층구조 세팅
    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ETC > ROLE_USER");
        return roleHierarchy;
    }

    // pw 암호화
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    // 기본 필터 체인은 모든 페이지를 검증
    // 첫 번째 페이지를 모두 허용하고 나머지만 검증하도록 변경
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> {
                    // index page를 response하는 / 요청만 모든 사용자에게 허용,
                    // 나머지는 인증이 된 사용자들만 접속할 수 있도록
                    request.requestMatchers("/","/test","/write").permitAll()
                            .anyRequest().authenticated();
                    //security login페이지가 실행되도록 처리
                })
                .formLogin(login -> login
                        .loginPage("/mylogin").permitAll()
                        .defaultSuccessUrl("/", false)
                        .failureUrl("/login-error")
                        .successHandler(mySuccessHandler)
                        .failureHandler(myFailureHandler)
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                )
                .exceptionHandling(exception -> exception
                        .accessDeniedPage("/accesserror")
                )
                .csrf(csrfConfigurer -> csrfConfigurer.disable());
        AuthenticationManagerBuilder authenticationManagerBuilder
                = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
        return http.build();
    }



    // css와 js, image는 security를 인증하지 않고 처리할 수 있도록 작업
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            web.ignoring().requestMatchers(
                    PathRequest.toStaticResources().atCommonLocations()
            );
        };
    }
}
