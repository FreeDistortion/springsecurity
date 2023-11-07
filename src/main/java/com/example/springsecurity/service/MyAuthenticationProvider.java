package com.example.springsecurity.service;


import com.example.springsecurity.model.SampleDTO2;
import com.example.springsecurity.model.SampleEntity;
import com.example.springsecurity.service.security.CustomerUserDetails;
import groovy.util.logging.Slf4j;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Slf4j
@RequiredArgsConstructor
public class MyAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    // TODO 검증을 위한 구현 작업
    // parameter로 전달 받은 Authentication은 AuthenticationManager로부터 return된 값.
    // 검증을 받지 못한, 사용자가 입력한 값.
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("&&&&&&&&&&&&&&&&&&&&&& PROVIDER &&&&&&&&&&&&&&&&&&&&&&");
        System.out.println(authentication);


        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!! EXTRACT START !!!!!!!!!!!!!!!!!!!!!!!!!");
        // 1. AuthenticationManager가 넘긴 Authentication object에서 사용자가 입력한 ID/PW 추출
        // username 추출
        String username = authentication.getName();
        // pw 추출
        String password = (String) authentication.getCredentials();
        System.out.println(username + ":::::::::" + password);
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!! EXTRACT END !!!!!!!!!!!!!!!!!!!!!!!!!");

        // 2. UserDetailService의 loadUserByUsername()을 호출해서 사용자 정보를 조회
        CustomerUserDetails userDetails =
                (CustomerUserDetails) userDetailsService.loadUserByUsername(username);

        // 3. UserDetails에 담긴 PW와 사용자가 입력한 PW를 encoding하여 비교
        // 만약 인증을 위해 체크해야 하는 것이 더 있다면 이 단계에서 수행.
        UsernamePasswordAuthenticationToken token = null;
        boolean state;
        if (userDetails != null) {
            state = passwordEncoder.matches(password, userDetails.getPassword());
            ModelMapper mapper = new ModelMapper();
            SampleDTO2 dto2 = mapper.map(userDetails.getEntity(), SampleDTO2.class);
            if (state) {
                // 4. 작업 완료 후 AuthenticationManager에게 넘길 인증 완료 토큰을 만들어서 정보 저장
                // 사용자 정보를 담고 있는 DTO 추출하기 위해 entity를 변환, 원랜 service에서 이루어져야 함.
                // 권한 정보를 담고 있는 DTO 추출.
                token = new UsernamePasswordAuthenticationToken(dto2, null, userDetails.getAuthorities());
                System.out.println("DTO:::::::::::" + dto2);
                System.out.println("TOKEN::::::::::::" + token);
            }
        }


        return token;
    }

    // fromLogin을 하는 경우, 전달된 parameter type이 UsernamePasswordAuthenticationToken type과 일치하는지 검사.
    // 인증한 token object가 인증 전에 전달받은 Authentication의 type과 일치하는지 비교.
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
