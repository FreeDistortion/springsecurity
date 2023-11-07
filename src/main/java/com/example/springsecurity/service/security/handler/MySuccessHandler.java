package com.example.springsecurity.service.security.handler;

import com.example.springsecurity.model.SampleDTO2;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class MySuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SampleDTO2 dto = (SampleDTO2) authentication.getPrincipal();
        System.out.println("인증 성공 후 실행: "+authentication);
        request.getSession().setAttribute("user",dto);

        // 인증이 성공하면 JW

    }
}
