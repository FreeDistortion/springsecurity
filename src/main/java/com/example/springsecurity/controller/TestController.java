package com.example.springsecurity.controller;

import com.example.springsecurity.dao.SampleDAOImpl;
import com.example.springsecurity.model.SampleDTO1;
import com.example.springsecurity.model.SampleDTO2;
import com.example.springsecurity.model.SampleEntity;
import com.example.springsecurity.model.UserInfo;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final PasswordEncoder passwordEncoder;
    // for test
    private final SampleDAOImpl sampleDAO;

    @RequestMapping("/")
    public String index() {
        return "Spring Security Test";
    }

    @GetMapping("/showAuth")
    public Authentication showAuth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @GetMapping("/userpage")
    public UserInfo usepage() {
        return UserInfo.builder()
                .authentication(SecurityContextHolder.getContext().getAuthentication())
                .msg("사용자 임의로 접근 가능한 페이지")
                .build();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @GetMapping("/adminpage")
    public UserInfo adminpage() {
        return UserInfo.builder()
                .authentication(SecurityContextHolder.getContext().getAuthentication())
                .msg("관리자 임의로 접근 가능한 페이지")
                .build();
    }

    @GetMapping("/test")
    public String test() {
        SampleDTO1 dto1 = new SampleDTO1("bts", passwordEncoder.encode("1234"), "btsName");
        System.out.println("--------------------------------------");
        System.out.println(dto1);
        ModelMapper mapper = new ModelMapper();
        SampleDTO2 dto2 = mapper.map(dto1,SampleDTO2.class);
        System.out.println(dto2);
        System.out.println("--------------------------------------");
        return "ok";
    }

    @GetMapping("/write")
    public String write(){
        // Annotation! 테스트를 위해서 엔티티를 생성해서 작업...
        sampleDAO.write(new SampleEntity(
                "playdata",
                passwordEncoder.encode("playdata"),
                "PlatdataName"));
        return "ok";
    }
}