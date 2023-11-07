package com.example.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {
    @GetMapping("/")
    public String main() {
        return "index";
    }

    @GetMapping("/mylogin")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/login-error")
    public String login(Model model) {
        model.addAttribute("loginError", true);
        return "loginForm";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @GetMapping("/user/page")
    public String usepage() {
        return "userPage";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @GetMapping("/admin/page")
    public String adminpage() {
        return "adminPage";
    }

    @GetMapping("/accesserror")
    public String accesserror() {
        return "accessDenied";
    }

}
