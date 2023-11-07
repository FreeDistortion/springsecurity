package com.example.springsecurity.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class UserInfo {
    private Authentication authentication;
    private String msg;
}
