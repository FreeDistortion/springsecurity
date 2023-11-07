package com.example.springsecurity.service.security;

import com.example.springsecurity.model.SampleEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

// UserDetails의 하위 객체인 User로 만들어서 return.
public class CustomerUserDetails extends User {
    private final SampleEntity entity;

    public CustomerUserDetails(SampleEntity entity,
                               Collection<? extends GrantedAuthority> authorities){
        super(entity.getUsername(),entity.getPassword(),authorities);
        this.entity=entity;
    }

    public SampleEntity getEntity() {
        return entity;
    }
}
