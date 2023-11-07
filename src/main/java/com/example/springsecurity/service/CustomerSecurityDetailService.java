package com.example.springsecurity.service;

import com.example.springsecurity.dao.SampleDAOImpl;
import com.example.springsecurity.model.SampleEntity;
import com.example.springsecurity.service.security.CustomerUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomerSecurityDetailService implements UserDetailsService {

        private final SampleDAOImpl sampleDAO;
        // AuthenticationProvider에 의해 호출되는 method. user id를 이용해서 DB에서 조회한 결과를 UserDetails로 return.
        // 조회한 entity를 UserDetails로 변환해서 return.
        // UserDetails(Security framework 내부에서 인식하는 인증값을 담고있는 특별한 dto)
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                // 1. 사용자 아이디로 정보 조회
                SampleEntity entity = sampleDAO.login(username);

                // 사용자가 없으면 exception throw
                if(entity==null){
                        throw new UsernameNotFoundException("No User.");
                }

                // 2. loadUserByUsername method는 조회한 사용자의 정보를 UserDetails의 하위로 만들어서 return.
                // -> 인증이 완료되면 Authentication 객체 내부에 저장될 객체.
                // -> UserDetails가 갖고 있는 값들을 채워서 return.
                // Spring Security 내부에서 인증된 객체는 권한이 중요. 따라서 내부에 자체적으로 인증 객체의 권한 정보를 List 형태로 갖고 있다.
                // 이 권한 정보를 모델링한 객체가 GrantedAuthority임.
//                List<GrantedAuthority> roles = new ArrayList<>();
                List<GrantedAuthority> roles = new ArrayList<>();

                // getRole이 없어서 일단 임시로 넣음

                // 유저가 있는지 가져오고, 암호화한 암호와 저장된 암호가 같은지 비교. 해당 작업은 복호화가 안 되기 때문에.
                // roles.add(new SimpleGrantedAuthority("ROLE_USER"));
                roles.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

                CustomerUserDetails userDetails = new CustomerUserDetails(entity,roles);

                return userDetails;
        }
}
