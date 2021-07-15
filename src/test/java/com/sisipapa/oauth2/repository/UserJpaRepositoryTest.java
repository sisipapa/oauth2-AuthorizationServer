package com.sisipapa.oauth2.repository;

import com.sisipapa.oauth2.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@SpringBootTest
class UserJpaRepositoryTest {
    @Autowired
    private UserJpaRepository userJpaRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void insertNewUser() {
        userJpaRepository.save(User.builder()
                .uid("sisipapa239@gmail.com")
                .password(passwordEncoder.encode("1234"))
                .name("sisipapa")
                .roles(Collections.singletonList("ROLE_USER"))
                .build());
    }
}