package com.sisipapa.oauth2;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoding {
    public static void main(String[] args){
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        System.out.printf("testSecret : %s\n", passwordEncoder.encode("testSecret"));
    }
}
