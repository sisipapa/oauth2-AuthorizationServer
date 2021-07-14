package com.sisipapa.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * Oauth2AuthorizationConfig
     * scopes - 인증 후 얻은 accessToken으로 접근할 수 있는 리소스의 범위이다.
     * accessTokenValiditySeconds - accessToken의 유효시간
     * redirectUri - 인증 완료 후 이동할 클라이언트 웹페이지 주소
     * authorizedGrantTypes - 4가지 방식중 authorization_code 사용
     *
     *
     * @param clients
     * @throws Exception
     */
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("testClientId")
                .secret("testSecret")
                .redirectUris("http://localhost:8081/oauth2/callback")
                .authorizedGrantTypes("authorization_code")
                .scopes("read", "write")
                .accessTokenValiditySeconds(30000);
    }
}
