늦었지만 이전 직장에서 인증서버 담당자로 일하면서 운영했던 Springboot + Oauth2 + JWT를 활용한 인증서버에 대해 정리해보려고 한다. 참고 링크에 포함된 아빠 프로그래머님의 블로그 oauth2 인증서버 관련 내용이 정리가 잘되어 있어 참고해서 정리를 하려고 한다.  

## Pre Setting
- H2 DB설치  
이전 블로그 [Springboot Document 라이브러리2(Spring Restdoc)](https://sisipapa.github.io/blog/2021/04/09/Springboot-Document-%EB%9D%BC%EC%9D%B4%EB%B8%8C%EB%9F%AC%EB%A6%AC2(Spring-Restdoc)/)의 H2 DB설치 부분을 참고해서 H2 DB를 설치한다. 
  
## build.gradle 및 Configration 파일 작성  
### build.gradle  
```properties
plugins {
    id 'org.springframework.boot' version '2.1.4.RELEASE'
    id 'io.spring.dependency-management' version '1.0.11.RELEASE'
    id 'java'
}

group = 'com.sisipapa'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = '11'

configurations {
    compileOnly {
        extendsFrom annotationProcessor
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    runtimeOnly 'com.h2database:h2'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'

    implementation 'org.springframework.cloud:spring-cloud-starter-security:2.1.2.RELEASE'
    implementation 'org.springframework.cloud:spring-cloud-starter-oauth2:2.1.2.RELEASE'
    implementation 'com.google.code.gson:gson'
}

test {
    useJUnitPlatform()
}
```  

### Authorization Server Config 생성  
SpringSecurity 5버전에서는 NoOpPasswordEncoder가 deprecate 되어 secret의 value값 앞에 {noop}을 붙여야 오류없이 테스트 진행이 가능하다.  
withClient : 인증서버에 인가된 client인지 확인을 위한 ID  
secret : 인증서버에 인가된 client인지 확인을 위한 SECRET  
redirectUris : 인증 완료 후 이동할 클라이언트 웹 페이지 주소로 code 값을 같이 보내준다.
authorizedGrantTypes : 인증방식은 총 4가지가 있다. 여기서는 authorization_code를 사용한다.  
scopes : accessToken으로 접근할 수 있는 리소스의 범위  
accessTokenValiditySeconds : 발급된 accessToken의 유효시간(초)  

```java

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("testClientId")
                .secret("{noop}testSecret")
                .redirectUris("http://localhost:8081/oauth2/callback")
                .authorizedGrantTypes("authorization_code")
                .scopes("read", "write")
                .accessTokenValiditySeconds(30000);

    }
}
```  

### SpringSecurity Config 생성  
SpringSecurity 5버전에서는 NoOpPasswordEncoder가 deprecate 되어 password의 value값 앞에 {noop}을 붙여야 오류없이 테스트 진행이 가능하다.    

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("test")
                .password("{noop}test")
                .roles("USER");
    }
    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests().antMatchers("/oauth/**", "/oauth2/callback", "/h2-console/*").permitAll()
                .and()
                .formLogin().and()
                .httpBasic();
    }
}
```  

### WebMvcConfig 생성
```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    private static final long MAX_AGE_SECONDS = 3600;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(MAX_AGE_SECONDS);
    }

    @Bean
    public RestTemplate getRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```  

### 토큰정보를 받을 모델
```java  

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthToken {
    private String access_token;
    private String token_type;
    private String refresh_token;
    private long expires_in;
    private String scope;
}
```  

### application.yml 설정
```yaml  
server:
  port: 8081
spring:
  h2:
    console:
      enabled: true
      settings:
        web-allow-others: true
  datasource:
    url: jdbc:h2:tcp://localhost/~/test
    driver-class-name: org.h2.Driver
    username: sa
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    properties.hibernate.hbm2ddl.auto: update
    showSql: true
```  

## 테스트
1. 로그인페이지 접속 : http://localhost:8081/oauth/authorize?client_id=testClientId&redirect_uri=http://localhost:8081/oauth2/callback&response_type=code&scope=read  
2. 아이디/패스워드 입력 후 Sign in 버튼 클릭(test / test)  
   <img src="https://sisipapa.github.io/assets/images/posts/oauth2-login.png" >  
3. Oauth Approval 설정 - Approve 체크박스 선택 후 Authorize 버튼 클릭  
   <img src="https://sisipapa.github.io/assets/images/posts/oauth2-approval.png" >  
4. 토큰 확인  
   <img src="https://sisipapa.github.io/assets/images/posts/oauth2-token.png" >  
   
## 프로젝트 설정시 오류  
아빠프로그래머님의 블로그의 build.gradle의 springboot version과 spring-cloud-starter-security, spring-cloud-starter-oauth2 버전을 최신 버전으로 변경 시 오류가 발생했다. 여기서는 오류원인 파악 및 해결에 초점을 두기 보다는 인증서버 구성을 빠르게 진행해 보기 위해 블로그와 동일한 설정을 적용했다.  
```text
Caused by: java.lang.NoClassDefFoundError: org/springframework/boot/context/properties/ConfigurationPropertiesBean
	at org.springframework.cloud.context.properties.ConfigurationPropertiesBeans.postProcessBeforeInitialization(ConfigurationPropertiesBeans.java:94) ~[spring-cloud-context-2.2.4.RELEASE.jar:2.2.4.RELEASE]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.applyBeanPostProcessorsBeforeInitialization(AbstractAutowireCapableBeanFactory.java:414) ~[spring-beans-5.1.6.RELEASE.jar:5.1.6.RELEASE]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1770) ~[spring-beans-5.1.6.RELEASE.jar:5.1.6.RELEASE]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:593) ~[spring-beans-5.1.6.RELEASE.jar:5.1.6.RELEASE]
	... 26 common frames omitted
Caused by: java.lang.ClassNotFoundException: org.springframework.boot.context.properties.ConfigurationPropertiesBean
	at java.base/jdk.internal.loader.BuiltinClassLoader.loadClass(BuiltinClassLoader.java:583) ~[na:na]
	at java.base/jdk.internal.loader.ClassLoaders$AppClassLoader.loadClass(ClassLoaders.java:178) ~[na:na]
	at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:521) ~[na:na]
	... 30 common frames omitted
```  

## 참고    
[아빠프로그래머 Spring Boot Oauth2 - AuthorizationServer](https://daddyprogrammer.org/post/1239/spring-oauth-authorizationserver/)  
  
[SISIPAPA 노트연결](https://sisipapa.github.io/blog/2021/07/12/Springboot-Oauth2-AuthorizationServer/)     
  
===================================================================================================================================================================================

이전에는 inMemory 방식으로 서버에서 하드코딩된 인증정보를 통해 인증을 진행 했던 부분을 DB를 사용해 처리할 수 있도록 수정할 예정이다.  
[아빠프로그래머 Spring Boot Oauth2 - AuthorizationServer : DB처리,JWT토큰 방식 적용](https://daddyprogrammer.org/post/1287/spring-oauth2-authorizationserver-database/) 블로그를 참고해서 진행할 예정이다.

## 변경사항
- 클라이언트 DB 인증
- 로그인 사용자 DB 인증
- 인증 및 토큰정보 DB 인증

## 클라이언트 DB인증
resources > db 디렉토리 하위에 schema.sql 중 아래 쿼리를 H2 DB에서 실행한다.    
oauth_client_details 테이블은 인증 전 인가된 client인지를 확인하기 위한 테이블이다.

클라이언트 인가를 위한 테이블 생성 및 클라이언트 데이터 Insert
```sql  
create table IF NOT EXISTS oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);

insert into oauth_client_details(client_id, resource_ids,client_secret,scope,authorized_grant_types,web_server_redirect_uri,authorities,access_token_validity,refresh_token_validity,additional_information,autoapprove)
values('testClientId',null,'{bcrypt}$2a$10$MtkK9P2c4GC4isH1GujIF.D98iO1j1BfyJxVwtHnhf8LYHswwghjO','read,write','authorization_code,refresh_token','http://localhost:8081/oauth2/callback','ROLE_USER',36000,50000,null,null);
```  

Oauth2AuthorizationConfig 수정
```java
@RequiredArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final DataSource dataSource;

    /**
     * 클라이언트 정보를 DB 정보로 인증
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }
}
```  

## 로그인 사용자 DB인증
### User Entity 생성
```java  
@Builder // builder를 사용할수 있게 합니다.
@Entity // jpa entity임을 알립니다.
@Getter // user 필드값의 getter를 자동으로 생성합니다.
@NoArgsConstructor // 인자없는 생성자를 자동으로 생성합니다.
@AllArgsConstructor // 인자를 모두 갖춘 생성자를 자동으로 생성합니다.
@Table(name = "user") // 'user' 테이블과 매핑됨을 명시
public class User implements UserDetails {
    @Id // pk
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long msrl;
    @Column(nullable = false, unique = true, length = 50)
    private String uid;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(length = 100)
    private String password;
    @Column(nullable = false, length = 100)
    private String name;
    @Column(length = 100)
    private String provider;

    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public String getUsername() {
        return this.uid;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```  
### User Repository 생성
```java
import com.sisipapa.oauth2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserJpaRepository extends JpaRepository<User, Long> {
    Optional<User> findByUid(String email);
}
```  

### 로그인 유효성 검증을 위한 AuthenticationProvider 생성
```java
import com.sisipapa.oauth2.model.User;
import com.sisipapa.oauth2.repository.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;

    private final UserJpaRepository userJpaRepository;

    @Override
    public Authentication authenticate(Authentication authentication) {

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        User user = userJpaRepository.findByUid(name).orElseThrow(() -> new UsernameNotFoundException("user is not exists"));

        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new BadCredentialsException("password is not valid");

        return new UsernamePasswordAuthenticationToken(name, password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                UsernamePasswordAuthenticationToken.class);
    }
}
```  

### SpringSecurity 관련 Config 수정
```java
import com.sisipapa.oauth2.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationProvider authenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests().antMatchers("/oauth/**", "/oauth/token", "/oauth2/callback", "/h2-console/*").permitAll()
                .and()
                .formLogin().and()
                .httpBasic();
    }
}
```  

### 로그인 사용자 DB인증을 위한 테스트 데이터 등록
지금까지 작업한 Server를 실행하고 아래 클릭해서 user 테이블에 등록한 테스트 데이터로 로그인을 하면 정상 로그인을 확인할 수 있다.  
[TEST URI 클릭](http://localhost:8081/oauth/authorize?client_id=testClientId&redirect_uri=http://localhost:8081/oauth2/callback&response_type=code&scope=read)
```java
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
```  

## 인증 및 토큰정보 DB 인증
### 토큰정보 DB 관리를 위한 테이블 생성 sql 실행
```sql
create table IF NOT EXISTS oauth_client_token (
    token_id VARCHAR(256),
    token LONGVARBINARY,
    authentication_id VARCHAR(256) PRIMARY KEY,
    user_name VARCHAR(256),
    client_id VARCHAR(256)
    );

create table IF NOT EXISTS oauth_access_token (
    token_id VARCHAR(256),
    token LONGVARBINARY,
    authentication_id VARCHAR(256) PRIMARY KEY,
    user_name VARCHAR(256),
    client_id VARCHAR(256),
    authentication LONGVARBINARY,
    refresh_token VARCHAR(256)
    );

create table IF NOT EXISTS oauth_refresh_token (
    token_id VARCHAR(256),
    token LONGVARBINARY,
    authentication LONGVARBINARY
    );

create table IF NOT EXISTS oauth_code (
    code VARCHAR(256), authentication LONGVARBINARY
    );

create table IF NOT EXISTS oauth_approvals (
    userId VARCHAR(256),
    clientId VARCHAR(256),
    scope VARCHAR(256),
    status VARCHAR(10),
    expiresAt TIMESTAMP,
    lastModifiedAt TIMESTAMP
    );
```  

### Token정보 DB 관리를 위한 설정추가(Oauth2AuthorizationConfig Config 추가)
```java
    /**
     * 토큰 정보를 DB 관리
     * @return
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new JdbcTokenStore(dataSource));
    }
```  

### Token정보 DB 관리가 아닌 JWT으로 변경
JdbcTokenStore가 아닌 jwtAccessTokenConverter를 사용하도록 설정한다. JWT를 사용하게 되면 토큰 자체로 인증정보가 관리가 되어 DB테이블을 사용하지 않게 된다.  
[JWT Token 발급 테스트 URI 클릭](http://localhost:8081/oauth/authorize?client_id=testClientId&redirect_uri=http://localhost:8081/oauth2/callback&response_type=code&scope=read)

```java
    /**
     * 토큰 정보를 DB 관리
     * @return
     */
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.tokenStore(new JdbcTokenStore(dataSource));
//    }

    /**
     * 토큰 발급 방식을 JWT 토큰 방식으로 변경한다. 이렇게 하면 토큰 저장하는 DB Table은 필요가 없다.
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
        endpoints.accessTokenConverter(jwtAccessTokenConverter());
    }

    /**
     * jwt converter를 등록
     *
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return new JwtAccessTokenConverter();
    }
```  

### refresh_token을 이용한 access_token 재발급
refresh_token이 정상인지 확인을 위해서는 회원정보를 조회해 봐야 하기때문에 Oauth2AuthorizationConfig에 userDetailsService를 설정해준다.
```java
    /**
     * 토큰 발급 방식을 JWT 토큰 방식으로 변경한다. 이렇게 하면 토큰 저장하는 DB Table은 필요가 없다.
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
//        endpoints.accessTokenConverter(jwtAccessTokenConverter());
        endpoints.accessTokenConverter(jwtAccessTokenConverter()).userDetailsService(userDetailService);
    }
```

### jwt signkey 세팅(application.yaml 파일에 추가)
이전 테스트까지는 signKey를 설정하지 않아서 임의의 키로 암호화가 되었지만 refresh_token 재발급을 위해서는 복호화가 되어야 하는데 이때 signKey가 필요하기 때문에 설정이 필요하다.
```yaml
  security:
    oauth2:
      jwt:
        signkey: 123@#$
```  

### Oauth2AuthorizationConfig의 JwtAccessTokenConverter에 signKey를 추가
```java

    @Value("${security.oauth2.jwt.signkey}")
    private String signKey;

    /**
     * jwt converter를 등록
     *
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
//        return new JwtAccessTokenConverter();
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(signKey);
        return converter;
    }
```  

### refresh 토큰을 위한 Controller API 추가
로그인 할 때 발급받은 refresh_token을 아래 API의 파라미터로 넣고 호출하면 새로운 refresh_token이 발급된다.  
[refresh 토큰 테스트 클릭](http://localhost:8081/oauth2/token/refresh?refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJzaXNpcGFwYTIzOUBnbWFpbC5jb20iLCJzY29wZSI6WyJyZWFkIl0sImF0aSI6IjUyOGVkMDliLTIwN2ItNDM2NS1hNTgxLWQyNzEzYmU2OWViNiIsImV4cCI6MTYyNjM2OTYzOCwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6IjY5OTU0ODJkLTAwMjUtNDg4My1iYTQ2LWFiZWI2ZGE0YmVmNiIsImNsaWVudF9pZCI6InRlc3RDbGllbnRJZCJ9.c0Zv4wu85cSgwfLBbfZeeXS3e87LFLrYz3FIde7sBo0)
```java
    @GetMapping(value = "/token/refresh")
    public OAuthToken refreshToken(@RequestParam String refreshToken) {

        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("refresh_token", refreshToken);
        params.add("grant_type", "refresh_token");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8081/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }
```  

## 참고
[아빠프로그래머 Spring Boot Oauth2 - AuthorizationServer : DB처리,JWT토큰 방식 적용](https://daddyprogrammer.org/post/1287/spring-oauth2-authorizationserver-database/)  

[SISIPAPA 노트연결](https://sisipapa.github.io/blog/2021/07/13/Springboot-Oauth2-AuthorizationServer2/)    

