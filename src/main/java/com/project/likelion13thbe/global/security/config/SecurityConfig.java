package com.project.likelion13thbe.global.security.config;

import com.project.likelion13thbe.global.security.exception.handler.CustomLogoutHandler;
import com.project.likelion13thbe.global.security.exception.handler.CustomLogoutSuccessHandler;
import com.project.likelion13thbe.global.security.filter.CustomLoginFilter;
import com.project.likelion13thbe.global.security.exception.handler.JwtAuthenticationEntryPoint;
import com.project.likelion13thbe.global.security.filter.ForcePasswordChangeFilter;
import com.project.likelion13thbe.global.security.filter.JwtAuthorizationFilter;
import com.project.likelion13thbe.global.security.exception.handler.JwtAccessDeniedHandler;
import com.project.likelion13thbe.global.security.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // 빈 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final CustomLogoutHandler jwtLogoutHandler;
    private final CustomLogoutSuccessHandler jwtLogoutSuccessHandler;
    private final RedisTemplate<String, String> redisTemplate;


    //인증이 필요하지 않은 url
    private final String[] allowUrl = {
            "/",
            "/index.html",
            "/login", //로그인 은 인증이 필요하지 않음
            "/auth", // 회원가입은 인증이 필요하지 않음
            "/temp-password", // 임시 비밀번호 발급
            "/mail-verifications/*", // 메일 인증 일단 빼기
            "/api/v1/login/kakao",
            "/s3/public-download-url", //s3 공개 파일 다운로드
            "/auth/reissue", // 토큰 재발급은 인증이 필요하지 않음
            "/auth/**",
            "api/usage",
            "/swagger-ui/**",   // swagger 관련 URL
            "/v3/api-docs/**",
    };

    // 인증이 필요하지 않은 GET url
    private final String[] allowGetUrl = {
            // product
            "/products",    // 상품 목록 조회
            "/products/*",  // 상품 상세 조회, cursor 조회

            // review
            "/products/**",  // 리뷰 상세 조회, cursor 조회
            "/reviews/*",   // 리뷰 목록 조회 (내 리뷰도 포함되나 선처리로 해결)

            // comment
            "/reviews/**",    // 댓글 목록 조회, cursor

            // kakao
            "/callback/kakao",

            // mail
            "/mail-verifications/request",
    };

    // 인증이 필요한 GET url
    private final String[] forbidGetUrl = {
            // review
            "/reviews/my"   // 내 리뷰 조회
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CustomLoginFilter loginFilter = new CustomLoginFilter(authenticationManager(authenticationConfiguration), jwtUtil);
        loginFilter.setFilterProcessesUrl("/login");

        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers(HttpMethod.GET, forbidGetUrl).authenticated()
                        .requestMatchers(allowUrl).permitAll()
                        .requestMatchers(HttpMethod.GET, allowGetUrl).permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new JwtAuthorizationFilter(jwtUtil, redisTemplate), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new ForcePasswordChangeFilter(), JwtAuthorizationFilter.class)
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(HttpBasicConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                // logout
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(jwtLogoutHandler)
                        .logoutSuccessHandler(jwtLogoutSuccessHandler)
                )
                // end of logout
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint))
        ;

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}