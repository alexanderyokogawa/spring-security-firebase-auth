package com.amaxnetlab.firebaseauth.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors() .and()
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                                .requestMatchers("/actuator/**").permitAll()
                                .requestMatchers("/api/user/get/**").hasAuthority("ROLE_USER")
                                .requestMatchers("/api/user/create").hasAuthority("ROLE_USER")
                                .requestMatchers("/api/user/update/**").hasAuthority("ROLE_USER")
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                ))
                .csrf().disable()
                .build();
    }

    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt ->
                Optional.ofNullable(jwt.getClaimAsStringList("role"))
                        .stream()
                        .flatMap(Collection::stream)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList())
        );

        return converter;
    }
}
