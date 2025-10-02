package com.eazybytes.config;

import com.eazybytes.exceptionhandler.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandler.CustomBasicAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
@RequiredArgsConstructor
public class ProjectSecurityProdConfig {



    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.requiresChannel(rcc->rcc.anyRequest().requiresSecure());
        httpSecurity.sessionManagement(sm->sm.invalidSessionUrl("/invalidSession").maximumSessions(1).maxSessionsPreventsLogin(true));
        httpSecurity.csrf(csrf->csrf.disable());
        httpSecurity.authorizeHttpRequests((request)
                -> request.requestMatchers("/myAccount", "/myBalance", "/myCards", "/contact", "/myLoans").authenticated()
                .requestMatchers("/notices", "/contact","/error","/register","/invalidSession").permitAll());
        httpSecurity.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        httpSecurity.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        return httpSecurity.build();
    }




    /**
     * InMemory User Details Service
     *
     * @Bean public UserDetailsService userDetailsService()
     * {
     * UserDetails user = User.withUsername("user").password("{noop}12345").authorities("read").build();
     * UserDetails admin = User.withUsername("admin").password("{noop}54321").authorities("admin").build();
     * UserDetails trial = new User("trial","passsword", Collections.singleton(new SimpleGrantedAuthority("ROLE_TRIAL")));
     * return new InMemoryUserDetailsManager(user,admin,trial);
     * }
     */

    /** JDBC User Details Service
     * @Bean public UserDetailsService userDetailsService(DataSource dataSource) {
     * return new JdbcUserDetailsManager(dataSource);
     * }
     */



    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }


}