package com.eazybytes.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class ProjectSecurityConfig {



    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(csrf->csrf.disable());
        httpSecurity.authorizeHttpRequests((request)
                -> request.requestMatchers("/myAccount", "/myBalance", "/myCards", "/contact", "/myLoans").authenticated()
                .requestMatchers("/notices", "/contact","/error","/register").permitAll());
        httpSecurity.formLogin(withDefaults());
        httpSecurity.httpBasic(withDefaults());

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