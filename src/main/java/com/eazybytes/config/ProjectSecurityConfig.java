package com.eazybytes.config;

//import com.eazybytes.exceptionhandler.CustomAccessDeniedHandler;

import com.eazybytes.exceptionhandler.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandler.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CSRFCookieFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
@RequiredArgsConstructor
public class ProjectSecurityConfig {

    final CustomCorsSourceConfiguration corsSourceConfiguration;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.cors(cors -> cors.configurationSource(corsSourceConfiguration));
        httpSecurity.requiresChannel(channel -> channel.anyRequest().requiresInsecure());
        httpSecurity.sessionManagement(session -> session
                .invalidSessionUrl("/invalidSession")
                .maximumSessions(3)
                .maxSessionsPreventsLogin(true)
        );
        httpSecurity.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        httpSecurity.addFilterAfter(new CSRFCookieFilter(), BasicAuthenticationFilter.class);
        httpSecurity.authorizeHttpRequests(auth -> auth
                .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE","VIEWACCOUNT")
                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                .requestMatchers("/user").authenticated()
                .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession").permitAll()
        );
        httpSecurity.formLogin(withDefaults());
        httpSecurity.httpBasic(http -> http.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        httpSecurity.exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
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

    /**
     * JDBC User Details Service
     *
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