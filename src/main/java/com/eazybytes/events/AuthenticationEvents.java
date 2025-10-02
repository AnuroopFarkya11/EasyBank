package com.eazybytes.events;


import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationEvents {

    @EventListener(AuthenticationSuccessEvent.class)
    public void onSuccess(AuthenticationSuccessEvent success) {
        log.info("Login successful for the user : {}", success.getAuthentication().getName());
    }

    @EventListener(AbstractAuthenticationFailureEvent.class)
    public void onFailure(AbstractAuthenticationFailureEvent failure) {
        log.error("Login failed for the user : {} due to : {}", failure.getAuthentication().getName(), failure.getException().getMessage());
    }

}
