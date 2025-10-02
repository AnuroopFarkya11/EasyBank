package com.eazybytes.exceptionhandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        LocalDateTime localDateTime = LocalDateTime.now();

        String message = (authException != null
                && authException.getMessage() != null)
                ? authException.getMessage() : "Authentication Failed";

        String path = request.getRequestURI();

        response.setHeader("easybank-authentication-reason",message);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");
        Map<String,Object> jsonResponse = new HashMap<>();
//        jsonResponse.put("timestamp",localDateTime);
        jsonResponse.put("message",message);
        jsonResponse.put("path",path);

        response.getWriter().write(new ObjectMapper().writeValueAsString(jsonResponse));


    }
}
