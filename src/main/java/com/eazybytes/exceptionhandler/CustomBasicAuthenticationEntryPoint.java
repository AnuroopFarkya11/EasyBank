package com.eazybytes.exceptionhandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        ///  Adding a custom header
        response.setHeader("easybank-error-reason","Authentication failed.");

        response.sendError(HttpStatus.UNAUTHORIZED.value(),HttpStatus.UNAUTHORIZED.getReasonPhrase());

        response.setContentType("application/json");

        Map<String,Object> jsonResponse = new HashMap<>();
        jsonResponse.put("EXAMPLE","timestamp");

        response.getWriter().write(new ObjectMapper().writeValueAsString(jsonResponse));


    }
}
