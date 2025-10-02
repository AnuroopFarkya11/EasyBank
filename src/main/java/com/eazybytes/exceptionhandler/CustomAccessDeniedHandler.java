package com.eazybytes.exceptionhandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        LocalDateTime localDateTime = LocalDateTime.now();

        String message = (accessDeniedException != null
                && accessDeniedException.getMessage() != null)
                ? accessDeniedException.getMessage() : "Access Failed";

        String path = request.getRequestURI();

        response.setHeader("easybank-denied-reason",message);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");
        Map<String,Object> jsonResponse = new HashMap<>();
//        jsonResponse.put("timestamp",localDateTime);
        jsonResponse.put("message",message);
        jsonResponse.put("path",path);

        response.getWriter().write(new ObjectMapper().writeValueAsString(jsonResponse));
    }
}
