package com.example.jwt.controller;

import com.example.jwt.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    @Autowired
    private AuthService authService;

    // 1. POST /generate - Accepts username & role, returns generated JWT token
    @PostMapping("/generate")
    public Map<String, String> generateToken(@RequestBody Map<String, String> user) {
        String token = authService.generateToken(user);

        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        return response;
    }

    // 2. POST /verify - Accepts JWT token, returns decoded username & role
    @PostMapping("/verify")
    public Map<String, Object> verifyToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        return authService.verifyToken(token);
    }
}
