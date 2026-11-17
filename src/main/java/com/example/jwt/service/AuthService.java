package com.example.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    // Secret key for HS256 (must be at least 256 bits / 32 bytes long)
    private static final String SECRET_KEY = "mySecretKeyForJwtSigningMustBeAtLeast256BitsLong!";
    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

    // 1. Generate JWT Token valid for 1 hour
    public String generateToken(Map<String, String> user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.get("username"));
        claims.put("role", user.get("role"));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour expiration
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // 2. Verify and decode JWT Token
    public Map<String, Object> verifyToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Map<String, Object> userData = new HashMap<>();
        userData.put("username", claims.get("username"));
        userData.put("role", claims.get("role"));
        return userData;
    }
}
