package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.AuthResponse;
import com.example.emailfirewall.dto.LoginRequest;
import com.example.emailfirewall.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {

        AuthResponse response =
                authService.authenticate(request.getEmail(), request.getPassword());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody LoginRequest request) {

        AuthResponse response =
                authService.register(request.getEmail(), request.getPassword());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}