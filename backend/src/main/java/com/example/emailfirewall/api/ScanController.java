package com.example.emailfirewall.api;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ScanController {

    @PostMapping("/scan")
    public Map<String, Object> scan(@RequestBody Map<String, Object> body) {
        return Map.of(
                "status", "OK",
                "verdict", "CLEAN",
                "received", body
        );
    }
}