package com.example.security.controller;

import com.example.security.services.TimestampService;
import org.bouncycastle.tsp.TimeStampResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/timestamp")
public class TimestampController {

    private final TimestampService timestampService;

    public TimestampController(TimestampService timestampService) {
        this.timestampService = timestampService;
    }

    @PostMapping
    public ResponseEntity<String> getTimestamp(@RequestBody byte[] data) {
        try {
            TimeStampResponse response = timestampService.timestamp(data);
            return ResponseEntity.ok("Horodatage reçu: " + response.getTimeStampToken().getTimeStampInfo().getGenTime());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur: " + e.getMessage());
        }
    }
}
