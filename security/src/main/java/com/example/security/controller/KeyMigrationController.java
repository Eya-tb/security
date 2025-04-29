package com.example.security.controller;

import com.example.security.services.ApiResponse;
import com.example.security.services.KeyMigrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/migration")
@RequiredArgsConstructor
public class KeyMigrationController {

    private final KeyMigrationService keyMigrationService;

    @PostMapping("/migrate-all")
    @PreAuthorize("hasAuthority('ADMIN')")

    public ResponseEntity<ApiResponse<Integer>> migrateAllKeys(
            @RequestParam String temporaryPassword) {

        int migratedCount = keyMigrationService.migrateAllUserKeys(temporaryPassword);
        return ResponseEntity.ok(ApiResponse.success(
                "Migration terminée", migratedCount));
    }

    @PostMapping("/migrate-user/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")

    public ResponseEntity<ApiResponse<Boolean>> migrateUserKey(
            @PathVariable Long userId,
            @RequestParam String password) {

        boolean success = keyMigrationService.migrateUserKey(userId, password);
        return ResponseEntity.ok(ApiResponse.success(
                success ? "Migration réussie" : "Pas de migration nécessaire", success));
    }
}