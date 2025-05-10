package com.example.security.controller;

import com.example.security.services.KeyRecoveryService;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/recovery")
@RequiredArgsConstructor
@Validated
public class KeyRecoveryController {

    private final KeyRecoveryService keyRecoveryService;

    @PostMapping("/initiate")
    public ResponseEntity<?> initiateKeyRecovery(@RequestBody @Validated InitiateRecoveryRequest request) {
        try {
            keyRecoveryService.initiateKeyRecovery(request.getEmail());
            return ResponseEntity.ok(Map.of("message", "Si l'email existe, un code de récupération a été envoyé."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Une erreur est survenue lors de l'envoi du code de récupération"));
        }
    }

    @PostMapping("/validate-code")
    public ResponseEntity<?> validateRecoveryCode(@RequestBody @Validated ValidateCodeRequest request) {
        try {
            String token = keyRecoveryService.validateRecoveryCode(request.getEmail(), request.getCode());
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "message", "Code validé. Vous pouvez maintenant définir un nouveau mot de passe."
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/complete")
    public ResponseEntity<?> completeKeyRecovery(@RequestBody @Validated CompleteRecoveryRequest request) {
        try {
            keyRecoveryService.completeKeyRecovery(request.getEmail(), request.getToken(), request.getNewPassword());
            return ResponseEntity.ok(Map.of("message", "Récupération de clé réussie. Vous pouvez maintenant vous connecter avec votre nouveau mot de passe."));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Une erreur est survenue lors de la récupération de la clé"));
        }
    }

    // === Requête : démarrer la récupération ===
    @lombok.Data
    public static class InitiateRecoveryRequest {
        @NotBlank(message = "L'email est obligatoire")
        @Email(message = "Format d'email invalide")
        private String email;
    }

    // === Requête : valider le code reçu par email ===
    @lombok.Data
    public static class ValidateCodeRequest {
        @NotBlank(message = "L'email est obligatoire")
        @Email(message = "Format d'email invalide")
        private String email;

        @NotBlank(message = "Le code est obligatoire")
        private String code;
    }

    // === Requête : finaliser la récupération avec un nouveau mot de passe ===
    @lombok.Data
    public static class CompleteRecoveryRequest {
        @NotBlank(message = "L'email est obligatoire")
        @Email(message = "Format d'email invalide")
        private String email;

        @NotBlank(message = "Le token est obligatoire")
        private String token;

        @NotBlank(message = "Le nouveau mot de passe est obligatoire")
        private String newPassword;
    }
}
