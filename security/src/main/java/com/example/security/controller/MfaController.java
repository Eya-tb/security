package com.example.security.controller;

import com.example.security.entities.User;
import com.example.security.security.JwtTokenProvider;
import com.example.security.security.UserPrincipal;
import com.example.security.services.TokenBlacklistService;
import com.example.security.services.UserService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final UserService userService;
    private final JwtTokenProvider tokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    @PostMapping("/enable")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> enableMfa(@RequestParam Long userId) {
        userService.enableMfa(userId);
        return ResponseEntity.ok(Map.of(
                "message", "2FA activée avec succès",
                "enabled", true
        ));
    }

    @PostMapping("/disable")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> disableMfa(@RequestParam Long userId) {
        userService.disableMfa(userId);
        return ResponseEntity.ok(Map.of(
                "message", "2FA désactivée avec succès",
                "enabled", false
        ));
    }

    @GetMapping("/setup")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> setupMfa(@RequestParam Long userId) {
        String qrCodeUri = userService.generateQrCodeForUser(userId);
        return ResponseEntity.ok(Map.of(
                "qrCodeUri", qrCodeUri
        ));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@RequestParam(required = false) Long userId,
                                        @RequestParam(required = false) String code,
                                        @RequestBody(required = false) MfaValidationRequest request) {
        // Utiliser les valeurs des paramètres ou du corps selon ce qui est disponible
        Long finalUserId = userId;
        String finalCode = code;

        // Si les paramètres d'URL sont null, essayer d'utiliser ceux du corps
        if (request != null) {
            if (finalUserId == null) finalUserId = request.getUserId();
            if (finalCode == null) finalCode = request.getCode();
        }

        // Vérifier que les paramètres nécessaires sont présents
        if (finalUserId == null || finalCode == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "L'ID utilisateur et le code sont requis"
            ));
        }

        // Nettoyer le code (supprimer les espaces et autres caractères non désirés)
        String cleanedCode = finalCode.trim().replaceAll("\\s+", "");
        boolean isValid = userService.verifyCode(finalUserId, cleanedCode);

        return ResponseEntity.ok(Map.of(
                "valid", isValid,
                "message", isValid ? "Code valide" : "Code invalide"
        ));
    }

    @GetMapping("/status")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMfaStatus(@RequestParam Long userId) {
        boolean enabled = userService.getUserById(userId).isMfaEnabled();
        return ResponseEntity.ok(Map.of(
                "enabled", enabled
        ));
    }

    @PostMapping("/validate-mfa")
    public ResponseEntity<?> validateMfa(@RequestBody Map<String, Object> requestBody) {
        try {
            Long userId = Long.valueOf(requestBody.get("userId").toString());
            String code = requestBody.get("code").toString();

            boolean isValid = userService.verifyCode(userId, code);

            if (!isValid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("valid", false, "message", "Code d'authentification invalide"));
            }

            // Si le code est valide, récupérer l'utilisateur
            User user = userService.getUserById(userId);

            // Créer une authentification
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    UserPrincipal.create(user), null, UserPrincipal.create(user).getAuthorities());

            // Générer les tokens
            String jwt = tokenProvider.generateToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(authentication);

            // Enregistrer le refresh token
            tokenBlacklistService.saveRefreshToken(user.getUsername(), refreshToken);

            // Retourner la réponse complète
            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "token", jwt,
                    "refreshToken", refreshToken,
                    "user", Map.of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "role", user.getRole(),
                            "mfaEnabled", user.isMfaEnabled()
                    )
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("valid", false, "message", "Erreur lors de la validation du code MFA: " + e.getMessage()));
        }
    }

    @PostMapping("/verify-and-enable")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyAndEnableMfa(@RequestBody MfaValidationRequest request) {
        try {
            // Vérifier le code avec le secret temporaire
            boolean isValid = userService.verifyCode(request.getUserId(), request.getCode());

            if (!isValid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of(
                                "success", false,
                                "message", "Code de vérification invalide. L'activation a échoué."
                        ));
            }

            // Promouvoir le secret temporaire en secret principal
            userService.confirmMfaSetup(request.getUserId());

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Authentification à deux facteurs activée avec succès"
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Erreur lors de l'activation de la 2FA: " + e.getMessage()
                    ));
        }
    }

    // Classe pour la requête de validation MFA
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    static class MfaValidationRequest {
        private Long userId;
        private String code;
    }
}