package com.example.security.controller;

import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import com.example.security.security.JwtTokenProvider;
import com.example.security.security.UserPrincipal;
import com.example.security.services.LoginAttemptService;
import com.example.security.services.TokenBlacklistService;
import com.example.security.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.example.security.services.TokenBlacklistService;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.AuthenticationException;
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final LoginAttemptService loginAttemptService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Vérifier si l'utilisateur est bloqué
            if (loginAttemptService.isBlocked(loginRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(Map.of(
                                "message", "Compte temporairement bloqué suite à de multiples échecs d'authentification",
                                "blockedUntil", loginAttemptService.getBlockedUntil(loginRequest.getEmail())
                        ));
            }

            // Tenter l'authentification
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            // Récupérer les détails de l'utilisateur
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            User user = userService.getUserById(userPrincipal.getId());

            // Authentification réussie, réinitialiser le compteur de tentatives
            loginAttemptService.loginSucceeded(loginRequest.getEmail());

            // Si l'utilisateur a activé l'authentification à deux facteurs, retourner une réponse spéciale
            if (user.isMfaEnabled()) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Veuillez saisir votre code d'authentification à deux facteurs",
                        "requireMfa", true,
                        "userId", user.getId()
                ));
            }

            // Si l'utilisateur n'a pas activé l'authentification à deux facteurs, générer les jetons et retourner la réponse complète
            String jwt = tokenProvider.generateToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(authentication);

            // Enregistrer le refresh token
            tokenBlacklistService.saveRefreshToken(userPrincipal.getUsername(), refreshToken);

            return ResponseEntity.ok(Map.of(
                    "token", jwt,
                    "refreshToken", refreshToken,
                    "requireMfa", false,
                    "user", Map.of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "role", user.getRole(),
                            "mfaEnabled", user.isMfaEnabled()
                    )
            ));
        } catch (BadCredentialsException e) {
            // Enregistrer l'échec d'authentification
            loginAttemptService.loginFailed(loginRequest.getEmail());

            // Si l'utilisateur est bloqué après cet échec, renvoyer un message spécifique
            if (loginAttemptService.isBlocked(loginRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(Map.of(
                                "message", "Compte temporairement bloqué suite à de multiples échecs d'authentification",
                                "blockedUntil", loginAttemptService.getBlockedUntil(loginRequest.getEmail())
                        ));
            }

            // Sinon, renvoyer le message d'erreur standard
            int attemptsLeft = 5 - loginAttemptService.getFailedAttempts(loginRequest.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "message", "Email ou mot de passe incorrect",
                            "attemptsLeft", Math.max(0, attemptsLeft)
                    ));
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(@RequestParam Long userId) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            // Masquer les données sensibles
            User userResponse = new User();
            userResponse.setId(user.getId());
            userResponse.setUsername(user.getUsername());
            userResponse.setEmail(user.getEmail());
            userResponse.setRole(user.getRole());
            userResponse.setPassword(null);
            userResponse.setPrivateKey(null);
            userResponse.setPublicKey(user.getPublicKey());

            return ResponseEntity.ok(Map.of("user", userResponse));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erreur lors de la récupération du profil"));
        }
    }


    static class LoginRequest {
        private String email;
        private String password;
        private String otpCode; // Nouveau champ pour le code OTP
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }




        public String getOtpCode() {
            return otpCode;
        }

        public void setOtpCode(String otpCode) {
            this.otpCode = otpCode;
        }




    }


    // Ajouter à AuthController.java
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            // Valider le refresh token
            if (!tokenBlacklistService.validateRefreshToken(refreshTokenRequest.getRefreshToken())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Refresh token invalide ou expiré"));
            }

            // Générer un nouveau token d'accès
            String newAccessToken = tokenProvider.generateTokenFromRefreshToken(
                    refreshTokenRequest.getRefreshToken());

            // Optionnel: révoquer l'ancien refresh token et en créer un nouveau
            tokenBlacklistService.deleteRefreshToken(refreshTokenRequest.getRefreshToken());

            return ResponseEntity.ok(Map.of(
                    "token", newAccessToken,
                    "message", "Token rafraîchi avec succès"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Échec du rafraîchissement: " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);
            tokenBlacklistService.blacklistToken(jwt);
            return ResponseEntity.ok(Map.of("message", "Déconnexion réussie"));
        }
        return ResponseEntity.badRequest().body(Map.of("message", "Token non fourni"));
    }

    // DTO pour le refresh token
    static class RefreshTokenRequest {
        private String refreshToken;

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }

}