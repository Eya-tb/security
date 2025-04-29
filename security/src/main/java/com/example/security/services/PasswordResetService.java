package com.example.security.services;

import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final PasswordValidationService passwordValidationService;
    @Value("${app.password-reset.expiration-minutes}")
    private int expirationMinutes;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    // Stockage des tokens de réinitialisation avec leur date d'expiration
    private final Map<String, ResetTokenInfo> resetTokens = new ConcurrentHashMap<>();

    /**
     * Génère un token de réinitialisation et envoie un email
     */
    public void generateResetToken(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new RuntimeException("Aucun compte associé à cet email");
        }

        // Génération d'un token unique
        String token = UUID.randomUUID().toString();

        // Stockage du token avec sa date d'expiration
        resetTokens.put(token, new ResetTokenInfo(user.getId(), LocalDateTime.now().plusMinutes(expirationMinutes)));

        // Envoi de l'email contenant le lien de réinitialisation
        // Dans PasswordResetService.java
        String resetLink = frontendUrl + "/auth/reset-password?token=" + token;

        String emailContent =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2 style='color: #3a3a3a;'>Réinitialisation de mot de passe</h2>" +
                        "<p>Bonjour " + user.getUsername() + ",</p>" +
                        "<p>Vous avez demandé la réinitialisation de votre mot de passe. Veuillez cliquer sur le lien ci-dessous pour définir un nouveau mot de passe :</p>" +
                        "<p><a href='" + resetLink + "' style='background-color: #4285f4; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;'>Réinitialiser mon mot de passe</a></p>" +
                        "<p>Ce lien expirera dans " + expirationMinutes + " minutes.</p>" +
                        "<p>Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer cet email.</p>" +
                        "<p>Cordialement,<br>L'équipe de sécurité</p>" +
                        "</div>";

        emailService.sendEmail(user.getEmail(), "Réinitialisation de votre mot de passe", emailContent);
    }

    /**
     * Valide si un token est valide et non expiré
     */
    public boolean validateToken(String token) {
        ResetTokenInfo info = resetTokens.get(token);
        if (info == null) {
            return false;
        }

        // Vérifier si le token n'est pas expiré
        if (LocalDateTime.now().isAfter(info.expiryDate)) {
            // Supprimer le token expiré
            resetTokens.remove(token);
            return false;
        }

        return true;
    }

    /**
     * Réinitialise le mot de passe à partir d'un token valide
     */
    public void resetPassword(String token, String newPassword) {
        if (!validateToken(token)) {
            throw new RuntimeException("Token invalide ou expiré");
        }

        // Valider la complexité du mot de passe

        List<String> passwordErrors = passwordValidationService.validatePassword(newPassword);
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Mot de passe invalide : " + String.join(", ", passwordErrors));
        }

        ResetTokenInfo info = resetTokens.get(token);

        // Récupérer l'utilisateur concerné
        User user = userRepository.findById(info.userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

        // Mettre à jour le mot de passe
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Supprimer le token après utilisation
        resetTokens.remove(token);

        // Envoyer un email de confirmation
        String emailContent =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2 style='color: #3a3a3a;'>Mot de passe réinitialisé avec succès</h2>" +
                        "<p>Bonjour " + user.getUsername() + ",</p>" +
                        "<p>Votre mot de passe a été réinitialisé avec succès.</p>" +
                        "<p>Si vous n'êtes pas à l'origine de cette action, veuillez contacter immédiatement notre support.</p>" +
                        "<p>Cordialement,<br>L'équipe de sécurité</p>" +
                        "</div>";

        emailService.sendEmail(user.getEmail(), "Confirmation de réinitialisation de mot de passe", emailContent);
    }

    /**
     * Classe interne pour stocker les informations du token
     */
    private static class ResetTokenInfo {
        private final Long userId;
        private final LocalDateTime expiryDate;

        public ResetTokenInfo(Long userId, LocalDateTime expiryDate) {
            this.userId = userId;
            this.expiryDate = expiryDate;
        }
    }

    /**
     * Obtient la date d'expiration d'un token
     */
    public LocalDateTime getTokenExpiryDate(String token) {
        ResetTokenInfo info = resetTokens.get(token);
        return info != null ? info.expiryDate : null;
    }
}