package com.example.security.services;

import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class KeyRecoveryService {

    private static final Logger logger = LoggerFactory.getLogger(KeyRecoveryService.class);

    private static final int RECOVERY_CODE_LENGTH = 6;
    private static final int RECOVERY_CODE_EXPIRATION_MINUTES = 15;

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final KeyVaultService keyVaultService;
    private final PasswordValidationService passwordValidationService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final VaultTemplate vaultTemplate;

    private final Map<String, RecoveryCodeInfo> recoveryCodesMap = new ConcurrentHashMap<>();

    @Value("${vault.master-key-path:secret/master-key}")
    private String vaultMasterKeyPath;

    @Value("${vault.master-key-field:master-backup-key}")
    private String vaultMasterKeyField;

    public KeyRecoveryService(VaultTemplate vaultTemplate,
                              UserRepository userRepository,
                              EmailService emailService,
                              KeyVaultService keyVaultService,
                              PasswordValidationService passwordValidationService,
                              BCryptPasswordEncoder passwordEncoder) {
        this.vaultTemplate = vaultTemplate;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.keyVaultService = keyVaultService;
        this.passwordValidationService = passwordValidationService;
        this.passwordEncoder = passwordEncoder;
    }

    public void initiateKeyRecovery(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            logger.info("Tentative de récupération pour un email inconnu: {}", email);
            return;
        }

        String recoveryCode = generateRandomCode(RECOVERY_CODE_LENGTH);

        recoveryCodesMap.put(email, new RecoveryCodeInfo(
                passwordEncoder.encode(recoveryCode),
                LocalDateTime.now().plusMinutes(RECOVERY_CODE_EXPIRATION_MINUTES)
        ));

        String emailContent =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2 style='color: #3a3a3a;'>Récupération de vos clés</h2>" +
                        "<p>Bonjour " + user.getUsername() + ",</p>" +
                        "<p>Voici votre code de vérification :</p>" +
                        "<p style='font-size: 24px; font-weight: bold; text-align: center; padding: 10px; background-color: #f5f5f5; border-radius: 4px;'>" + recoveryCode + "</p>" +
                        "<p>Ce code est valable pendant " + RECOVERY_CODE_EXPIRATION_MINUTES + " minutes.</p>" +
                        "<p>Si vous n'avez pas demandé cette récupération, ignorez cet email.</p>" +
                        "<p>Cordialement,<br>L'équipe de sécurité</p>" +
                        "</div>";

        emailService.sendEmail(email, "Code de récupération de vos clés", emailContent);
        logger.info("Code de récupération envoyé à: {}", email);
    }

    public String validateRecoveryCode(String email, String recoveryCode) {
        RecoveryCodeInfo codeInfo = recoveryCodesMap.get(email);
        if (codeInfo == null) {
            throw new RuntimeException("Aucun code de récupération trouvé pour cet email");
        }

        if (LocalDateTime.now().isAfter(codeInfo.expiryDate)) {
            recoveryCodesMap.remove(email);
            throw new RuntimeException("Le code de récupération a expiré");
        }

        if (!passwordEncoder.matches(recoveryCode, codeInfo.hashedCode)) {
            throw new RuntimeException("Code de récupération invalide");
        }

        String token = UUID.randomUUID().toString();
        codeInfo.validationToken = token;
        codeInfo.tokenExpiry = LocalDateTime.now().plusMinutes(10);
        return token;
    }

    public void completeKeyRecovery(String email, String token, String newPassword) throws Exception {
        RecoveryCodeInfo codeInfo = recoveryCodesMap.get(email);
        if (codeInfo == null || !token.equals(codeInfo.validationToken)
                || LocalDateTime.now().isAfter(codeInfo.tokenExpiry)) {
            throw new RuntimeException("Token invalide ou expiré");
        }

        List<String> passwordErrors = passwordValidationService.validatePassword(newPassword);
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Mot de passe invalide: " + String.join(", ", passwordErrors));
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new RuntimeException("Utilisateur introuvable");
        }

        try {
            String masterKey = getBackupKeyFromVault();
            if (masterKey == null || masterKey.isEmpty()) {
                throw new RuntimeException("Clé de sauvegarde introuvable dans Vault");
            }

            String decryptedKey = keyVaultService.decryptPrivateKey(
                    user.getBackupPrivateKey(),
                    masterKey
            );

            if (!isValidPrivateKey(decryptedKey)) {
                throw new RuntimeException("Format de clé invalide après déchiffrement");
            }

            String newEncryptedKey = keyVaultService.encryptPrivateKey(
                    decryptedKey,
                    newPassword
            );

            // === VERSION AMÉLIORÉE AVEC LOGS DÉTAILLÉS ===
            String hashedPassword = passwordEncoder.encode(newPassword);
            logger.debug("Mise à jour mot de passe : hashedPassword={}", hashedPassword);
            user.setPassword(hashedPassword);
            user.setPrivateKey(newEncryptedKey);
            logger.debug("Sauvegarde utilisateur ID={}, Email={}", user.getId(), user.getEmail());
            User savedUser = userRepository.save(user);
            logger.debug("Utilisateur sauvegardé avec hash de password={}", savedUser.getPassword());

            recoveryCodesMap.remove(email);
            sendRecoverySuccessEmail(user);

        } catch (Exception e) {
            logger.error("Échec de la récupération pour l'utilisateur {}", email, e);
            throw new Exception("Échec du processus de récupération: " + e.getMessage());
        }
    }

    private boolean isValidPrivateKey(String key) {
        try {
            KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key))
            );
            return true;
        } catch (Exception e) {
            logger.warn("Clé privée invalide détectée", e);
            return false;
        }
    }

    private void sendRecoverySuccessEmail(User user) {
        String emailContent =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2 style='color: #3a3a3a;'>Récupération de clés réussie</h2>" +
                        "<p>Bonjour " + user.getUsername() + ",</p>" +
                        "<p>La récupération de vos clés a été effectuée avec succès.</p>" +
                        "<p>Si vous n'êtes pas à l'origine de cette action, contactez immédiatement le support.</p>" +
                        "<p>Cordialement,<br>L'équipe de sécurité</p>" +
                        "</div>";

        emailService.sendEmail(user.getEmail(), "Récupération de clés réussie", emailContent);
    }

    private String getBackupKeyFromVault() {
        try {
            String correctPath = "secret/data/master-key";
            logger.debug("Tentative de lecture depuis Vault avec le chemin: {}", correctPath);

            VaultResponse response = vaultTemplate.read(correctPath);

            if (response == null || response.getData() == null) {
                logger.error("Réponse Vault vide pour le chemin: {}", correctPath);
                return null;
            }

            logger.debug("Réponse Vault reçue: {}", response.getData());

            Map<String, Object> secretData = (Map<String, Object>) response.getData().get("data");
            if (secretData == null) {
                logger.error("Champ 'data' manquant dans la réponse Vault. Structure complète: {}", response.getData());
                return null;
            }

            String masterKey = (String) secretData.get(vaultMasterKeyField);
            if (masterKey == null) {
                logger.error("Clé '{}' introuvable. Clés disponibles: {}",
                        vaultMasterKeyField, secretData.keySet());
                return null;
            }

            logger.debug("Clé maîtresse récupérée avec succès");
            return masterKey.trim();
        } catch (Exception e) {
            logger.error("Erreur critique lors de la lecture de Vault", e);
            return null;
        }
    }

    private String generateRandomCode(int length) {
        StringBuilder code = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < length; i++) {
            code.append(rand.nextInt(10));
        }
        return code.toString();
    }

    private static class RecoveryCodeInfo {
        private final String hashedCode;
        private final LocalDateTime expiryDate;
        private String validationToken;
        private LocalDateTime tokenExpiry;

        public RecoveryCodeInfo(String hashedCode, LocalDateTime expiryDate) {
            this.hashedCode = hashedCode;
            this.expiryDate = expiryDate;
        }
    }
}
