package com.example.security.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Service
@Component
public class KeyVaultService {
    private static final Logger logger = LoggerFactory.getLogger(KeyVaultService.class);

    /**
     * Chiffre la clé privée avec un mot de passe personnel de l'utilisateur
     */
    public String encryptPrivateKey(String privateKey, String userPassword) throws Exception {
        SecretKey derivedKey = deriveKeyFromPassword(userPassword);
        byte[] encryptedKey = EncryptionService.encrypt(
                privateKey.getBytes(StandardCharsets.UTF_8),
                derivedKey
        );
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    /**
     * Déchiffre la clé privée avec le mot de passe personnel de l'utilisateur
     */
    public String decryptPrivateKey(String encryptedPrivateKey, String userPassword) throws Exception {
        try {
            logger.debug("Tentative de déchiffrement de clé privée");

            // Utiliser un mot de passe par défaut si non fourni
            if (userPassword == null || userPassword.isEmpty()) {
                throw new IllegalArgumentException("Mot de passe non fourni");
            }

            // S'assurer que la clé n'est pas null
            if (encryptedPrivateKey == null) {
                throw new IllegalArgumentException("Clé privée chiffrée non fournie");
            }

            SecretKey derivedKey = deriveKeyFromPassword(userPassword);
            byte[] privateKeyBytes;

            try {
                privateKeyBytes = EncryptionService.decrypt(
                        Base64.getDecoder().decode(encryptedPrivateKey),
                        derivedKey
                );
            } catch (Exception e) {
                logger.error("Erreur de déchiffrement: {}", e.getMessage());
                throw new SecurityException("Mot de passe incorrect pour le déchiffrement de la clé privée");
            }

            return new String(privateKeyBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Échec du déchiffrement de la clé privée", e);
            throw new SecurityException("Échec du déchiffrement de la clé privée: " + e.getMessage());
        }
    }

    /**
     * Dérive une clé de chiffrement à partir du mot de passe utilisateur
     */
    private SecretKey deriveKeyFromPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, "AES");
    }
}