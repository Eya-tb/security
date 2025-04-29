package com.example.security.services;

import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class KeyMigrationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyMigrationService.class);

    private final UserRepository userRepository;
    private final KeyVaultService keyVaultService;

    /**
     * Migre la clé privée d'un utilisateur vers le nouveau format sécurisé
     * Cette méthode nécessite des droits d'administrateur
     *
     * @param userId ID de l'utilisateur à migrer
     * @param password Mot de passe pour chiffrer la nouvelle clé
     * @return true si la migration a réussi, false sinon
     */
    @Transactional
    @PreAuthorize("hasAuthority('ADMIN')")
    public boolean migrateUserKey(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Utilisateur introuvable avec ID: " + userId));

            logger.info("Démarrage de la migration des clés pour l'utilisateur {} (ID: {})", user.getUsername(), userId);

            // Vérifier si la clé est déjà au nouveau format
            if (isKeyEncrypted(user.getPrivateKey())) {
                logger.info("La clé de l'utilisateur est déjà migrée vers le nouveau format.");
                return true;
            }

            // Valider que la clé privée est au format attendu
            try {
                validatePrivateKey(user.getPrivateKey());
            } catch (Exception e) {
                logger.error("Format de clé privée invalide pour l'utilisateur {}", userId, e);
                return false;
            }

            // Migrer la clé vers le nouveau format chiffré
            String encryptedPrivateKey = keyVaultService.encryptPrivateKey(user.getPrivateKey(), password);
            user.setPrivateKey(encryptedPrivateKey);

            userRepository.save(user);
            logger.info("Migration des clés réussie pour l'utilisateur {}", userId);

            return true;
        } catch (Exception e) {
            logger.error("Erreur lors de la migration des clés pour l'utilisateur {}", userId, e);
            return false;
        }
    }

    /**
     * Vérifie si une clé est déjà dans le format chiffré
     */
    private boolean isKeyEncrypted(String privateKey) {
        try {
            // Essayer de décoder la clé en Base64
            byte[] decoded = Base64.getDecoder().decode(privateKey);

            // Si la clé est déjà chiffrée, elle ne sera pas un format PKCS8 valide
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
                kf.generatePrivate(keySpec);
                // Si on arrive ici, c'est que la clé est en format PKCS8 non chiffré
                return false;
            } catch (Exception e) {
                // Si on ne peut pas charger la clé comme PKCS8, elle est probablement déjà chiffrée
                return true;
            }
        } catch (Exception e) {
            // En cas d'erreur de décodage Base64, on suppose que c'est déjà chiffré
            return true;
        }
    }

    /**
     * Valide que la clé privée est au format attendu (PKCS8)
     */
    private void validatePrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        keyFactory.generatePrivate(keySpec);
    }

    /**
     * Migre toutes les clés utilisateurs du système qui ne sont pas encore migrées
     * Cette méthode est destinée à être utilisée lors de la mise à niveau du système
     *
     * @param adminPassword Mot de passe administrateur pour chiffrer les clés
     * @return le nombre d'utilisateurs migrés avec succès
     */
    @Transactional
    @PreAuthorize("hasAuthority('ADMIN')")
    public int migrateAllUserKeys(String adminPassword) {
        int migratedCount = 0;
        int failedCount = 0;

        logger.info("Démarrage de la migration de toutes les clés utilisateurs");

        for (User user : userRepository.findAll()) {
            try {
                if (!isKeyEncrypted(user.getPrivateKey())) {
                    String encryptedPrivateKey = keyVaultService.encryptPrivateKey(user.getPrivateKey(), adminPassword);
                    user.setPrivateKey(encryptedPrivateKey);
                    userRepository.save(user);
                    migratedCount++;
                    logger.info("Clé migrée avec succès pour l'utilisateur {} (ID: {})", user.getUsername(), user.getId());
                }
            } catch (Exception e) {
                failedCount++;
                logger.error("Échec de migration pour l'utilisateur {} (ID: {})", user.getUsername(), user.getId(), e);
            }
        }

        logger.info("Migration terminée. Utilisateurs migrés: {}, échecs: {}", migratedCount, failedCount);
        return migratedCount;
    }
}