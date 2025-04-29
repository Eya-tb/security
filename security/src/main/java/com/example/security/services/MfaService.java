package com.example.security.services;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
public class MfaService {
    private static final Logger logger = LoggerFactory.getLogger(MfaService.class);
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(new DefaultCodeGenerator(), timeProvider);
    private final String issuer = "Secure Document Signing Application";

    /**
     * Génère un secret pour l'authentification TOTP
     * @return Le secret généré
     */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /**
     * Génère l'URI du QR code pour configurer l'authentification TOTP
     * @param secret Le secret associé à l'utilisateur
     * @param email L'identifiant de l'utilisateur
     * @return L'URI du QR code au format data URL
     */
    public String getQrCodeImageUri(String secret, String email) {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        try {
            QrGenerator qrGenerator = new ZxingPngQrGenerator();
            byte[] imageData = qrGenerator.generate(data);
            return getDataUriForImage(imageData, qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            logger.error("Erreur lors de la génération du QR code", e);
            throw new RuntimeException("Échec de génération du QR code", e);
        }
    }

    /**
     * Vérifie si un code TOTP est valide pour un secret donné
     * @param secret Le secret TOTP
     * @param code Le code fourni par l'utilisateur
     * @return true si le code est valide, false sinon
     */
    public boolean verifyCode(String secret, String code) {
        String cleanedCode = code.replaceAll("\\s+", "");
        logger.debug("🔐 Tentative de vérif - secret: [{}], code reçu: [{}]", secret, cleanedCode);
        boolean result = codeVerifier.isValidCode(secret, cleanedCode);
        logger.debug("🔐 Résultat vérification MFA: {}", result);
        return result;
    }
}
