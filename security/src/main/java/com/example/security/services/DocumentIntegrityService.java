package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.repositories.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DocumentIntegrityService {

    private final DocumentRepository documentRepository;
    private final SignatureService signatureService;

    /**
     * Vérifie l'intégrité complète d'un document
     */
    public Map<String, Object> verifyDocumentIntegrity(Long documentId) {
        Map<String, Object> result = new HashMap<>();
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable"));

        try {
            // 1. Vérifier le hash du document
            boolean hashValid = verifyDocumentHash(document);
            result.put("hashValid", hashValid);

            // 2. Vérifier la signature (si présente)
            boolean signatureValid = false;
            boolean hasSignature = document.getSignature() != null;
            result.put("hasSignature", hasSignature);

            if (hasSignature) {
                signatureValid = signatureService.verifySignature(documentId);
                result.put("signatureValid", signatureValid);
                result.put("signedAt", document.getSignature().getSignedAt());
                result.put("signedBy", document.getSignature().getSigner().getUsername());
            }

            // 3. Verdict global
            boolean overallValid = hashValid && (!hasSignature || signatureValid);
            result.put("overallValid", overallValid);

            return result;
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("overallValid", false);
            return result;
        }
    }

    /**
     * Vérifie si le hash stocké correspond au contenu actuel
     */
    private boolean verifyDocumentHash(Document document) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computedHash = digest.digest(document.getContent());
        String computedHashHex = bytesToHex(computedHash);

        return computedHashHex.equals(document.getFileHash());
    }

    /**
     * Vérifie si un contenu a été modifié par rapport à un document existant
     */
    public boolean isDocumentModified(Long documentId, byte[] newContent) throws NoSuchAlgorithmException {
        Document originalDoc = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable"));

        // 1. Comparer directement les bytes
        if (Arrays.equals(originalDoc.getContent(), newContent)) {
            return false; // Identiques
        }

        // 2. Calculer et comparer les hashes
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] newHash = digest.digest(newContent);
        String newHashHex = bytesToHex(newHash);

        return !newHashHex.equals(originalDoc.getFileHash());
    }

    /**
     * Détecte des modifications partielles dans un document
     * (pourcentage de similarité)
     */
    public double calculateDocumentSimilarity(Long documentId, byte[] newContent) {
        Document originalDoc = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable"));

        // Calcul simple du pourcentage de similarité basé sur les octets identiques
        int matchingBytes = 0;
        int minLength = Math.min(originalDoc.getContent().length, newContent.length);

        for (int i = 0; i < minLength; i++) {
            if (originalDoc.getContent()[i] == newContent[i]) {
                matchingBytes++;
            }
        }

        return (double) matchingBytes / Math.max(originalDoc.getContent().length, newContent.length);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}