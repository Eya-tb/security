package com.example.security.services;


import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import com.example.security.repositories.SignatureRepository;
import com.example.security.repositories.UserRepository;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class SignatureService {
    private final SignatureRepository signatureRepository;
    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;

    public SignatureService(SignatureRepository signatureRepository, DocumentRepository documentRepository, UserRepository userRepository) {
        this.signatureRepository = signatureRepository;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
    }

    // 🔹 Générer une signature numérique
    public Signature signerDocument(Long documentId, Long userId, byte[] privateKeyBase64) throws Exception {
        // Vérifier si le document existe
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable avec ID : " + documentId));

        // Vérifier si l'utilisateur existe
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable avec ID : " + userId));

        // Charger la clé privée
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = loadPrivateKey(privateKeyBytes);

        // Hasher le document
        byte[] documentHash = hashDocument(document.getContent());

        // Signer le hash
        byte[] signatureBytes = signHash(documentHash, privateKey);

        // Stocker la signature
        Signature signature = new Signature();
        signature.setSignedHash(signatureBytes);
        signature.setAlgorithm("SHA256withRSA");
        signature.setSignedAt(LocalDateTime.now());
        signature.setDocument(document);
        signature.setUser(user);

        return signatureRepository.save(signature);
    }



    // 🔹 Charger une clé privée depuis un tableau de bytes
    private PrivateKey loadPrivateKey(byte[] privateKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }


    // 🔹 Vérifier une signature numérique
    public boolean verifierSignature(Long documentId, String signedHashBase64, String publicKeyBase64) throws Exception {
        // Vérifier que le document existe
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable avec ID : " + documentId));

        // Charger la clé publique
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = loadPublicKey(publicKeyBytes);

        // Hasher le document
        byte[] documentHash = hashDocument(document.getContent());

        // Décoder le hash signé
        byte[] signedHash = Base64.getDecoder().decode(signedHashBase64);

        // Vérifier la signature
        return verifySignature(documentHash, signedHash, publicKey);
    }


    // 🔹 Méthodes utilitaires (inchangées)

    // 🔹 Méthode pour hasher un document (SHA-256)
    private byte[] hashDocument(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(content);
    }

    // 🔹 Méthode pour signer un hash avec une clé privée
    private byte[] signHash(byte[] hash, PrivateKey privateKey) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        return signature.sign();
    }

    // 🔹 Charger une clé publique depuis un tableau de bytes
    private PublicKey loadPublicKey(byte[] publicKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    // 🔹 Méthode pour vérifier une signature
    private boolean verifySignature(byte[] hash, byte[] signedHash, PublicKey publicKey) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(hash);
        return signature.verify(signedHash);
    }

}
