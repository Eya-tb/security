package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import com.example.security.entities.User;
import com.example.security.repositories.SignatureRepository;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class SignatureService {
    private final SignatureRepository signatureRepository;

    public SignatureService(SignatureRepository signatureRepository) {
        this.signatureRepository = signatureRepository;
    }

    // 🔹 Générer une signature numérique
    public Signature signerDocument(Document document, User user, PrivateKey privateKey) throws Exception {
        byte[] documentHash = hashDocument(document.getContent()); // 1. Hasher le document
        byte[] signatureBytes = signHash(documentHash, privateKey); // 2. Signer le hash

        Signature signature = new Signature();
        signature.setSignedHash(signatureBytes);
        signature.setAlgorithm("SHA256withRSA");
        signature.setPublicKey(encodePublicKey(privateKey)); // Correct way to get PublicKey
        signature.setSignedAt(LocalDateTime.now());
        signature.setDocument(document);
        signature.setUser(user);

        return signatureRepository.save(signature); // 3. Stocker la signature
    }

    // 🔹 Vérifier une signature numérique
    public boolean verifierSignature(Document document, byte[] signedHash, PublicKey publicKey) throws Exception {
        byte[] documentHash = hashDocument(document.getContent()); // 1. Recalculer le hash
        return verifySignature(documentHash, signedHash, publicKey); // 2. Vérifier
    }

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

    // 🔹 Méthode pour vérifier une signature
    private boolean verifySignature(byte[] hash, byte[] signedHash, PublicKey publicKey) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(hash);
        return signature.verify(signedHash);
    }

    // 🔹 Encode the PublicKey as a Base64 string
    private String encodePublicKey(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(privateKey.getEncoded()));
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
