package com.example.security.services;

import com.example.security.entities.User;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class CertificateService {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyVaultService keyVaultService;

    public byte[] generateSelfSignedCertificate(User user, String password) throws Exception {
        // 🔐 Déchiffrer la clé privée avec le mot de passe utilisateur
        String decryptedPrivateKey = keyVaultService.decryptPrivateKey(user.getPrivateKey(), password);
        PrivateKey privateKey = loadPrivateKey(decryptedPrivateKey);
        PublicKey publicKey = loadPublicKey(user.getPublicKey());

        X500Name subject = new X500Name("CN=" + user.getUsername() + ", E=" + user.getEmail());
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 an

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(now), startDate, endDate, subject, publicKeyInfo);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certBldr.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        return exportToPEM(certificate);
    }

    private byte[] exportToPEM(X509Certificate certificate) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(baos))) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
        return baos.toByteArray();
    }

    private PrivateKey loadPrivateKey(String privateKeyBase64) throws Exception {
        if (!isValidBase64(privateKeyBase64)) {
            throw new IllegalArgumentException("Clé privée invalide : Base64 incorrect");
        }
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey(String publicKeyBase64) throws Exception {
        if (!isValidBase64(publicKeyBase64)) {
            throw new IllegalArgumentException("Clé publique invalide : Base64 incorrect");
        }
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Exporte un certificat au format PKCS#12 (p12/pfx) contenant la clé privée et le certificat
     */
    public byte[] exportToPKCS12(User user, String password) throws Exception {
        // Charger les clés depuis Base64 vers objets Java
        PrivateKey privateKey = loadPrivateKey(user.getPrivateKey(), password); // Déchiffrement avec mot de passe utilisateur
        X509Certificate certificate = generateCertificateObject(user, password);

        // Créer un KeyStore PKCS12
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);

        // Ajouter la clé privée + certificat dans le keystore
        keyStore.setKeyEntry(
                user.getUsername(),
                privateKey,
                password.toCharArray(),
                new java.security.cert.Certificate[]{certificate}
        );

        // Écrire le keystore dans un flux en mémoire
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());

        return baos.toByteArray();
    }

    /**
     * Génère un objet X509Certificate à partir des données utilisateur
     */
    private X509Certificate generateCertificateObject(User user, String password) throws Exception {
        // Déchiffrer la clé privée avec le mot de passe utilisateur
        String decryptedPrivateKey = keyVaultService.decryptPrivateKey(user.getPrivateKey(), password);
        PrivateKey privateKey = loadPrivateKey(decryptedPrivateKey);
        PublicKey publicKey = loadPublicKey(user.getPublicKey());

        X500Name subject = new X500Name("CN=" + user.getUsername() + ", E=" + user.getEmail());
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 an

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now),
                startDate,
                endDate,
                subject,
                publicKeyInfo
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateHolder);
    }

    /**
     * Charge une clé privée déchiffrée à partir de sa version Base64 et du mot de passe
     */
    private PrivateKey loadPrivateKey(String privateKeyBase64, String password) throws Exception {
        String decryptedPrivateKey = keyVaultService.decryptPrivateKey(privateKeyBase64, password);
        byte[] decodedKey = Base64.getDecoder().decode(decryptedPrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private boolean isValidBase64(String base64) {
        try {
            Base64.getDecoder().decode(base64);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}