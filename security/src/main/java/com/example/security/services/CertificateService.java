package com.example.security.services;

import com.example.security.entities.User;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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

    /**
     * Génère un certificat X.509 auto-signé pour l'utilisateur
     */
    public byte[] generateSelfSignedCertificate(User user) throws Exception {
        // Convertir les clés stockées en Base64 en objets Java
        PrivateKey privateKey = loadPrivateKey(user.getPrivateKey());
        PublicKey publicKey = loadPublicKey(user.getPublicKey());

        // Informations sur le sujet du certificat
        X500Name subject = new X500Name("CN=" + user.getUsername() + ", E=" + user.getEmail());

        // Période de validité du certificat
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // Valide 1 an

        // Création du builder de certificat
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                subject, // Émetteur (auto-signé, donc identique au sujet)
                BigInteger.valueOf(now), // Numéro de série unique
                startDate,
                endDate,
                subject, // Sujet
                publicKeyInfo // Clé publique
        );

        // Signer le certificat avec la clé privée
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        // Générer le certificat
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateHolder);

        return exportToPEM(certificate);
    }

    /**
     * Exporte un certificat au format PEM (Base64 avec en-têtes)
     */
    private byte[] exportToPEM(X509Certificate certificate) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(baos))) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
        return baos.toByteArray();
    }

    /**
     * Exporte un certificat au format PKCS#12 (p12/pfx) contenant la clé privée et le certificat
     */
    public byte[] exportToPKCS12(User user, String password) throws Exception {
        // Convertir les clés en objets Java
        PrivateKey privateKey = loadPrivateKey(user.getPrivateKey());

        // Générer un certificat X.509
        X509Certificate certificate = generateCertificateObject(user);

        // Créer le keystore PKCS#12
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        // Ajouter la clé privée et le certificat au keystore
        keyStore.setKeyEntry(
                user.getUsername(),
                privateKey,
                password.toCharArray(),
                new java.security.cert.Certificate[]{certificate}
        );

        // Exporter le keystore
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());

        return baos.toByteArray();
    }

    private X509Certificate generateCertificateObject(User user) throws Exception {
        // Convertir les clés stockées en Base64 en objets Java
        PrivateKey privateKey = loadPrivateKey(user.getPrivateKey());
        PublicKey publicKey = loadPublicKey(user.getPublicKey());

        // Informations sur le sujet du certificat
        X500Name subject = new X500Name("CN=" + user.getUsername() + ", E=" + user.getEmail());

        // Période de validité du certificat
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // Valide 1 an

        // Création du builder de certificat
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now),
                startDate,
                endDate,
                subject,
                publicKeyInfo
        );

        // Signer le certificat avec la clé privée
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        // Générer le certificat
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateHolder);
    }

    private PrivateKey loadPrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}