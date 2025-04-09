package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import com.example.security.repositories.SignatureRepository;
import com.example.security.repositories.UserRepository;
import com.example.security.utils.KeyUtils;
import com.example.security.utils.SigningUtils;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class SignatureService {

    private static final Logger logger = LoggerFactory.getLogger(SignatureService.class);

    private final SignatureRepository signatureRepository;
    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final TSAClient tsaClient;

    // Initialisation du provider Bouncy Castle
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public Signature createSignature(Long documentId, Long userId, String privateKeyBase64) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found"));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        // 1. Préparation des clés
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = KeyUtils.loadPrivateKey(privateKeyBytes);
        PublicKey publicKey = KeyUtils.extractPublicKey(privateKey);

        // 2. Calcul du hash du document
        byte[] documentHash = calculateSHA256(document.getContent());

        // 3. Création de la signature
        byte[] signatureBytes = SigningUtils.sign(documentHash, privateKey);

        // 4. Obtention du tampon temporel certifié
        byte[] timestampToken = getTimestampToken(signatureBytes);

        // 5. Sauvegarde de la signature
        Signature signature = new Signature();
        signature.setSignedHash(signatureBytes);
        signature.setPublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        signature.setSignedAt(LocalDateTime.now());
        signature.setTimestampToken(Base64.getEncoder().encodeToString(timestampToken));
        signature.setDocument(document);
        signature.setSigner(user);

        return signatureRepository.save(signature);
    }


    public boolean verifySignature(Long documentId) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document not found"));

        Signature signature = signatureRepository.findByDocument(document)
                .orElseThrow(() -> new EntityNotFoundException("Signature not found"));

        // 1. Vérification de base de la signature
        PublicKey publicKey = KeyUtils.loadPublicKey(Base64.getDecoder().decode(signature.getPublicKey()));
        byte[] documentHash = calculateSHA256(document.getContent());
        boolean sigValid = SigningUtils.verify(documentHash, signature.getSignedHash(), publicKey);

        // 2. Vérification de l'horodatage
        boolean timestampValid = verifyTimestamp(
                signature.getSignedHash(),
                Base64.getDecoder().decode(signature.getTimestampToken())
        );

        return sigValid && timestampValid;
    }

    private byte[] getTimestampToken(byte[] signature) throws Exception {
        // Créer le générateur de requête d'horodatage
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true); // Demander le certificat TSA dans la réponse

        // Calculer le hachage de la signature pour l'horodatage
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] signatureHash = digest.digest(signature);

        // Identifiant pour l'algorithme SHA-256
        ASN1ObjectIdentifier hashAlgorithm = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

        // Génération d'un nonce (nombre unique) pour éviter les attaques par rejeu
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

        // Créer la requête d'horodatage avec le hachage de la signature
        TimeStampRequest request = reqGen.generate(hashAlgorithm, signatureHash, nonce);

        // Envoyer la requête au serveur TSA et obtenir la réponse
        byte[] response = tsaClient.getTimeStampResponse(request.getEncoded());
        TimeStampResponse tsResponse = new TimeStampResponse(response);

        // Vérifier que la réponse correspond à notre requête
        tsResponse.validate(request);

        // Affichage de débogage pour l'horodatage
        TimeStampToken token = tsResponse.getTimeStampToken();
        Date genTime = token.getTimeStampInfo().getGenTime();
        logger.info("Horodatage TSA reçu : {}", genTime);



        // Récupérer et retourner le jeton d'horodatage
        return tsResponse.getTimeStampToken().getEncoded();
    }

    private boolean verifyTimestamp(byte[] signature, byte[] timestampToken) throws Exception {
        try {
            // 1. Analyser le jeton d'horodatage
            TimeStampToken tsToken = new TimeStampToken(new CMSSignedData(timestampToken));

            // 2. Extraire les certificats du jeton
            Store<X509CertificateHolder> certStore = tsToken.getCertificates();
            Collection<X509CertificateHolder> matches = certStore.getMatches(null);

            if (matches.isEmpty()) {
                throw new Exception("Aucun certificat trouvé dans le jeton d'horodatage");
            }

            // 3. Trouver le certificat du signataire
            X509CertificateHolder certHolder = null;
            SignerId signerId = tsToken.getSID();

            for (X509CertificateHolder holder : matches) {
                if (holder.getSerialNumber().equals(signerId.getSerialNumber()) &&
                    holder.getIssuer().equals(signerId.getIssuer())) {
                    certHolder = holder;
                    break;
                }
            }

            if (certHolder == null) {
                // Si nous ne pouvons pas trouver le certificat exact, prenons le premier
                certHolder = matches.iterator().next();
            }

            // 4. Construire le vérificateur avec le certificat
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC")
                    .build(certHolder);

            // 5. Valider le jeton d'horodatage
            tsToken.validate(verifier);

            // 6. Vérifier que l'empreinte dans le jeton correspond à notre signature
            // Calculer le hachage de la signature
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] signatureHash = digest.digest(signature);

            // Comparer avec l'empreinte dans le jeton
            byte[] tokenImprint = tsToken.getTimeStampInfo().getMessageImprintDigest();
            return Arrays.equals(signatureHash, tokenImprint);

        } catch (Exception e) {
            throw new SignatureVerificationException("Échec de validation du timestamp: " + e.getMessage(), e);
        }
    }

    public Signature getSignatureByDocumentId(Long documentId) {
        return signatureRepository.findByDocumentId(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Signature not found"));
    }

    private byte[] calculateSHA256(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(content);
    }

    public static class SignatureVerificationException extends Exception {
        public SignatureVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}