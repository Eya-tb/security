package com.example.security.services;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;

@Service
public class TimestampService {

    private final TSAClientBouncyCastle tsaClient;

    public TimestampService() {
        // Tu peux aussi injecter l'URL via application.properties plus tard
        this.tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr");
    }

    public TimeStampResponse timestamp(byte[] data) throws Exception {
        // Étape 1: Hasher les données
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);

        // Étape 2: Créer la requête RFC 3161
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        TimeStampRequest request = tsqGenerator.generate(TSPAlgorithms.SHA256, hash);
        byte[] requestBytes = request.getEncoded();

        // Étape 3: Envoyer la requête
        byte[] responseBytes = tsaClient.getTimeStampResponse(requestBytes);

        // Étape 4: Retourner la réponse parsée
        TimeStampResponse response = new TimeStampResponse(responseBytes);
        response.validate(request); // Facultatif, mais bon pour valider la réponse

        return response;
    }
}
