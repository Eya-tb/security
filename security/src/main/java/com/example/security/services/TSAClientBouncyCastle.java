package com.example.security.services;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class TSAClientBouncyCastle implements TSAClient {

    private final String tsaUrl;
    private final int connectTimeout;
    private final int readTimeout;

    public TSAClientBouncyCastle(String tsaUrl) {
        this(tsaUrl, 5000, 10000); // Valeurs par défaut pour les timeouts
    }

    public TSAClientBouncyCastle(String tsaUrl, int connectTimeout, int readTimeout) {
        this.tsaUrl = tsaUrl;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    @Override
    public byte[] getTimeStampResponse(byte[] requestBytes) throws Exception {
        URL url = new URL(tsaUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/timestamp-query");
        conn.setRequestProperty("Content-Length", String.valueOf(requestBytes.length));

        // Configuration des timeouts
        conn.setConnectTimeout(connectTimeout);
        conn.setReadTimeout(readTimeout);

        try (OutputStream out = conn.getOutputStream()) {
            out.write(requestBytes);
        }

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Échec de la réponse TSA: code HTTP " + conn.getResponseCode());
        }

        try (InputStream in = conn.getInputStream()) {
            return in.readAllBytes();
        }
    }
}