package com.example.security.services;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class TokenBlacklistService {

    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final Map<String, Instant> refreshTokens = new ConcurrentHashMap<>();

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshTokenExpirationMs;

    // Ajouter un token à la liste noire
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    // Vérifier si un token est sur la liste noire
    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    // Gérer les tokens de rafraîchissement
    public void saveRefreshToken(String username, String refreshToken) {
        refreshTokens.put(refreshToken, Instant.now().plusMillis(refreshTokenExpirationMs));
    }

    public boolean validateRefreshToken(String refreshToken) {
        Instant expiration = refreshTokens.get(refreshToken);
        return expiration != null && expiration.isAfter(Instant.now());
    }

    public void deleteRefreshToken(String refreshToken) {
        refreshTokens.remove(refreshToken);
    }

    // Nettoyage périodique des tokens expirés
    @Scheduled(fixedRate = 3600000) // Toutes les heures
    public void cleanExpiredTokens() {
        Instant now = Instant.now();
        refreshTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }
}