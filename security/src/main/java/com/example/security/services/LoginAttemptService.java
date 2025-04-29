package com.example.security.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {
    @Value("${login.max-attempts:5}")
    private int maxAttempts;

    @Value("${login.blocking-period-minutes:30}")
    private int blockingPeriodMinutes;

    private final Map<String, Integer> attemptCache = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> blockedUsers = new ConcurrentHashMap<>();

    public void loginSucceeded(String username) {
        attemptCache.remove(username);
        blockedUsers.remove(username);
    }

    public void loginFailed(String username) {
        // Si l'utilisateur est bloqué, on ne fait rien de plus
        if (isBlocked(username)) {
            return;
        }

        // Sinon on incrémente le compteur
        int currentAttempts = attemptCache.getOrDefault(username, 0);
        attemptCache.put(username, currentAttempts + 1);

        // Si le seuil est dépassé, on bloque l'utilisateur
        if (currentAttempts + 1 >= maxAttempts) {
            blockedUsers.put(username, LocalDateTime.now().plusMinutes(blockingPeriodMinutes));
        }
    }

    public boolean isBlocked(String username) {
        LocalDateTime blockedUntil = blockedUsers.get(username);
        if (blockedUntil == null) {
            return false;
        }

        // Si la période de blocage est terminée, on retire l'utilisateur de la liste
        if (LocalDateTime.now().isAfter(blockedUntil)) {
            blockedUsers.remove(username);
            attemptCache.remove(username);
            return false;
        }

        return true;
    }

    public LocalDateTime getBlockedUntil(String username) {
        return blockedUsers.get(username);
    }

    public int getFailedAttempts(String email) {
        return attemptCache.getOrDefault(email, 0);
    }
}