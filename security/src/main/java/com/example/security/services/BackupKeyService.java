package com.example.security.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
@Service
public class BackupKeyService {

    private final VaultTemplate vaultTemplate;
    private final String vaultPath;
    private final String keyField;

    public BackupKeyService(VaultTemplate vaultTemplate,
                            @Value("${vault.master-key-path}") String vaultPath,
                            @Value("${vault.master-key-field}") String keyField) {
        this.vaultTemplate = vaultTemplate;
        this.vaultPath = vaultPath;
        this.keyField = keyField;
    }

    public String getMasterBackupKey() {
        try {
            log.debug("Fetching master key from Vault at path: {}", vaultPath);

            // Méthode recommandée pour KV v2
            VaultResponse response = vaultTemplate.read(vaultPath);

            if (response == null) {
                throw new IllegalStateException("Vault returned null response for path: " + vaultPath);
            }

            // Structure imbriquée pour KV v2
            Map<String, Object> dataMap = (Map<String, Object>) response.getData().get("data");

            if (dataMap == null) {
                throw new IllegalStateException("No 'data' field found in Vault response");
            }

            Object keyValue = dataMap.get(keyField);

            if (keyValue == null) {
                throw new IllegalStateException(
                        String.format("Key '%s' not found in Vault data. Available keys: %s",
                                keyField, dataMap.keySet())
                );
            }

            return keyValue.toString();

        } catch (Exception e) {
            log.error("Failed to retrieve master backup key from Vault", e);
            throw new RuntimeException("Could not retrieve master backup key: " + e.getMessage(), e);
        }
    }
}