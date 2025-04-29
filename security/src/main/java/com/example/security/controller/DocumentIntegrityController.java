package com.example.security.controller;

import com.example.security.services.DocumentIntegrityService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api/documents/integrity")
@RequiredArgsConstructor
public class DocumentIntegrityController {

    private final DocumentIntegrityService documentIntegrityService;

    @GetMapping("/verify/{documentId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyDocumentIntegrity(@PathVariable Long documentId) {
        try {
            Map<String, Object> verificationResult = documentIntegrityService.verifyDocumentIntegrity(documentId);
            return ResponseEntity.ok(verificationResult);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "Échec de la vérification: " + e.getMessage(),
                    "valid", false
            ));
        }
    }

    @PostMapping("/compare/{documentId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> compareWithOriginal(
            @PathVariable Long documentId,
            @RequestParam("file") MultipartFile file) {
        try {
            byte[] newContent = file.getBytes();
            boolean isModified = documentIntegrityService.isDocumentModified(documentId, newContent);
            double similarity = documentIntegrityService.calculateDocumentSimilarity(documentId, newContent);

            return ResponseEntity.ok(Map.of(
                    "modified", isModified,
                    "similarityPercent", Math.round(similarity * 10000) / 100.0, // Arrondi à 2 décimales
                    "message", isModified ?
                            "Le document a été modifié par rapport à l'original" :
                            "Le document est identique à l'original"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "Échec de la comparaison: " + e.getMessage()
            ));
        }
    }
}