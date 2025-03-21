package com.example.security.controller;

import com.example.security.entities.Signature;
import com.example.security.services.SignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping("/api/signatures")
public class SignatureController {
    private final SignatureService signatureService;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    // 🔹 Signer un document
    @PostMapping("/sign")
    public ResponseEntity<?> signDocument(
            @RequestParam Long documentId,
            @RequestParam Long userId,
            @RequestParam String privateKeyBase64) {
        try {
            if (privateKeyBase64 == null || privateKeyBase64.isEmpty()) {
                return ResponseEntity.badRequest().body("Private key cannot be empty");
            }
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
            Signature signature = signatureService.signerDocument(documentId, userId, Base64.getDecoder().decode(privateKeyBase64));
            return ResponseEntity.ok(signature);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Invalid Base64 encoding");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error signing document: " + e.getMessage());
        }
    }

    // 🔹 Vérifier une signature
    @PostMapping("/verify")
    public ResponseEntity<?> verifySignature(
            @RequestParam Long documentId,
            @RequestParam String signedHashBase64,
            @RequestParam String publicKeyBase64) {
        try {
            if (signedHashBase64 == null || publicKeyBase64 == null) {
                return ResponseEntity.badRequest().body("Signed hash and public key cannot be null");
            }

            boolean isValid = signatureService.verifierSignature(documentId, signedHashBase64, publicKeyBase64);
            return ResponseEntity.ok(isValid);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Invalid Base64 encoding");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error verifying signature: " + e.getMessage());
        }
    }
}
