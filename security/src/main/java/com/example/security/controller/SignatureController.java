package com.example.security.controller;

import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import com.example.security.entities.User;
import com.example.security.services.SignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
@RequestMapping("/api/signatures")
public class SignatureController {
    private final SignatureService signatureService;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    // 🔹 Signer un document
    @PostMapping("/sign")
    public ResponseEntity<Signature> signDocument(@RequestParam Long documentId, @RequestParam Long userId, @RequestBody PrivateKey privateKey) throws Exception {
        Document document = new Document();
        document.setId(documentId);
        User user = new User();
        user.setId(userId);

        Signature signature = signatureService.signerDocument(document, user, privateKey);
        return ResponseEntity.ok(signature);
    }

    // 🔹 Vérifier une signature
    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifySignature(@RequestParam Long documentId, @RequestBody byte[] signedHash, @RequestBody PublicKey publicKey) throws Exception {
        Document document = new Document();
        document.setId(documentId);
        boolean isValid = signatureService.verifierSignature(document, signedHash, publicKey);
        return ResponseEntity.ok(isValid);
    }
}
