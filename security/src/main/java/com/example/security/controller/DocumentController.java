package com.example.security.controller;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import com.example.security.services.DocumentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;

    // 🔹 Upload d’un document
    @PostMapping("/upload")
    public ResponseEntity<Document> uploadDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam("userId") Long userId) throws IOException {

        User user = new User();
        user.setId(userId);
        return ResponseEntity.ok(documentService.uploadDocument(file, user));
    }

    // 🔹 Signature d’un document
    @PostMapping("/{documentId}/sign")
    public ResponseEntity<Document> signDocument(
            @PathVariable Long documentId,
            @RequestParam("userId") Long userId,
            @RequestParam("privateKey") String privateKeyBase64) throws Exception {

        User user = new User();
        user.setId(userId);
        return ResponseEntity.ok(documentService.signDocument(documentId, user, privateKeyBase64));
    }

    // 🔹 Vérification de signature
    @GetMapping("/{documentId}/verify")
    public ResponseEntity<Boolean> verifyDocument(@PathVariable Long documentId) throws Exception {
        return ResponseEntity.ok(documentService.verifyDocument(documentId));
    }

    // 🔹 Liste des documents par utilisateur
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Document>> getDocumentsByUser(@PathVariable Long userId) {
        User user = new User();
        user.setId(userId);
        return ResponseEntity.ok(documentService.getDocumentsByUser(user));
    }

    // 🔹 Suppression d’un document
    @DeleteMapping("/{documentId}")
    public ResponseEntity<String> deleteDocument(@PathVariable Long documentId) {
        documentService.deleteDocument(documentId);
        return ResponseEntity.ok("Document supprimé !");
    }
}
