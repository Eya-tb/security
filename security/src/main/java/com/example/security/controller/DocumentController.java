package com.example.security.controller;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import com.example.security.services.DocumentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {
    private final DocumentService documentService;

    public DocumentController(DocumentService documentService) {
        this.documentService = documentService;
    }

    // 🔹 Téléverser un document
    @PostMapping("/upload")
    public ResponseEntity<Document> uploadDocument(@RequestParam("file") MultipartFile file, @RequestParam("userId") Long userId) throws IOException {
        User user = new User();
        user.setId(userId);
        return ResponseEntity.ok(documentService.uploadDocument(file, user));
    }

    // 🔹 Récupérer les documents d'un utilisateur
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Document>> getDocumentsByUser(@PathVariable Long userId) {
        User user = new User();
        user.setId(userId);
        return ResponseEntity.ok(documentService.getDocumentsByUser(user));
    }

    // 🔹 Supprimer un document
    @DeleteMapping("/{documentId}")
    public ResponseEntity<String> deleteDocument(@PathVariable Long documentId) {
        documentService.deleteDocument(documentId);
        return ResponseEntity.ok("Document supprimé !");
    }
}
