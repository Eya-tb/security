package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service
public class DocumentService {
    private final DocumentRepository documentRepository;

    public DocumentService(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }

    // 🔹 Téléverser un document
    public Document uploadDocument(MultipartFile file, User user) throws IOException {
        Document document = new Document();
        document.setName(file.getOriginalFilename());
        document.setType(file.getContentType());
        document.setContent(file.getBytes());
        document.setUser(user);
        return documentRepository.save(document);
    }

    // 🔹 Récupérer tous les documents d'un utilisateur
    public List<Document> getDocumentsByUser(User user) {
        return documentRepository.findByUser(user);
    }

    // 🔹 Supprimer un document
    public void deleteDocument(Long documentId) {
        if (!documentRepository.existsById(documentId)) {
            throw new RuntimeException("Document introuvable !");
        }
        documentRepository.deleteById(documentId);
    }
}
