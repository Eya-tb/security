package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
@Service
@RequiredArgsConstructor
public class DocumentService {
    private final DocumentRepository documentRepository;
    private final SignatureService signatureService;

    public Document uploadDocument(MultipartFile file, User user) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Le fichier ne peut pas être vide !");
        }

        if (user == null) {
            throw new IllegalArgumentException("L'utilisateur est introuvable !");
        }

        Document document = new Document();
        document.setName(file.getOriginalFilename());
        document.setType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        document.setContent(file.getBytes());
        document.setUser(user);

        return documentRepository.save(document);
    }

    public List<Document> getDocumentsByUser(User user) {
        return documentRepository.findByUser(user);
    }

    public void deleteDocument(Long documentId) {
        if (!documentRepository.existsById(documentId)) {
            throw new RuntimeException("Document introuvable !");
        }
        documentRepository.deleteById(documentId);
    }

    public Document signDocument(Long documentId, User user, String privateKeyBase64) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable"));
        signatureService.createSignature(document.getId(), user.getId(), privateKeyBase64);
        return document;
    }

    public boolean verifyDocument(Long documentId) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new RuntimeException("Document introuvable"));
        return signatureService.verifySignature(document.getId());
    }
}
