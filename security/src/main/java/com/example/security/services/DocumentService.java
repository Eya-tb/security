package com.example.security.services;

import com.example.security.entities.*;
import com.example.security.repositories.DocumentPermissionRepository;
import com.example.security.repositories.DocumentRepository;
import com.example.security.repositories.SignatureRepository;
import com.example.security.repositories.UserRepository;
import com.example.security.security.UserPrincipal;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

@Service
@RequiredArgsConstructor
public class DocumentService {

    private static final Logger logger = LoggerFactory.getLogger(DocumentService.class);
    private final DocumentRepository documentRepository;
    private final SignatureRepository signatureRepository;
    private final SignatureService signatureService;
    private final UserRepository userRepository;
    private final DocumentIntegrityService documentIntegrityService;
    private final DocumentPermissionRepository permissionRepository;
    public Document uploadDocument(MultipartFile file, UserDetails userDetails) throws IOException, NoSuchAlgorithmException {
        UserPrincipal userPrincipal = (UserPrincipal) userDetails;
        User user = userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new EntityNotFoundException("L'utilisateur est introuvable !"));

        Document document = new Document();
        document.setName(file.getOriginalFilename());
        document.setType(file.getContentType());
        document.setContent(file.getBytes());
        document.setUser(user);

        return documentRepository.save(document);
    }

    public List<Document> getDocumentsByUser(User user) {
        return documentRepository.findByUser(user)
                .stream()
                .map(doc -> {
                    doc.setContent(null);
                    return doc;
                })
                .toList();
    }

    public Document getDocumentById(Long id) {
        Document document = documentRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Document non trouvé avec l'ID: " + id));

        if (document.getSignature() != null && document.getSignature().getSigner() == null) {
            document.getSignature().setSigner(new User());
            document.getSignature().getSigner().setUsername("Utilisateur inconnu");
        }

        return document;
    }

    public void deleteDocument(Long documentId) {
        if (!documentRepository.existsById(documentId)) {
            throw new EntityNotFoundException("Document introuvable !");
        }
        documentRepository.deleteById(documentId);
    }

    public void signDocument(Long documentId, User user, String privateKeyBase64) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable"));

        if (!document.getUser().getId().equals(user.getId()) && user.getRole() != Role.ADMIN) {
            throw new SecurityException("Vous n'êtes pas autorisé à signer ce document");
        }

        if (document.getSignature() != null) {
            throw new IllegalStateException("Ce document est déjà signé");
        }

        document.calculateHash();
        documentRepository.save(document);
        signatureService.createSignature(documentId, user.getId(), privateKeyBase64);
    }

    public boolean verifyDocument(Long documentId) throws Exception {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable"));
        return signatureService.verifySignature(document.getId());
    }

    public Optional<Signature> getDocumentSignature(Long documentId) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable avec ID: " + documentId));
        return signatureRepository.findByDocument(document);
    }

    public Document updateDocument(Long documentId, MultipartFile file) throws IOException {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable avec ID: " + documentId));

        if (document.getSignature() != null) {
            throw new IllegalStateException("Impossible de modifier un document déjà signé");
        }

        document.setName(file.getOriginalFilename());
        document.setType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        document.setContent(file.getBytes());

        return documentRepository.save(document);
    }

    public Page<Document> searchDocuments(String query, Pageable pageable) {
        return documentRepository.searchByName(query, pageable);
    }

    public Page<Document> getAllDocuments(Pageable pageable) {
        return documentRepository.findAll(pageable);
    }

    public Page<Document> getUserDocumentsPaginated(User user, Pageable pageable) {
        return documentRepository.findByUser(user, pageable);
    }

    public List<Document> findSimilarDocuments(byte[] content, double similarityThreshold) {
        DuplicateDetectionService duplicateDetectionService = new DuplicateDetectionService(documentRepository);
        return duplicateDetectionService.findSimilarDocuments(content, similarityThreshold);
    }

    public List<Document> findSimilarStructuredDocuments(List<List<String>> content, double similarityThreshold) {
        List<Document> similarDocs = new ArrayList<>();

        // Récupérer tous les documents
        List<Document> allDocuments = documentRepository.findAll();

        for (Document doc : allDocuments) {
            // Ne pas traiter les documents non structurés
            if (!isSpreadsheetDocument(doc)) continue;

            try {
                // Extraire le contenu structuré du document existant
                List<List<String>> docContent = extractStructuredContentFromDocument(doc);

                // Calculer la similarité entre les deux contenus structurés
                double similarity = calculateStructuredContentSimilarity(content, docContent);

                if (similarity >= similarityThreshold) {
                    similarDocs.add(doc);
                }
            } catch (Exception e) {
                // Si erreur pendant l'analyse, ignorer ce document
                continue;
            }
        }

        return similarDocs;
    }

    private boolean isSpreadsheetDocument(Document doc) {
        String type = doc.getType();
        String name = doc.getName();

        return (type != null && (
                type.contains("excel") ||
                        type.contains("spreadsheet") ||
                        type.contains("csv"))) ||
                (name != null && (
                        name.endsWith(".xlsx") ||
                                name.endsWith(".xls") ||
                                name.endsWith(".csv")));
    }

    private List<List<String>> extractStructuredContentFromDocument(Document doc) throws IOException {
        List<List<String>> content = new ArrayList<>();

        if (doc.getName().endsWith(".csv")) {
            // Traiter le CSV
            String csvContent = new String(doc.getContent(), StandardCharsets.UTF_8);
            try (BufferedReader reader = new BufferedReader(new StringReader(csvContent))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.add(Arrays.asList(line.split(",")));
                }
            }
        } else {
            // Traiter l'Excel
            try (InputStream is = new ByteArrayInputStream(doc.getContent())) {
                Workbook workbook = WorkbookFactory.create(is);
                Sheet sheet = workbook.getSheetAt(0);

                for (Row row : sheet) {
                    List<String> rowData = new ArrayList<>();
                    for (Cell cell : row) {
                        switch (cell.getCellType()) {
                            case STRING:
                                rowData.add(cell.getStringCellValue());
                                break;
                            case NUMERIC:
                                rowData.add(String.valueOf(cell.getNumericCellValue()));
                                break;
                            case BOOLEAN:
                                rowData.add(String.valueOf(cell.getBooleanCellValue()));
                                break;
                            default:
                                rowData.add("");
                        }
                    }
                    content.add(rowData);
                }
                workbook.close();
            }
        }

        return content;
    }

    private double calculateStructuredContentSimilarity(List<List<String>> content1, List<List<String>> content2) {
        int totalCells = 0;
        int matchingCells = 0;

        // Déterminer le nombre minimal de lignes à comparer
        int minRows = Math.min(content1.size(), content2.size());

        for (int i = 0; i < minRows; i++) {
            List<String> row1 = content1.get(i);
            List<String> row2 = content2.get(i);

            // Déterminer le nombre minimal de cellules à comparer dans cette ligne
            int minCells = Math.min(row1.size(), row2.size());
            totalCells += Math.max(row1.size(), row2.size());

            for (int j = 0; j < minCells; j++) {
                if (row1.get(j).equals(row2.get(j))) {
                    matchingCells++;
                }
            }
        }

        // Ajouter les lignes restantes au total
        if (content1.size() > minRows) {
            for (int i = minRows; i < content1.size(); i++) {
                totalCells += content1.get(i).size();
            }
        } else if (content2.size() > minRows) {
            for (int i = minRows; i < content2.size(); i++) {
                totalCells += content2.get(i).size();
            }
        }

        // Éviter la division par zéro
        if (totalCells == 0) return 0.0;

        return (double) matchingCells / totalCells;
    }

    public class DuplicateDetectionService {
        private final DocumentRepository documentRepository;

        public DuplicateDetectionService(DocumentRepository documentRepository) {
            this.documentRepository = documentRepository;
        }

        public List<Document> findSimilarDocuments(byte[] content, double similarityThreshold) {
            String text = extractText(content);
            long simhash = computeSimhash(text);

            List<Document> similarDocs = new ArrayList<>();
            for (Document doc : documentRepository.findAll()) {
                double similarity = calculateSimilarity(simhash, computeSimhash(extractText(doc.getContent())));
                if (similarity >= similarityThreshold) {
                    similarDocs.add(doc);
                }
            }
            return similarDocs;
        }

        private String extractText(byte[] content) {
            return new String(content, java.nio.charset.StandardCharsets.UTF_8);
        }

        private long computeSimhash(String text) {
            if (text == null || text.isEmpty()) {
                return 0;
            }
            return text.hashCode();
        }

        private double calculateSimilarity(long hash1, long hash2) {
            long xor = hash1 ^ hash2;
            int bitDifferences = Long.bitCount(xor);
            return 1.0 - (bitDifferences / 64.0);
        }
    }


    // Méthode pour partager un document
    public DocumentPermission shareDocument(Long documentId, Long userId, DocumentPermission.PermissionType permissionType,
                                            LocalDateTime expiresAt, UserDetails currentUser) {
        UserPrincipal userPrincipal = (UserPrincipal) currentUser;

        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable"));

        User targetUser = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable"));

        // Vérifier que l'utilisateur courant est le propriétaire du document ou un admin
        if (!document.getUser().getId().equals(userPrincipal.getId())
                && userPrincipal.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            throw new SecurityException("Vous n'êtes pas autorisé à partager ce document");
        }

        DocumentPermission permission = new DocumentPermission();
        permission.setDocument(document);
        permission.setUser(targetUser);
        permission.setPermissionType(permissionType);
        permission.setGrantedAt(LocalDateTime.now());
        permission.setExpiresAt(expiresAt);
        permission.setCreatedBy(userPrincipal.getId());

        return permissionRepository.save(permission);
    }

    // Méthode pour vérifier si un utilisateur a une permission
    public boolean hasPermission(Long documentId, Long userId, DocumentPermission.PermissionType permissionType) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new EntityNotFoundException("Document introuvable"));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable"));

        // Le propriétaire du document a toujours toutes les permissions
        if (document.getUser().getId().equals(userId)) {
            return true;
        }

        // Les admins ont toutes les permissions
        if (user.getRole() == Role.ADMIN) {
            return true;
        }

        // Vérifier les permissions explicites qui ne sont pas expirées
        List<DocumentPermission> permissions = permissionRepository
                .findValidPermissions(document, user, LocalDateTime.now());

        return permissions.stream()
                .anyMatch(p -> p.getPermissionType() == permissionType);
    }

    // Modifier la méthode getDocumentById pour vérifier les permissions
    public Document getDocumentById(Long id, UserDetails userDetails) {
        Document document = documentRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Document non trouvé avec l'ID: " + id));

        UserPrincipal userPrincipal = (UserPrincipal) userDetails;
        boolean isOwner = document.getUser().getId().equals(userPrincipal.getId());
        boolean isAdmin = userPrincipal.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean hasPermission = hasPermission(id, userPrincipal.getId(), DocumentPermission.PermissionType.READ);

        if (!isOwner && !isAdmin && !hasPermission) {
            throw new SecurityException("Vous n'avez pas la permission de voir ce document");
        }

        if (document.getSignature() != null && document.getSignature().getSigner() == null) {
            document.getSignature().setSigner(new User());
            document.getSignature().getSigner().setUsername("Utilisateur inconnu");
        }

        return document;
    }

    // Méthode pour récupérer les documents partagés avec un utilisateur
    public List<Document> getSharedDocuments(User user) {
        List<DocumentPermission> permissions = permissionRepository.findByUser(user);
        return permissions.stream()
                .map(DocumentPermission::getDocument)
                .distinct()
                .map(doc -> {
                    doc.setContent(null); // Ne pas renvoyer le contenu dans les listes
                    return doc;
                })
                .toList();
    }

    // Méthode pour révoquer un accès
    public void revokeAccess(Long permissionId, UserDetails currentUser) {
        UserPrincipal userPrincipal = (UserPrincipal) currentUser;

        DocumentPermission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new EntityNotFoundException("Permission introuvable"));

        // Vérifier que l'utilisateur courant est le propriétaire ou un admin
        if (!permission.getDocument().getUser().getId().equals(userPrincipal.getId())
                && userPrincipal.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            throw new SecurityException("Vous n'êtes pas autorisé à révoquer cet accès");
        }

        permissionRepository.delete(permission);
    }


}