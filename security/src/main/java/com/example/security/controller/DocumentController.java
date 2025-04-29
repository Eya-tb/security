package com.example.security.controller;

import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import com.example.security.repositories.UserRepository;
import com.example.security.security.UserPrincipal;
import com.example.security.services.ApiResponse;
import com.example.security.services.DocumentService;
import com.example.security.services.SignatureService;
import com.example.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

    private final DocumentService documentService;
    private final UserRepository userRepository;
    private final UserService userService;
    private final SignatureService signatureService;

    @PostMapping("/upload")
    public ResponseEntity<?> uploadDocument(@RequestParam("file") MultipartFile file,
                                            Authentication authentication) {
        try {
            // Vérifier la similarité avec les documents existants
            List<Document> similarDocs = documentService.findSimilarDocuments(file.getBytes(), 0.9);
            if (!similarDocs.isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("message", "Un document similaire existe déjà dans le système");
                response.put("similarDocuments", similarDocs.stream()
                        .map(doc -> Map.of(
                                "id", doc.getId(),
                                "name", doc.getName(),
                                "signedStatus", doc.getSignature() != null ? "Signé" : "Non signé"
                        ))
                        .collect(Collectors.toList()));
                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
            }
            // Si aucun document similaire, procéder à l'upload
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            Document document = documentService.uploadDocument(file, userPrincipal);
            return ResponseEntity.ok(ApiResponse.success("Document uploadé avec succès", document));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de l'upload: " + e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<Document>>> getUserDocuments(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
            List<Document> documents = documentService.getDocumentsByUser(user);
            return ResponseEntity.ok(ApiResponse.success("Documents récupérés avec succès", documents));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération: " + e.getMessage()));
        }
    }

    @GetMapping("/user")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserDocumentsPaginated(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size) {
        try {
            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));
            Pageable pageable = PageRequest.of(page, size);
            Page<Document> documents = documentService.getUserDocumentsPaginated(user, pageable);

            List<Document> documentList = documents.getContent()
                    .stream()
                    .peek(doc -> doc.setContent(null))
                    .toList();

            Map<String, Object> response = new HashMap<>();
            response.put("documents", documentList);
            response.put("currentPage", documents.getNumber());
            response.put("totalItems", documents.getTotalElements());
            response.put("totalPages", documents.getTotalPages());

            return ResponseEntity.ok(ApiResponse.success("Documents récupérés avec succès", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération: " + e.getMessage()));
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Document>> getDocumentById(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            Document document = documentService.getDocumentById(id);

            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            boolean isAdmin = user.getRole().name().equals("ADMIN");
            boolean isOwner = document.getUser().getId().equals(user.getId());

            if (!isAdmin && !isOwner) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Vous n'êtes pas autorisé à accéder à ce document"));
            }

            document.setContent(null);
            return ResponseEntity.ok(ApiResponse.success("Document récupéré avec succès", document));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Document non trouvé: " + e.getMessage()));
        }
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<?> downloadDocument(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            Document document = documentService.getDocumentById(id);

            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            boolean isAdmin = user.getRole().name().equals("ADMIN");
            boolean isOwner = document.getUser().getId().equals(user.getId());

            if (!isAdmin && !isOwner) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Accès refusé: vous n'êtes pas autorisé à télécharger ce document"));
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(document.getType()));
            headers.setContentDispositionFormData("attachment", document.getName());
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(document.getContent());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(ApiResponse.error("Document non trouvé: " + e.getMessage()));
        }
    }
    @PostMapping("/{documentId}/sign")
    public ResponseEntity<?> signDocument(@PathVariable Long documentId,
                                          @RequestBody Map<String, String> payload,
                                          @AuthenticationPrincipal UserDetails userDetails) {
        try {
            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            String password = payload.get("password");

            if (password == null || password.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Le mot de passe est requis"));
            }

            User user = userService.getUserById(userPrincipal.getId());

            // Essayer de signer le document
            signatureService.createSignature(documentId, user.getId(), password);

            return ResponseEntity.ok(ApiResponse.success("Document signé avec succès", null));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Erreur d'authentification: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        }
    }

    @GetMapping("/{id}/verify")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyDocument(@PathVariable Long id) {
        try {
            boolean isValid = documentService.verifyDocument(id);

            Map<String, Object> response = new HashMap<>();
            response.put("valid", isValid);
            String message = isValid ?
                    "La signature du document est valide" :
                    "La signature du document n'est pas valide";

            return ResponseEntity.ok(ApiResponse.success(message, response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la vérification: " + e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN') or @documentService.isOwner(#id, authentication.principal)")
    public ResponseEntity<ApiResponse<String>> deleteDocument(@PathVariable Long id) {
        try {
            documentService.deleteDocument(id);
            // Ajouter null comme deuxième argument pour les données
            return ResponseEntity.ok(ApiResponse.success("Document supprimé avec succès", null));
        } catch (Exception e) {
            // Ajouter null comme deuxième argument pour les données
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la suppression: " + e.getMessage()));
        }
    }

    @GetMapping("/{id}/signature")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSignatureInfo(@PathVariable Long id) {
        try {
            Optional<Signature> signature = documentService.getDocumentSignature(id);

            Map<String, Object> response = new HashMap<>();
            if (signature.isEmpty()) {
                response.put("signed", false);
                return ResponseEntity.ok(ApiResponse.success("Document non signé", response));
            }

            String signerUsername = "Utilisateur inconnu";
            if (signature.get().getSigner() != null && signature.get().getSigner().getUsername() != null) {
                signerUsername = signature.get().getSigner().getUsername();
            }

            response.put("signed", true);
            response.put("signedAt", signature.get().getSignedAt());
            response.put("algorithm", signature.get().getAlgorithm());
            response.put("signer", signerUsername);

            return ResponseEntity.ok(ApiResponse.success("Informations de signature récupérées", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur: " + e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> updateDocument(
            @PathVariable Long id,
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            UserPrincipal userPrincipal = (UserPrincipal) userDetails;
            User user = userRepository.findById(userPrincipal.getId())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            Document document = documentService.getDocumentById(id);
            if (!document.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("Vous ne pouvez mettre à jour que vos propres documents"));
            }

            Document updatedDocument = documentService.updateDocument(id, file);

            Map<String, Object> response = new HashMap<>();
            response.put("id", updatedDocument.getId());
            response.put("name", updatedDocument.getName());
            response.put("type", updatedDocument.getType());

            return ResponseEntity.ok(ApiResponse.success("Document mis à jour avec succès", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la mise à jour: " + e.getMessage()));
        }
    }

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<Map<String, Object>>> searchDocuments(
            @RequestParam(value = "query", defaultValue = "") String query,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<Document> documents = documentService.searchDocuments(query, pageable);

            List<Document> documentList = documents.getContent()
                    .stream()
                    .peek(doc -> doc.setContent(null))
                    .toList();

            Map<String, Object> response = new HashMap<>();
            response.put("documents", documentList);
            response.put("currentPage", documents.getNumber());
            response.put("totalItems", documents.getTotalElements());
            response.put("totalPages", documents.getTotalPages());

            return ResponseEntity.ok(ApiResponse.success("Résultats de recherche", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la recherche: " + e.getMessage()));
        }
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAllDocuments(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "20") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<Document> documents = documentService.getAllDocuments(pageable);

            List<Document> documentList = documents.getContent()
                    .stream()
                    .peek(doc -> doc.setContent(null))
                    .toList();

            Map<String, Object> response = new HashMap<>();
            response.put("documents", documentList);
            response.put("currentPage", documents.getNumber());
            response.put("totalItems", documents.getTotalElements());
            response.put("totalPages", documents.getTotalPages());

            return ResponseEntity.ok(ApiResponse.success("Tous les documents récupérés", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération: " + e.getMessage()));
        }
    }

    @GetMapping("/{id}/history")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDocumentHistory(@PathVariable Long id) {
        try {
            List<Map<String, Object>> history = new ArrayList<>();

            Map<String, Object> entry = new HashMap<>();
            entry.put("action", "CRÉATION");
            entry.put("date", LocalDateTime.now().minusDays(1));
            entry.put("user", "Utilisateur");
            history.add(entry);

            return ResponseEntity.ok(ApiResponse.success("Historique récupéré avec succès", history));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération de l'historique: " + e.getMessage()));
        }
    }
    @PostMapping("/check-structured-similarity")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> checkStructuredDocumentSimilarity(@RequestParam("file") MultipartFile file) {
        try {
            List<Document> similarDocs = new ArrayList<>();

            if (isSpreadsheetFile(file)) {
                // Extraire le contenu structuré (cellules, valeurs) du fichier
                List<List<String>> extractedContent = extractStructuredContent(file);
                // Rechercher des documents similaires basés sur le contenu structuré
                similarDocs = documentService.findSimilarStructuredDocuments(extractedContent, 0.8);
            }

            if (!similarDocs.isEmpty()) {
                Map<String, Object> response = new HashMap<>();
                response.put("message", "Des documents similaires existent déjà");
                response.put("similarDocuments", similarDocs.stream()
                        .map(doc -> Map.of(
                                "id", doc.getId(),
                                "name", doc.getName(),
                                "signedStatus", doc.getSignature() != null ? "Signé" : "Non signé"
                        ))
                        .collect(Collectors.toList()));
                return ResponseEntity.status(HttpStatus.OK).body(response);
            }

            return ResponseEntity.ok(Map.of("message", "Aucun document similaire trouvé"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erreur lors de la vérification: " + e.getMessage()));
        }
    }

    private boolean isSpreadsheetFile(MultipartFile file) {
        String contentType = file.getContentType();
        String filename = file.getOriginalFilename();

        return contentType != null && (
                contentType.contains("excel") ||
                        contentType.contains("spreadsheet") ||
                        contentType.contains("csv")) ||
                (filename != null && (
                        filename.endsWith(".xlsx") ||
                                filename.endsWith(".xls") ||
                                filename.endsWith(".csv")));
    }

    private List<List<String>> extractStructuredContent(MultipartFile file) throws IOException {
        List<List<String>> content = new ArrayList<>();
        String filename = file.getOriginalFilename();

        if (filename != null && filename.endsWith(".csv")) {
            // Traitement CSV
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    List<String> row = Arrays.asList(line.split(","));
                    content.add(row);
                }
            }
        } else {
            // Traitement Excel
            try (InputStream is = file.getInputStream()) {
                Workbook workbook = WorkbookFactory.create(is);
                Sheet sheet = workbook.getSheetAt(0); // Première feuille

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
}