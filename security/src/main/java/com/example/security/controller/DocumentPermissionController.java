package com.example.security.controller;

import com.example.security.entities.Document;
import com.example.security.entities.DocumentPermission;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentPermissionRepository;
import com.example.security.repositories.UserRepository;
import com.example.security.security.UserPrincipal;
import com.example.security.services.DocumentService;
import jakarta.persistence.EntityNotFoundException;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
public class DocumentPermissionController {

    private final DocumentService documentService;
    private final UserRepository userRepository;
    private final DocumentPermissionRepository permissionRepository;

    @PostMapping("/share")
    public ResponseEntity<?> shareDocument(@RequestBody ShareDocumentRequest request,
                                           @AuthenticationPrincipal UserDetails userDetails) {
        try {
            DocumentPermission permission = documentService.shareDocument(
                    request.getDocumentId(),
                    request.getUserId(),
                    request.getPermissionType(),
                    request.getExpiresAt(),
                    userDetails
            );
            return ResponseEntity.ok(permission);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/shared-with-me")
    public ResponseEntity<?> getSharedDocuments(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            UserPrincipal principal = (UserPrincipal) userDetails;
            User user = userRepository.findById(principal.getId())
                    .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable"));

            List<Document> documents = documentService.getSharedDocuments(user);
            return ResponseEntity.ok(documents);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/{permissionId}")
    public ResponseEntity<?> revokeAccess(@PathVariable Long permissionId,
                                          @AuthenticationPrincipal UserDetails userDetails) {
        try {
            documentService.revokeAccess(permissionId, userDetails);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/document/{documentId}")
    public ResponseEntity<?> getDocumentPermissions(@PathVariable Long documentId,
                                                    @AuthenticationPrincipal UserDetails userDetails) {
        try {
            UserPrincipal principal = (UserPrincipal) userDetails;
            Document document = documentService.getDocumentById(documentId, userDetails);

            // Vérifier que l'utilisateur est le propriétaire ou un admin
            if (!document.getUser().getId().equals(principal.getId())
                    && principal.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Accès refusé");
            }

            List<DocumentPermission> permissions = permissionRepository.findByDocument(document);
            return ResponseEntity.ok(permissions);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Classes pour les requêtes
    @Data
    public static class ShareDocumentRequest {
        private Long documentId;
        private Long userId;
        private DocumentPermission.PermissionType permissionType;
        private LocalDateTime expiresAt;
    }
}