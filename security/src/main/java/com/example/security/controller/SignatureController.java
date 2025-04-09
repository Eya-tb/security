package com.example.security.controller;

import com.example.security.entities.Signature;
import com.example.security.services.SignatureService;
import jakarta.persistence.EntityNotFoundException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/signatures")
@RequiredArgsConstructor
@Validated
public class SignatureController {
    private final SignatureService signatureService;

    @PostMapping("/sign")
    public ResponseEntity<ApiResponse<SignatureResponse>> signDocument(
            @Valid @RequestBody SignRequest request) {
        try {
            Signature signature = signatureService.createSignature(
                    request.getDocumentId(),
                    request.getUserId(),
                    request.getPrivateKeyBase64()
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(
                            "Document signed successfully",
                            new SignatureResponse(
                                    signature.getId(),
                                    signature.getDocument().getId(),
                                    signature.getSignedAt()
                            )
                    )
            );
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(e.getMessage(), null));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>(e.getMessage(), null));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ApiResponse<>("Signing failed: " + e.getMessage(), null));
        }
    }

    @GetMapping("/verify/{documentId}")
    public ResponseEntity<ApiResponse<VerificationResponse>> verifySignature(
            @PathVariable Long documentId) {
        try {
            boolean isValid = signatureService.verifySignature(documentId);
            Signature signature = signatureService.getSignatureByDocumentId(documentId);

            return ResponseEntity.ok(
                    new ApiResponse<>(
                            "Verification completed",
                            new VerificationResponse(
                                    isValid,
                                    signature.getSigner().getUsername(),
                                    signature.getSignedAt()
                            )
                    )
            );
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>(e.getMessage(), null));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ApiResponse<>("Verification failed: " + e.getMessage(), null));
        }
    }


    // ... (DTOs inchangés)

    // === DTOs ===
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SignRequest {
        @NotNull(message = "Document ID is required")
        private Long documentId;

        @NotNull(message = "User ID is required")
        private Long userId;

        @NotBlank(message = "Private key cannot be empty")
        private String privateKeyBase64;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SignatureResponse {
        private Long signatureId;
        private Long documentId;
        private LocalDateTime signedAt;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VerificationResponse {
        private boolean isValid;
        private String signedBy;
        private LocalDateTime signingTime;
    }

    @Data
    @AllArgsConstructor
    public static class ApiResponse<T> {
        private String message;
        private T data;
    }
}
