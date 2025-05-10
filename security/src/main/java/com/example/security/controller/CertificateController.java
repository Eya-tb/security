package com.example.security.controller;

import com.example.security.entities.User;
import com.example.security.security.UserPrincipal;
import com.example.security.services.CertificateService;
import com.example.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final UserService userService;

    @GetMapping("/export/pem")
    public ResponseEntity<Resource> exportCertificatePEM(
            @AuthenticationPrincipal UserPrincipal currentUser,
            @RequestParam String password) {
        try {
            User user = userService.getUserById(currentUser.getId());

            // Déchiffrer la clé privée via KeyVaultService
            byte[] certificateData = certificateService.generateSelfSignedCertificate(user, password);

            ByteArrayResource resource = new ByteArrayResource(certificateData);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + user.getUsername() + "-certificate.pem\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(certificateData.length)
                    .body(resource);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping("/export/pkcs12")
    public ResponseEntity<Resource> exportCertificatePKCS12(
            @AuthenticationPrincipal UserPrincipal currentUser,
            @RequestParam String password) {
        try {
            User user = userService.getUserById(currentUser.getId());
            byte[] certificateData = certificateService.exportToPKCS12(user, password);
            ByteArrayResource resource = new ByteArrayResource(certificateData);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + user.getUsername() + "-certificate.p12\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .contentLength(certificateData.length)
                    .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}