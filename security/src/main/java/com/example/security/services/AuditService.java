package com.example.security.services;

import com.example.security.entities.IntegrityAudit;
import com.example.security.repositories.IntegrityAuditRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final IntegrityAuditRepository auditRepository;

    public void logIntegrityCheck(Long documentId, Long userId, boolean passed, String details) {
        IntegrityAudit audit = new IntegrityAudit();
        audit.setDocumentId(documentId);
        audit.setUserId(userId);
        audit.setPassed(passed);
        audit.setDetails(details);
        audit.setTimestamp(LocalDateTime.now());

        auditRepository.save(audit);
    }
}