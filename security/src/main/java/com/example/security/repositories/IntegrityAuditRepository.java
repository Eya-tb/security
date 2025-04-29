package com.example.security.repositories;

import com.example.security.entities.IntegrityAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface IntegrityAuditRepository extends JpaRepository<IntegrityAudit, Long> {

    // Trouver tous les audits pour un document spécifique
    List<IntegrityAudit> findByDocumentId(Long documentId);

    // Trouver tous les audits effectués par un utilisateur spécifique
    List<IntegrityAudit> findByUserId(Long userId);

    // Trouver les audits par résultat (réussi/échoué)
    List<IntegrityAudit> findByPassed(boolean passed);

    // Trouver les audits dans une période spécifique
    List<IntegrityAudit> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    // Trouver les derniers audits pour un document
    @Query("SELECT a FROM IntegrityAudit a WHERE a.documentId = :documentId ORDER BY a.timestamp DESC")
    List<IntegrityAudit> findLatestAuditsForDocument(@Param("documentId") Long documentId);

    // Compter le nombre d'échecs d'intégrité pour un document
    @Query("SELECT COUNT(a) FROM IntegrityAudit a WHERE a.documentId = :documentId AND a.passed = false")
    long countIntegrityFailures(@Param("documentId") Long documentId);
}