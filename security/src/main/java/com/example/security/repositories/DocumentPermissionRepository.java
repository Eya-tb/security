package com.example.security.repositories;

import com.example.security.entities.Document;
import com.example.security.entities.DocumentPermission;
import com.example.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface DocumentPermissionRepository extends JpaRepository<DocumentPermission, Long> {
    List<DocumentPermission> findByUser(User user);
    List<DocumentPermission> findByDocument(Document document);

    boolean existsByDocumentAndUserAndPermissionType(Document document, User user, DocumentPermission.PermissionType permissionType);

    @Query("SELECT dp FROM DocumentPermission dp WHERE dp.document = ?1 AND dp.user = ?2 AND (dp.expiresAt IS NULL OR dp.expiresAt > ?3)")
    List<DocumentPermission> findValidPermissions(Document document, User user, LocalDateTime now);
}