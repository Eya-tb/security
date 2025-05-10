package com.example.security.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "document_permissions")
@Data
@NoArgsConstructor
public class DocumentPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    private PermissionType permissionType;

    private LocalDateTime grantedAt;

    private LocalDateTime expiresAt;

    @Column(name = "created_by")
    private Long createdBy;

    public enum PermissionType {
        READ, EDIT, SIGN
    }
}