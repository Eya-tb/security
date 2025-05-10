package com.example.security.entities;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "key_pairs")
public class KeyPair {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, unique = true)
    private Long userId;

    @Column(name = "public_key", nullable = false, length = 2048)
    private String publicKey;

    @Column(name = "encrypted_private_key", nullable = false, length = 4096)
    private String encryptedPrivateKey;

    @Column(name = "backup_key_id")
    private String backupKeyId;

    @Column(nullable = false)
    private boolean recoverable;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    // Getters et setters
}
