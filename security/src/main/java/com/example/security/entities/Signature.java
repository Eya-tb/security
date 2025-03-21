package com.example.security.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "signatures")
public class Signature {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    @Column(nullable = false)
    private byte[] signedHash;

    @Column(nullable = false)
    private String algorithm;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(nullable = false)
    private LocalDateTime signedAt;

    @OneToOne
    @JoinColumn(name = "document_id", referencedColumnName = "id", nullable = false, unique = true)
    private Document document;  // ✅ Ensures One-to-One

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    private User user;
}