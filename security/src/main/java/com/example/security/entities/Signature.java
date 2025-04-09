package com.example.security.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "signatures")
@Getter @Setter @NoArgsConstructor
public class Signature {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    @Column(nullable = false, columnDefinition = "LONGBLOB")
    private byte[] signedHash;

    @Column(nullable = false)
    private String algorithm = "SHA256withRSA";

    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(nullable = false)
    private LocalDateTime signedAt;

    @Column
    private String timestampToken;  // Ajoute à l'entité Signature

    @OneToOne
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User signer;
}