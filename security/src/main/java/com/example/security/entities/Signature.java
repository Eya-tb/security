package com.example.security.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "signatures")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
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

    @Lob
    @Column(name = "timestamp_token", columnDefinition = "LONGTEXT")
    private String timestampToken;

    @OneToOne
    @JoinColumn(name = "document_id", nullable = false)
    @JsonIgnoreProperties("signature") // Ignore la signature quand on sérialise le document
    private Document document;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference // Empêche les boucles infinies lors de la sérialisation JSON
    private User signer;
}
