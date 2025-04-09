package com.example.security.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Entity
@Table(name = "documents")
@Getter @Setter @NoArgsConstructor
public class Document {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String type;

    @Lob
    @Column(columnDefinition = "LONGBLOB", nullable = false)
    private byte[] content;

    @Column(nullable = false, length = 64)
    private String fileHash; // SHA-256

    @OneToOne(mappedBy = "document", cascade = CascadeType.ALL, orphanRemoval = true)
    private Signature signature;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference
    private User user;

    @PrePersist
    public void calculateHash() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(this.content);
        this.fileHash = bytesToHex(hashBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}