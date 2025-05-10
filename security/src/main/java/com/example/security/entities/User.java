package com.example.security.entities;


import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;




    @Column(nullable = false, length = 255) // Ou VARCHAR(255) en SQL
    @NotBlank(message = "Password is mandatory")
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role; // ADMIN or USER

    @OneToMany(mappedBy = "signer", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Signature> signatures; // ✅ Changed to List

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true , fetch = FetchType.LAZY)
    @JsonManagedReference
    private List<Document> documents; // ✅ Changed to List

    @Column(nullable = false, columnDefinition = "TEXT")
    private String privateKey; // Stored in Base64

    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey; // Stored in Base64



    @Column(name = "mfa_enabled")
    private boolean mfaEnabled = false;

    @Column(name = "mfa_secret")
    private String mfaSecret;


    @Column(name = "mfa_temp_secret")
    private String mfaTempSecret;

    // Dans la classe User


    @Column(length = 2048)
    private String backupPrivateKey;



}
