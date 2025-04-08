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

    @Column(nullable = false)
    @NotBlank(message = "Password is mandatory")

    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role; // ADMIN or USER

    @OneToMany(mappedBy = "signer", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Signature> signatures; // ✅ Changed to List

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private List<Document> documents; // ✅ Changed to List

    @Column(nullable = false, columnDefinition = "TEXT")
    private String privateKey; // Stored in Base64

    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey; // Stored in Base64
}
