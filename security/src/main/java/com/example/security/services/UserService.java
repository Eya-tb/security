package com.example.security.services;

import com.example.security.entities.Role;
import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // 🔹 Inscription d'un utilisateur avec génération des clés RSA
    public User registerUser(User user) throws Exception {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Cet email est déjà utilisé !");
        }

        // Générer les clés RSA pour l'utilisateur
        KeyPair keyPair = generateKeyPair();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // Stocker les clés générées
        user.setPrivateKey(privateKeyBase64);
        user.setPublicKey(publicKeyBase64);

        // Définir le rôle de l'utilisateur (USER par défaut)
        user.setRole(Role.USER);

        return userRepository.save(user);
    }

    // 🔹 Générer une paire de clés RSA
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // 🔹 Récupérer un utilisateur par son ID
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé !"));
    }

    // 🔹 Récupérer tous les utilisateurs
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
