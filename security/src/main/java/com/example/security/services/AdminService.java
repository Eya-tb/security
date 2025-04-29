package com.example.security.services;

import com.example.security.entities.Document;
import com.example.security.entities.Role;
import com.example.security.entities.User;
import com.example.security.repositories.DocumentRepository;
import com.example.security.repositories.SignatureRepository;
import com.example.security.repositories.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AdminService {
    private final UserRepository userRepository;
    private final SignatureRepository signatureRepository;
    private final DocumentRepository documentRepository;

    public AdminService(UserRepository userRepository, SignatureRepository signatureRepository, DocumentRepository documentRepository) {
        this.userRepository = userRepository;
        this.signatureRepository = signatureRepository;
        this.documentRepository = documentRepository;
    }

    // 🔹 Récupérer tous les utilisateurs
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // 🔹 Supprimer un utilisateur
    @Transactional
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new RuntimeException("Utilisateur introuvable !");
        }

        // Supprimer d'abord les signatures associées à l'utilisateur
        signatureRepository.deleteBySignerId(userId);

        // Ensuite supprimer l'utilisateur
        userRepository.deleteById(userId);
    }

    // 🔹 Modifier le rôle d'un utilisateur
    public void updateUserRole(Long userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable !"));

        user.setRole(role);
        userRepository.save(user);
    }

    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable avec l'ID: " + id));
    }

    // 🔹 Récupérer tous les documents avec pagination
    public Page<Document> getAllDocuments(int page, int size, String sort, String direction) {
        Sort.Direction sortDirection = Sort.Direction.fromString(direction);
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortDirection, sort));
        return documentRepository.findAll(pageable);
    }
}