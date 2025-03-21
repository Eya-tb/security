package com.example.security.repositories;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
    List<com.example.security.entities.Document> findByUser(User user); // Trouver tous les documents d'un utilisateur
}
