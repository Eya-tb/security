package com.example.security.repositories;

import com.example.security.entities.Document;
import com.example.security.entities.Signature;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SignatureRepository extends JpaRepository<Signature, Long> {
    Signature findByDocument(Document document); // Trouver la signature d'un document
}
