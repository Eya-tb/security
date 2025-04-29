package com.example.security.repositories;

import com.example.security.entities.Document;
import com.example.security.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
    List<com.example.security.entities.Document> findByUser(User user); // Trouver tous les documents d'un utilisateur

    Page<Document> findAll(Pageable pageable);;
    Page<Document> findByUser(User user, Pageable pageable);

    @Query("SELECT d FROM Document d WHERE LOWER(d.name) LIKE LOWER(CONCAT('%', :query, '%'))")
    Page<Document> searchByName(@Param("query") String query, Pageable pageable);
}
