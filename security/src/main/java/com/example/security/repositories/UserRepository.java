package com.example.security.repositories;

import com.example.security.entities.Role;
import com.example.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email); // Trouver un utilisateur par email

    boolean existsByEmail(String email); // Vérifier si un email est déjà utilisé

    List<User> findByRole(Role role); // Trouver tous les utilisateurs ayant un rôle spécifique
}
