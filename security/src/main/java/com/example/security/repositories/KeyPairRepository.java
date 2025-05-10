package com.example.security.repositories;

import com.example.security.entities.KeyPair;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface KeyPairRepository extends JpaRepository<KeyPair, Long> {
    Optional<KeyPair> findByUserId(Long userId);
}