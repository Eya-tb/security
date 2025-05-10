package com.example.security.repositories;

import com.example.security.entities.RecoveryCode;
import com.example.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {
    Optional<RecoveryCode> findFirstByUserAndUsedOrderByCreatedAtDesc(User user, boolean used);
    void deleteByUserAndUsed(User user, boolean used);
}
