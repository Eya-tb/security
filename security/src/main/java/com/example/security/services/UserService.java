package com.example.security.services;

import com.example.security.entities.Role;
import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
import com.example.security.services.KeyVaultService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;
    private final MfaService mfaService;
    private final PasswordValidationService passwordValidationService;
    private final KeyVaultService keyVaultService;
    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder,
                       LoginAttemptService loginAttemptService, MfaService mfaService, PasswordValidationService passwordValidationService, KeyVaultService keyVaultService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.mfaService = mfaService;
        this.passwordValidationService = passwordValidationService;
        this.keyVaultService = keyVaultService;
    }

    // 🔹 Inscription d'un utilisateur avec génération des clés RSA
    public User registerUser(User user, String password) throws Exception {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Cet email est déjà utilisé !");
        }

        // Validation de la complexité du mot de passe
        List<String> passwordErrors = passwordValidationService.validatePassword(user.getPassword());
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Mot de passe invalide : " + String.join(", ", passwordErrors));
        }

        // Hacher le mot de passe avant enregistrement
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Générer les clés RSA pour l'utilisateur
        KeyPair keyPair = generateKeyPair();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // Chiffrer la clé privée avec le mot de passe
        String encryptedPrivateKey = keyVaultService.encryptPrivateKey(privateKeyBase64, password);
        // Stocker les clés générées
        user.setPrivateKey(encryptedPrivateKey);
        user.setPublicKey(publicKeyBase64);

        // Définir le rôle de l'utilisateur (USER par défaut)
        user.setRole(Role.USER);

        return userRepository.save(user);
    }

    //  une méthode pour changer le mot de passe en vérifiant la politique
    public void changePassword(Long userId, String oldPassword, String newPassword) throws Exception{
        User user = getUserById(userId);

        // Vérifier l'ancien mot de passe
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new RuntimeException("Ancien mot de passe incorrect");
        }
        // Valider le nouveau mot de passe
        List<String> passwordErrors = passwordValidationService.validatePassword(newPassword);
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Nouveau mot de passe invalide : " + String.join(", ", passwordErrors));
        }
        // Décrypter la clé privée avec l'ancien mot de passe
        String privateKeyBase64 = keyVaultService.decryptPrivateKey(user.getPrivateKey(), oldPassword);

        // La rechiffrer avec le nouveau mot de passe
        String newEncryptedPrivateKey = keyVaultService.encryptPrivateKey(privateKeyBase64, newPassword);

        // Mettre à jour le mot de passe
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPrivateKey(newEncryptedPrivateKey);
        userRepository.save(user);
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

    public int getFailedAttempts(String email) {
        return loginAttemptService.getFailedAttempts(email);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public void updateUserRole(Long userId, Role role) {
        User user = getUserById(userId);
        user.setRole(role);
        userRepository.save(user);
    }

    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new RuntimeException("Utilisateur non trouvé !");
        }
        userRepository.deleteById(userId);
    }

    // Méthodes pour la gestion de l'authentification à deux facteurs (MFA)
    public void enableMfa(Long userId) {
        User user = getUserById(userId);
        String secret = mfaService.generateSecret();
        // Stockage temporaire du secret avant confirmation
        user.setMfaTempSecret(secret);
        userRepository.save(user);
    }

    public void disableMfa(Long userId) {
        User user = getUserById(userId);
        user.setMfaSecret(null);
        user.setMfaTempSecret(null);
        user.setMfaEnabled(false);
        userRepository.save(user);
    }

    public String generateQrCodeForUser(Long userId) {
        User user = getUserById(userId);
        if (user.getMfaTempSecret() == null) {
            String secret = mfaService.generateSecret();
            user.setMfaTempSecret(secret);
            userRepository.save(user);
        }
        return mfaService.getQrCodeImageUri(user.getMfaTempSecret(), user.getEmail());
    }

    public boolean verifyCode(Long userId, String code) {
        User user = getUserById(userId);

        // Vérifier d'abord avec le secret final s'il existe
        if (user.isMfaEnabled() && user.getMfaSecret() != null) {
            return mfaService.verifyCode(user.getMfaSecret(), code);
        }
        // Sinon vérifier avec le secret temporaire
        else if (user.getMfaTempSecret() != null) {
            return mfaService.verifyCode(user.getMfaTempSecret(), code);
        }

        return false;
    }

    public void confirmMfaSetup(Long userId) {
        User user = getUserById(userId);

        // Transférer le secret temporaire vers le secret final
        if (user.getMfaTempSecret() != null) {
            user.setMfaSecret(user.getMfaTempSecret());
            user.setMfaTempSecret(null);
        }

        user.setMfaEnabled(true);
        userRepository.save(user);
    }

    // Vérification MFA pour l'authentification
    public boolean verifyMfaCode(Long userId, String code) {
        User user = getUserById(userId);
        if (user.getMfaSecret() == null) {
            return false;
        }

        return mfaService.verifyCode(user.getMfaSecret(), code);
    }

    // Récupérer un utilisateur par son email
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}