package com.example.security.services;

import com.example.security.entities.Role;
import com.example.security.entities.User;
import com.example.security.repositories.UserRepository;
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
    private final BackupKeyService backupKeyService;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder,
                       LoginAttemptService loginAttemptService, MfaService mfaService,
                       PasswordValidationService passwordValidationService,
                       KeyVaultService keyVaultService,
                       BackupKeyService backupKeyService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.mfaService = mfaService;
        this.passwordValidationService = passwordValidationService;
        this.keyVaultService = keyVaultService;
        this.backupKeyService = backupKeyService;
    }

    // 🔐 Enregistrement utilisateur avec génération + double chiffrement de la clé privée
    public User registerUser(User user, String password) throws Exception {
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Cet email est déjà utilisé !");
        }

        // 🔒 Vérification des règles de sécurité du mot de passe
        List<String> passwordErrors = passwordValidationService.validatePassword(user.getPassword());
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Mot de passe invalide : " + String.join(", ", passwordErrors));
        }

        // 🔑 Générer la paire de clés RSA
        KeyPair keyPair = generateKeyPair();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        // 🔐 Chiffrer la clé privée avec le mot de passe utilisateur
        String encryptedPrivateKey = keyVaultService.encryptPrivateKey(privateKeyBase64, password);
        user.setPrivateKey(encryptedPrivateKey);

        // 🛡️ Chiffrer la clé privée avec la clé maîtresse pour backup
        String masterKey = backupKeyService.getMasterBackupKey();
        String backupEncryptedKey = keyVaultService.encryptPrivateKey(privateKeyBase64, masterKey);
        user.setBackupPrivateKey(backupEncryptedKey);

        // 🧂 Hasher le mot de passe
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // 📤 Stocker la clé publique
        user.setPublicKey(publicKeyBase64);
        user.setRole(Role.USER);

        return userRepository.save(user);
    }

    // 🔁 Changement de mot de passe avec récupération de la clé privée
    public void changePassword(Long userId, String oldPassword, String newPassword) throws Exception {
        User user = getUserById(userId);

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new RuntimeException("Ancien mot de passe incorrect");
        }

        List<String> passwordErrors = passwordValidationService.validatePassword(newPassword);
        if (!passwordErrors.isEmpty()) {
            throw new RuntimeException("Nouveau mot de passe invalide : " + String.join(", ", passwordErrors));
        }

        // 🔓 Déchiffrer la clé privée avec l'ancien mot de passe
        String privateKeyBase64 = keyVaultService.decryptPrivateKey(user.getPrivateKey(), oldPassword);

        // 🔐 Rechiffrer avec le nouveau mot de passe
        String newEncryptedPrivateKey = keyVaultService.encryptPrivateKey(privateKeyBase64, newPassword);

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPrivateKey(newEncryptedPrivateKey);
        userRepository.save(user);
    }
    public void recoverUserKeys(String email, String newPassword) throws Exception {
        User user = userRepository.findByEmail(email);
        if (user == null) throw new RuntimeException("User not found");

        // 1. Récupérer clé maîtresse depuis Vault
        String masterKey = backupKeyService.getMasterBackupKey();

        // 2. Déchiffrer la clé backup avec la clé maîtresse
        String decryptedPrivateKey = keyVaultService.decryptPrivateKey(
                user.getBackupPrivateKey(),
                masterKey
        );

        // 3. Rechiffrer avec le nouveau mot de passe
        String reEncryptedKey = keyVaultService.encryptPrivateKey(
                decryptedPrivateKey,
                newPassword
        );

        // 4. Mettre à jour
        user.setPrivateKey(reEncryptedKey);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    // 🛠 Méthodes utilitaires
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé !"));
    }

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

    // 🔐 MFA (2FA) fonctions
    public void enableMfa(Long userId) {
        User user = getUserById(userId);
        String secret = mfaService.generateSecret();
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
        if (user.isMfaEnabled() && user.getMfaSecret() != null) {
            return mfaService.verifyCode(user.getMfaSecret(), code);
        } else if (user.getMfaTempSecret() != null) {
            return mfaService.verifyCode(user.getMfaTempSecret(), code);
        }
        return false;
    }

    public void confirmMfaSetup(Long userId) {
        User user = getUserById(userId);
        if (user.getMfaTempSecret() != null) {
            user.setMfaSecret(user.getMfaTempSecret());
            user.setMfaTempSecret(null);
        }
        user.setMfaEnabled(true);
        userRepository.save(user);
    }

    public boolean verifyMfaCode(Long userId, String code) {
        User user = getUserById(userId);
        if (user.getMfaSecret() == null) return false;
        return mfaService.verifyCode(user.getMfaSecret(), code);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
