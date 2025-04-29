package com.example.security.services;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class PasswordValidationService {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[^A-Za-z0-9]");

    public List<String> validatePassword(String password) {
        List<String> validationErrors = new ArrayList<>();

        // Vérification de la longueur
        if (password == null || password.length() < MIN_LENGTH) {
            validationErrors.add("Le mot de passe doit contenir au moins " + MIN_LENGTH + " caractères");
        }

        if (password != null && password.length() > MAX_LENGTH) {
            validationErrors.add("Le mot de passe ne doit pas dépasser " + MAX_LENGTH + " caractères");
        }

        if (password != null) {
            // Vérification des caractères requis
            if (!UPPERCASE_PATTERN.matcher(password).find()) {
                validationErrors.add("Le mot de passe doit contenir au moins une lettre majuscule");
            }

            if (!LOWERCASE_PATTERN.matcher(password).find()) {
                validationErrors.add("Le mot de passe doit contenir au moins une lettre minuscule");
            }

            if (!DIGIT_PATTERN.matcher(password).find()) {
                validationErrors.add("Le mot de passe doit contenir au moins un chiffre");
            }

            if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
                validationErrors.add("Le mot de passe doit contenir au moins un caractère spécial");
            }
        }

        return validationErrors;
    }

    public boolean isPasswordValid(String password) {
        return validatePassword(password).isEmpty();
    }
}