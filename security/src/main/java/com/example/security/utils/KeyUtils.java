package com.example.security.utils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtils {
    public static PrivateKey loadPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey loadPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PublicKey extractPublicKey(PrivateKey privateKey) throws Exception {
        if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    rsaPrivateKey.getModulus(),
                    BigInteger.valueOf(65537)
            );
            return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        }
        throw new IllegalArgumentException("Unsupported key type");
    }
}
