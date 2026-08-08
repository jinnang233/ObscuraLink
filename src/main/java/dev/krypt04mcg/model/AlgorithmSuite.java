package dev.krypt04mcg.model;

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;

public record AlgorithmSuite(String kem, String signature, String aead, String hkdf) {
    public static final String HKDF_SHA256 = "HKDF-SHA256";

    public static AlgorithmSuite defaults() {
        return of(KemAlgorithm.CMCE_MCELIECE348864, SignatureAlgorithm.FALCON_512,
                AeadAlgorithm.AES_256_GCM);
    }

    public static AlgorithmSuite of(KemAlgorithm kem, SignatureAlgorithm signature, AeadAlgorithm aead) {
        return new AlgorithmSuite(kem.identifier(), signature.identifier(), aead.identifier(), HKDF_SHA256);
    }
}
