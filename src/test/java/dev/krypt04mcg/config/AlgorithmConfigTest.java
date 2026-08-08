package dev.krypt04mcg.config;

import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class AlgorithmConfigTest {
    @Test
    void existingStringConfigValuesMigrateToEnumSelections() {
        String json = """
                {
                  "kemAlgorithm": "CMCE/mceliece348864",
                  "signatureAlgorithm": "Falcon-512",
                  "aeadAlgorithm": "AES-256-GCM"
                }
                """;

        Krypt04McgConfig config = JsonSupport.prettyGson().fromJson(json, Krypt04McgConfig.class);

        assertEquals(KemAlgorithm.CMCE_MCELIECE348864, config.kemAlgorithm);
        assertEquals(SignatureAlgorithm.FALCON_512, config.signatureAlgorithm);
        assertEquals(AeadAlgorithm.AES_256_GCM, config.aeadAlgorithm);
    }

    @Test
    void everyKeyIdentifierResolvesWithStoredKeyRoleSuffixes() {
        for (KemAlgorithm algorithm : KemAlgorithm.values()) {
            assertEquals(algorithm, KemAlgorithm.fromIdentifier(algorithm.identifier() + "/public"));
            assertEquals(algorithm, KemAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));
        }
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/public"));
            assertEquals(algorithm, SignatureAlgorithm.fromIdentifier(algorithm.identifier() + "/private"));
        }
    }
}
