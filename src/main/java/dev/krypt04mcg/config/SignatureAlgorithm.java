package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public enum SignatureAlgorithm {
    @SerializedName("Falcon-512")
    FALCON_512("Falcon-512", "Falcon", "BCPQC", FalconParameterSpec.falcon_512),
    @SerializedName("Falcon-1024")
    FALCON_1024("Falcon-1024", "Falcon", "BCPQC", FalconParameterSpec.falcon_1024),
    @SerializedName("ML-DSA-44")
    ML_DSA_44("ML-DSA-44", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_44),
    @SerializedName("ML-DSA-65")
    ML_DSA_65("ML-DSA-65", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_65),
    @SerializedName("ML-DSA-87")
    ML_DSA_87("ML-DSA-87", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_87);

    private final String identifier;
    private final String jcaName;
    private final String provider;
    private final AlgorithmParameterSpec parameterSpec;

    SignatureAlgorithm(String identifier, String jcaName, String provider, AlgorithmParameterSpec parameterSpec) {
        this.identifier = identifier;
        this.jcaName = jcaName;
        this.provider = provider;
        this.parameterSpec = parameterSpec;
    }

    public String identifier() {
        return identifier;
    }

    public String jcaName() {
        return jcaName;
    }

    public String provider() {
        return provider;
    }

    public AlgorithmParameterSpec parameterSpec() {
        return parameterSpec;
    }

    public static SignatureAlgorithm fromIdentifier(String value) {
        String normalized = withoutKeyRole(value);
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.identifier.equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported signature algorithm: " + value));
    }

    private static String withoutKeyRole(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Signature algorithm is missing");
        }
        String normalized = value.trim();
        if (normalized.toLowerCase(java.util.Locale.ROOT).endsWith("/public")) {
            return normalized.substring(0, normalized.length() - 7);
        }
        if (normalized.toLowerCase(java.util.Locale.ROOT).endsWith("/private")) {
            return normalized.substring(0, normalized.length() - 8);
        }
        return normalized;
    }
}
