package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public enum KemAlgorithm {
    @SerializedName("CMCE/mceliece348864")
    CMCE_MCELIECE348864("CMCE/mceliece348864", "CMCE", "BCPQC", CMCEParameterSpec.mceliece348864),
    @SerializedName("CMCE/mceliece348864f")
    CMCE_MCELIECE348864F("CMCE/mceliece348864f", "CMCE", "BCPQC", CMCEParameterSpec.mceliece348864f),
    @SerializedName("CMCE/mceliece460896")
    CMCE_MCELIECE460896("CMCE/mceliece460896", "CMCE", "BCPQC", CMCEParameterSpec.mceliece460896),
    @SerializedName("CMCE/mceliece460896f")
    CMCE_MCELIECE460896F("CMCE/mceliece460896f", "CMCE", "BCPQC", CMCEParameterSpec.mceliece460896f),
    @SerializedName("CMCE/mceliece6688128")
    CMCE_MCELIECE6688128("CMCE/mceliece6688128", "CMCE", "BCPQC", CMCEParameterSpec.mceliece6688128),
    @SerializedName("CMCE/mceliece6688128f")
    CMCE_MCELIECE6688128F("CMCE/mceliece6688128f", "CMCE", "BCPQC", CMCEParameterSpec.mceliece6688128f),
    @SerializedName("CMCE/mceliece6960119")
    CMCE_MCELIECE6960119("CMCE/mceliece6960119", "CMCE", "BCPQC", CMCEParameterSpec.mceliece6960119),
    @SerializedName("CMCE/mceliece6960119f")
    CMCE_MCELIECE6960119F("CMCE/mceliece6960119f", "CMCE", "BCPQC", CMCEParameterSpec.mceliece6960119f),
    @SerializedName("CMCE/mceliece8192128")
    CMCE_MCELIECE8192128("CMCE/mceliece8192128", "CMCE", "BCPQC", CMCEParameterSpec.mceliece8192128),
    @SerializedName("CMCE/mceliece8192128f")
    CMCE_MCELIECE8192128F("CMCE/mceliece8192128f", "CMCE", "BCPQC", CMCEParameterSpec.mceliece8192128f),
    @SerializedName("ML-KEM-512")
    ML_KEM_512("ML-KEM-512", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_512),
    @SerializedName("ML-KEM-768")
    ML_KEM_768("ML-KEM-768", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_768),
    @SerializedName("ML-KEM-1024")
    ML_KEM_1024("ML-KEM-1024", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_1024);

    private final String identifier;
    private final String jcaName;
    private final String provider;
    private final AlgorithmParameterSpec parameterSpec;

    KemAlgorithm(String identifier, String jcaName, String provider, AlgorithmParameterSpec parameterSpec) {
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

    public static KemAlgorithm fromIdentifier(String value) {
        String normalized = withoutKeyRole(value);
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.identifier.equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported KEM algorithm: " + value));
    }

    private static String withoutKeyRole(String value) {
        if (value == null) {
            throw new IllegalArgumentException("KEM algorithm is missing");
        }
        String normalized = value.trim();
        String lower = normalized.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith("/public")) {
            return normalized.substring(0, normalized.length() - 7);
        }
        if (lower.endsWith("/private")) {
            return normalized.substring(0, normalized.length() - 8);
        }
        return normalized;
    }
}
