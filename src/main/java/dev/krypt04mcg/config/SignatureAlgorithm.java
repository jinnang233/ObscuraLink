package dev.krypt04mcg.config;

import com.google.gson.annotations.SerializedName;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
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
    ML_DSA_87("ML-DSA-87", "ML-DSA", "BC", MLDSAParameterSpec.ml_dsa_87),
    @SerializedName("SLH-DSA-SHA2-128F")
    SLH_DSA_SHA2_128F("SLH-DSA-SHA2-128F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_128f),
    @SerializedName("SLH-DSA-SHA2-128S")
    SLH_DSA_SHA2_128S("SLH-DSA-SHA2-128S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_128s),
    @SerializedName("SLH-DSA-SHA2-192F")
    SLH_DSA_SHA2_192F("SLH-DSA-SHA2-192F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_192f),
    @SerializedName("SLH-DSA-SHA2-192S")
    SLH_DSA_SHA2_192S("SLH-DSA-SHA2-192S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_192s),
    @SerializedName("SLH-DSA-SHA2-256F")
    SLH_DSA_SHA2_256F("SLH-DSA-SHA2-256F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_256f),
    @SerializedName("SLH-DSA-SHA2-256S")
    SLH_DSA_SHA2_256S("SLH-DSA-SHA2-256S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_sha2_256s),
    @SerializedName("SLH-DSA-SHAKE-128F")
    SLH_DSA_SHAKE_128F("SLH-DSA-SHAKE-128F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_128f),
    @SerializedName("SLH-DSA-SHAKE-128S")
    SLH_DSA_SHAKE_128S("SLH-DSA-SHAKE-128S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_128s),
    @SerializedName("SLH-DSA-SHAKE-192F")
    SLH_DSA_SHAKE_192F("SLH-DSA-SHAKE-192F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_192f),
    @SerializedName("SLH-DSA-SHAKE-192S")
    SLH_DSA_SHAKE_192S("SLH-DSA-SHAKE-192S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_192s),
    @SerializedName("SLH-DSA-SHAKE-256F")
    SLH_DSA_SHAKE_256F("SLH-DSA-SHAKE-256F", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_256f),
    @SerializedName("SLH-DSA-SHAKE-256S")
    SLH_DSA_SHAKE_256S("SLH-DSA-SHAKE-256S", "SLH-DSA", "BC", SLHDSAParameterSpec.slh_dsa_shake_256s),
    @SerializedName("SLH-DSA-SHA2-128F-WITH-SHA256")
    SLH_DSA_SHA2_128F_WITH_SHA256("SLH-DSA-SHA2-128F-WITH-SHA256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256),
    @SerializedName("SLH-DSA-SHA2-128S-WITH-SHA256")
    SLH_DSA_SHA2_128S_WITH_SHA256("SLH-DSA-SHA2-128S-WITH-SHA256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256),
    @SerializedName("SLH-DSA-SHA2-192F-WITH-SHA512")
    SLH_DSA_SHA2_192F_WITH_SHA512("SLH-DSA-SHA2-192F-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512),
    @SerializedName("SLH-DSA-SHA2-192S-WITH-SHA512")
    SLH_DSA_SHA2_192S_WITH_SHA512("SLH-DSA-SHA2-192S-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512),
    @SerializedName("SLH-DSA-SHA2-256F-WITH-SHA512")
    SLH_DSA_SHA2_256F_WITH_SHA512("SLH-DSA-SHA2-256F-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512),
    @SerializedName("SLH-DSA-SHA2-256S-WITH-SHA512")
    SLH_DSA_SHA2_256S_WITH_SHA512("SLH-DSA-SHA2-256S-WITH-SHA512", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512),
    @SerializedName("SLH-DSA-SHAKE-128F-WITH-SHAKE128")
    SLH_DSA_SHAKE_128F_WITH_SHAKE128("SLH-DSA-SHAKE-128F-WITH-SHAKE128", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128),
    @SerializedName("SLH-DSA-SHAKE-128S-WITH-SHAKE128")
    SLH_DSA_SHAKE_128S_WITH_SHAKE128("SLH-DSA-SHAKE-128S-WITH-SHAKE128", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128),
    @SerializedName("SLH-DSA-SHAKE-192F-WITH-SHAKE256")
    SLH_DSA_SHAKE_192F_WITH_SHAKE256("SLH-DSA-SHAKE-192F-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-192S-WITH-SHAKE256")
    SLH_DSA_SHAKE_192S_WITH_SHAKE256("SLH-DSA-SHAKE-192S-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-256F-WITH-SHAKE256")
    SLH_DSA_SHAKE_256F_WITH_SHAKE256("SLH-DSA-SHAKE-256F-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256),
    @SerializedName("SLH-DSA-SHAKE-256S-WITH-SHAKE256")
    SLH_DSA_SHAKE_256S_WITH_SHAKE256("SLH-DSA-SHAKE-256S-WITH-SHAKE256", "HASH-SLH-DSA", "BC",
            SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256);

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
