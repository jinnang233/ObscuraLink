package dev.krypt04mcg.service;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class KeyTrustService {
    private final Path trustFile;
    private final Gson gson = JsonSupport.prettyGson();
    private final SensitiveFileStore sensitiveFiles;

    public KeyTrustService(Path root) {
        this.trustFile = root.resolve("keys").resolve("trust.json");
        this.sensitiveFiles = new SensitiveFileStore(root);
    }

    public synchronized TrustState trustState(String player, PublicIdentity identity) throws IOException {
        TrustBinding stored = readTrust().get(normalize(player));
        if (stored == null) {
            return identity == null ? TrustState.UNTRUSTED : TrustState.TOFU_TRUSTED;
        }
        if (identity != null && stored.hasFingerprints() && !stored.matches(identity)) {
            return TrustState.DISTRUSTED;
        }
        if (stored.state() == TrustState.VERIFIED && !stored.hasFingerprints()) {
            return identity == null ? TrustState.UNTRUSTED : TrustState.TOFU_TRUSTED;
        }
        return stored.state();
    }

    public synchronized void markTofuTrusted(String player, PublicIdentity identity) throws IOException {
        setTrustState(player, TrustState.TOFU_TRUSTED, identity);
    }

    public synchronized void rememberTofu(String player, PublicIdentity identity) throws IOException {
        Map<String, TrustBinding> trust = readTrust();
        if (trust.putIfAbsent(normalize(player), TrustBinding.of(TrustState.TOFU_TRUSTED, identity)) == null) {
            sensitiveFiles.writeString(trustFile, gson.toJson(trust));
        }
    }

    public synchronized void markVerified(String player, PublicIdentity identity) throws IOException {
        if (identity == null) {
            throw new IOException("A verified trust record requires both public keys");
        }
        setTrustState(player, TrustState.VERIFIED, identity);
    }

    public synchronized void markDistrusted(String player, PublicIdentity identity) throws IOException {
        setTrustState(player, TrustState.DISTRUSTED, identity);
    }

    public boolean fingerprintMatches(PublicIdentity identity, String fingerprintPair) {
        if (identity == null || fingerprintPair == null) {
            return false;
        }
        String expected = fingerprintPair(identity).toLowerCase(Locale.ROOT);
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] suppliedBytes = fingerprintPair.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expectedBytes, suppliedBytes);
    }

    public static String fingerprintPair(PublicIdentity identity) {
        return identity.kemPublicKey().fingerprint() + ":" + identity.signaturePublicKey().fingerprint();
    }

    private void setTrustState(String player, TrustState state, PublicIdentity identity) throws IOException {
        Map<String, TrustBinding> trust = readTrust();
        trust.put(normalize(player), TrustBinding.of(state, identity));
        sensitiveFiles.writeString(trustFile, gson.toJson(trust));
    }

    private Map<String, TrustBinding> readTrust() throws IOException {
        if (!Files.exists(trustFile)) {
            return new HashMap<>();
        }
        try {
            boolean legacyPlaintext = !SensitiveFileStore.isEncrypted(trustFile);
            JsonElement parsed = JsonParser.parseString(sensitiveFiles.readString(trustFile));
            if (!parsed.isJsonObject()) {
                throw new IOException("Trust database is not a JSON object");
            }
            Map<String, TrustBinding> trust = new HashMap<>();
            for (Map.Entry<String, JsonElement> entry : parsed.getAsJsonObject().entrySet()) {
                TrustBinding binding = parseBinding(entry.getValue());
                if (binding != null && binding.state() != null) {
                    trust.put(normalize(entry.getKey()), binding);
                }
            }
            if (legacyPlaintext) {
                sensitiveFiles.writeString(trustFile, gson.toJson(trust));
            }
            return trust;
        } catch (RuntimeException e) {
            throw new IOException("Trust database is invalid", e);
        }
    }

    private TrustBinding parseBinding(JsonElement value) {
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            TrustState legacy = TrustState.valueOf(value.getAsString());
            return new TrustBinding(legacy == TrustState.VERIFIED ? TrustState.TOFU_TRUSTED : legacy, null, null);
        }
        return gson.fromJson(value, TrustBinding.class);
    }

    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }

    private record TrustBinding(TrustState state, String kemFingerprint, String signatureFingerprint) {
        private static TrustBinding of(TrustState state, PublicIdentity identity) {
            return identity == null
                    ? new TrustBinding(state, null, null)
                    : new TrustBinding(state, identity.kemPublicKey().fingerprint(),
                    identity.signaturePublicKey().fingerprint());
        }

        private boolean hasFingerprints() {
            return kemFingerprint != null && signatureFingerprint != null;
        }

        private boolean matches(PublicIdentity identity) {
            return kemFingerprint.equalsIgnoreCase(identity.kemPublicKey().fingerprint())
                    && signatureFingerprint.equalsIgnoreCase(identity.signaturePublicKey().fingerprint());
        }
    }
}
