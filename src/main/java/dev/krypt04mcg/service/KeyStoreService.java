package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.SecureFiles;
import dev.krypt04mcg.util.SensitiveFileStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class KeyStoreService {
    private final Path root;
    private final Path keysDir;
    private final Gson gson = JsonSupport.prettyGson();
    private final CryptoService cryptoService;
    private final SensitiveFileStore sensitiveFiles;
    private LocalKeyMaterial local;

    public KeyStoreService(Path root, CryptoService cryptoService) {
        this.root = root;
        this.keysDir = root.resolve("keys");
        this.cryptoService = cryptoService;
        this.sensitiveFiles = new SensitiveFileStore(root);
    }

    public void init(String owner, String uuid) throws IOException, CryptoException {
        init(owner, uuid, KemAlgorithm.CMCE_MCELIECE348864, SignatureAlgorithm.FALCON_512);
    }

    public void init(String owner, String uuid, KemAlgorithm kemAlgorithm, SignatureAlgorithm signatureAlgorithm)
            throws IOException, CryptoException {
        SecureFiles.createPrivateDirectories(keysDir.resolve("private"));
        SecureFiles.createPrivateDirectories(keysDir.resolve("public"));
        SecureFiles.createPrivateDirectories(root.resolve("sessions"));
        SecureFiles.createPrivateDirectories(root.resolve("cache"));
        Path localFile = keysDir.resolve("private").resolve("local.json");
        String stableUuid = uuid == null || uuid.isBlank()
                ? UUID.nameUUIDFromBytes(("OfflinePlayer:" + owner).getBytes(StandardCharsets.UTF_8)).toString()
                : uuid;
        if (Files.exists(localFile)) {
            LocalKeyMaterial loaded = gson.fromJson(sensitiveFiles.readString(localFile), LocalKeyMaterial.class);
            local = cryptoService.validateLocalKeyMaterial(loaded, owner, stableUuid);
            writeLocal(localFile, local);
            exportOwnPublicFile();
            return;
        }
        local = cryptoService.generateLocalKeys(owner, stableUuid, kemAlgorithm, signatureAlgorithm);
        writeLocal(localFile, local);
        exportOwnPublicFile();
    }

    public LocalKeyMaterial local() {
        if (local == null) {
            throw new IllegalStateException("Key store has not been initialized");
        }
        return local;
    }

    public PublicIdentity ownPublicIdentity() {
        LocalKeyMaterial material = local();
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }

    public PublicKeyExport exportOwnPublicFile() throws IOException {
        PublicIdentity identity = ownPublicIdentity();
        write(keysDir.resolve("public").resolve("self-public.json"), identity);
        Path exportDir = root.resolve("export");
        Path exportFile = exportDir.resolve("self-public.json");
        write(exportFile, identity);
        return new PublicKeyExport(exportFile.toAbsolutePath().normalize(), identity);
    }

    public String regenerationFingerprint() {
        return local().kemPublicKey().fingerprint();
    }

    public LocalKeyMaterial regenerate(String fingerprint, KemAlgorithm kemAlgorithm,
                                       SignatureAlgorithm signatureAlgorithm) throws IOException, CryptoException {
        if (!fingerprintMatches(regenerationFingerprint(), fingerprint)) {
            throw new CryptoException("Regeneration fingerprint does not match the current local key");
        }
        LocalKeyMaterial current = local();
        LocalKeyMaterial regenerated = cryptoService.generateLocalKeys(current.kemPublicKey().owner(),
                current.kemPublicKey().uuid(), kemAlgorithm, signatureAlgorithm);
        writeLocal(keysDir.resolve("private").resolve("local.json"), regenerated);
        local = regenerated;
        exportOwnPublicFile();
        return regenerated;
    }

    public PublicIdentity importPublicIdentity(String player, String dataOrFile) throws IOException {
        String json = readImportData(dataOrFile);
        PublicIdentity incoming = parsePublicIdentity(json);
        if (incoming.owner() == null || !incoming.owner().equalsIgnoreCase(player)) {
            throw new IOException("Imported public key owner does not match player " + player);
        }
        String normalized = normalize(player);
        Path path = keysDir.resolve("public").resolve(normalized + ".json");
        if (Files.exists(path)) {
            PublicIdentity existing = readPublicIdentity(path);
            if (!sameIdentity(existing, incoming)) {
                throw new IOException("TOFU violation: public key for " + player + " changed; refusing to overwrite");
            }
            return existing;
        }
        Optional<PublicIdentity> existingByOwner = findPublicIdentity(player);
        if (existingByOwner.isPresent()) {
            if (!sameIdentity(existingByOwner.get(), incoming)) {
                throw new IOException("TOFU violation: public key for " + player + " changed; refusing to overwrite");
            }
            write(path, incoming);
            return incoming;
        }
        write(path, incoming);
        return incoming;
    }

    public Optional<PublicIdentity> findPublicIdentity(String player) throws IOException {
        Path path = keysDir.resolve("public").resolve(normalize(player) + ".json");
        if (Files.exists(path)) {
            return Optional.of(readPublicIdentity(path));
        }
        if (!Files.exists(keysDir.resolve("public"))) {
            return Optional.empty();
        }
        try (var stream = Files.list(keysDir.resolve("public"))) {
            for (Path candidate : stream.filter(p -> p.toString().endsWith(".json")).toList()) {
                PublicIdentity identity = readPublicIdentity(candidate);
                if (identity != null && identity.owner() != null && identity.owner().equalsIgnoreCase(player)) {
                    return Optional.of(identity);
                }
            }
        }
        return Optional.empty();
    }

    public List<PublicIdentity> listPublicIdentities() throws IOException {
        List<PublicIdentity> result = new ArrayList<>();
        if (!Files.exists(keysDir.resolve("public"))) {
            return result;
        }
        try (var stream = Files.list(keysDir.resolve("public"))) {
            for (Path path : stream.filter(p -> p.toString().endsWith(".json")).toList()) {
                result.add(readPublicIdentity(path));
            }
        }
        return result;
    }

    public KeyRecord rebuildPublicRecord(String algorithm, String owner, String uuid, String keyData) throws CryptoException {
        return cryptoService.keyRecord(algorithm, owner, uuid, Instant.now(), Base64Url.decode(keyData));
    }

    private String readImportData(String dataOrFile) throws IOException {
        String trimmed = stripWrappingQuotes(dataOrFile.trim());
        Optional<Path> importFile = findImportFile(trimmed);
        if (importFile.isPresent()) {
            return Files.readString(importFile.get(), StandardCharsets.UTF_8);
        }
        if (trimmed.startsWith("{")) {
            return trimmed;
        }
        if (looksLikePath(trimmed)) {
            throw new IOException("Import file was not found or is not readable: " + trimmed);
        }
        try {
            return new String(Base64Url.decode(trimmed), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IOException("Import data is neither a readable file nor valid Base64URL public key data: " + dataOrFile, e);
        }
    }

    private static String stripWrappingQuotes(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')
                    || (first == '\u201c' && last == '\u201d') || (first == '\u2018' && last == '\u2019')) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }

    private Optional<Path> findImportFile(String dataOrFile) {
        Set<Path> candidates = new LinkedHashSet<>();
        try {
            Path input = Path.of(dataOrFile);
            if (input.isAbsolute()) {
                candidates.add(input.normalize());
            } else {
                addImportCandidate(candidates, root, dataOrFile);
                addImportCandidate(candidates, keysDir.resolve("public"), dataOrFile);

                Path baseRoot = accountBaseRoot(root);
                if (!baseRoot.equals(root.toAbsolutePath().normalize())) {
                    addImportCandidate(candidates, baseRoot, dataOrFile);
                    addImportCandidate(candidates, baseRoot.resolve("keys").resolve("public"), dataOrFile);
                    Path gameRoot = gameRoot(baseRoot);
                    if (gameRoot != null) {
                        addImportCandidate(candidates, gameRoot, dataOrFile);
                    }
                }
            }
        } catch (InvalidPathException e) {
            return Optional.empty();
        }
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private static void addImportCandidate(Set<Path> candidates, Path base, String child) {
        try {
            candidates.add(safeResolve(base, child));
        } catch (InvalidPathException ignored) {
            // Try the other explicitly allowed import roots.
        }
    }

    private static Path accountBaseRoot(Path accountRoot) {
        Path normalized = accountRoot.toAbsolutePath().normalize();
        Path accounts = normalized.getParent();
        if (accounts != null && accounts.getFileName() != null
                && "accounts".equalsIgnoreCase(accounts.getFileName().toString())
                && accounts.getParent() != null) {
            return accounts.getParent();
        }
        return normalized;
    }

    private static Path gameRoot(Path baseRoot) {
        Path config = baseRoot.getParent();
        if (config == null || config.getFileName() == null
                || !"config".equalsIgnoreCase(config.getFileName().toString())) {
            return null;
        }
        return config.getParent();
    }

    private static boolean looksLikePath(String value) {
        return value.indexOf('/') >= 0 || value.indexOf('\\') >= 0
                || value.toLowerCase(Locale.ROOT).endsWith(".json")
                || value.startsWith(".")
                || (value.length() >= 2 && Character.isLetter(value.charAt(0)) && value.charAt(1) == ':');
    }

    private static Path safeResolve(Path base, String child) {
        Path normalizedBase = base.toAbsolutePath().normalize();
        Path resolved = normalizedBase.resolve(child).normalize();
        if (!resolved.startsWith(normalizedBase)) {
            throw new InvalidPathException(child, "Path escapes import directory");
        }
        return resolved;
    }

    private PublicIdentity parsePublicIdentity(String json) throws IOException {
        try {
            return cryptoService.validatePublicIdentity(gson.fromJson(json, PublicIdentity.class));
        } catch (CryptoException | RuntimeException e) {
            throw new IOException("Imported public key data is invalid", e);
        }
    }

    private static boolean sameIdentity(PublicIdentity first, PublicIdentity second) {
        return first.kemPublicKey().fingerprint().equals(second.kemPublicKey().fingerprint())
                && first.signaturePublicKey().fingerprint().equals(second.signaturePublicKey().fingerprint());
    }

    private PublicIdentity readPublicIdentity(Path path) throws IOException {
        return parsePublicIdentity(Files.readString(path, StandardCharsets.UTF_8));
    }

    private void writeLocal(Path path, LocalKeyMaterial value) throws IOException {
        sensitiveFiles.writeString(path, gson.toJson(value));
    }

    private void write(Path path, Object value) throws IOException {
        SecureFiles.atomicWrite(path, gson.toJson(value).getBytes(StandardCharsets.UTF_8));
    }

    private static boolean fingerprintMatches(String expected, String supplied) {
        if (expected == null || supplied == null) {
            return false;
        }
        byte[] expectedBytes = expected.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        byte[] suppliedBytes = supplied.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expectedBytes, suppliedBytes);
    }

    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_");
    }

    public record PublicKeyExport(Path path, PublicIdentity identity) {
    }
}
