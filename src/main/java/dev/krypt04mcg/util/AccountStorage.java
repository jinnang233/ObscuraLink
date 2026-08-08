package dev.krypt04mcg.util;

import com.google.gson.Gson;
import dev.krypt04mcg.model.LocalKeyMaterial;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

public final class AccountStorage {
    private static final List<String> LEGACY_DIRECTORIES = List.of("keys", "sessions", "cache", "export", "secrets");

    private AccountStorage() {
    }

    public static Path resolve(Path baseRoot, String owner, String uuid) throws IOException {
        String stableUuid = uuid == null || uuid.isBlank()
                ? UUID.nameUUIDFromBytes(("OfflinePlayer:" + owner).getBytes(StandardCharsets.UTF_8)).toString()
                : uuid;
        Path accountRoot = baseRoot.resolve("accounts").resolve(normalize(stableUuid));
        Path marker = accountRoot.resolve(".account-storage-v1");
        if (!Files.exists(marker) && (storageBelongsTo(baseRoot, owner, stableUuid)
                || storageBelongsTo(accountRoot, owner, stableUuid))) {
            migrateLegacy(baseRoot, accountRoot);
        }
        SecureFiles.createPrivateDirectories(accountRoot.getParent());
        SecureFiles.createPrivateDirectories(accountRoot);
        if (!Files.exists(marker)) {
            SecureFiles.atomicWrite(marker, (owner + "\n" + stableUuid + "\n").getBytes(StandardCharsets.UTF_8));
        }
        return accountRoot;
    }

    private static boolean storageBelongsTo(Path root, String owner, String uuid) throws IOException {
        Path localFile = root.resolve("keys").resolve("private").resolve("local.json");
        if (!Files.isRegularFile(localFile)) {
            return false;
        }
        try {
            Gson gson = JsonSupport.prettyGson();
            LocalKeyMaterial material = gson.fromJson(new SensitiveFileStore(root).readString(localFile),
                    LocalKeyMaterial.class);
            return material != null && material.kemPublicKey() != null
                    && owner.equalsIgnoreCase(material.kemPublicKey().owner())
                    && uuid.equalsIgnoreCase(material.kemPublicKey().uuid());
        } catch (RuntimeException e) {
            throw new IOException("Unable to inspect legacy account key storage", e);
        }
    }

    private static void migrateLegacy(Path baseRoot, Path accountRoot) throws IOException {
        SecureFiles.createPrivateDirectories(accountRoot);
        for (String name : LEGACY_DIRECTORIES) {
            Path source = baseRoot.resolve(name);
            Path target = accountRoot.resolve(name);
            if (Files.exists(source) && !Files.exists(target)) {
                move(source, target);
            }
        }
        Path legacyGroups = baseRoot.resolve("groups.json");
        Path accountGroups = accountRoot.resolve("groups.json");
        if (Files.exists(legacyGroups) && !Files.exists(accountGroups)) {
            move(legacyGroups, accountGroups);
        }
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target);
        }
    }

    private static String normalize(String uuid) {
        return uuid.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_");
    }
}
