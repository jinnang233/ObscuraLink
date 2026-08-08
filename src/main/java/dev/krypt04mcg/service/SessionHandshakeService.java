package dev.krypt04mcg.service;

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.crypto.CryptoException;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.crypto.EphemeralKemKeyPair;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionExchangePayload;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class SessionHandshakeService implements AutoCloseable {
    private static final Duration PENDING_TTL = Duration.ofMinutes(5);
    private static final int MAX_PENDING = 64;
    private static final ScheduledExecutorService EXPIRY_EXECUTOR = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "Krypt04Mcg Ephemeral KEM Expiry");
        thread.setDaemon(true);
        return thread;
    });

    private final CryptoService cryptoService;
    private final SessionService sessionService;
    private final Gson gson = JsonSupport.prettyGson();
    private final Map<String, PendingHandshake> pending = new LinkedHashMap<>();

    public SessionHandshakeService(CryptoService cryptoService, SessionService sessionService) {
        this.cryptoService = cryptoService;
        this.sessionService = sessionService;
    }

    public synchronized EncryptedPacket begin(PublicIdentity receiver, LocalKeyMaterial senderKeys,
                                              KemAlgorithm ephemeralAlgorithm, boolean compress,
                                              AeadAlgorithm aeadAlgorithm) throws CryptoException {
        cleanupExpired();
        String sender = senderKeys.kemPublicKey().owner();
        EphemeralKemKeyPair ephemeral = cryptoService.generateEphemeralKemKeyPair(ephemeralAlgorithm);
        try {
            byte[] sessionIdBytes = cryptoService.randomMessageId();
            String sessionId = Base64Url.encode(sessionIdBytes);
            Instant createdAt = Instant.now();
            KeyRecord ephemeralPublic = cryptoService.keyRecord(ephemeral.algorithm().identifier() + "/public",
                    sender, senderKeys.kemPublicKey().uuid(), createdAt, ephemeral.publicKey());
            SessionExchangePayload payload = new SessionExchangePayload(SessionExchangePayload.VERSION,
                    SessionExchangePayload.Kind.REQUEST, sender, senderKeys.kemPublicKey().uuid(), receiver.owner(),
                    receiver.uuid(), sessionId, "", fingerprint(senderKeys), fingerprint(receiver),
                    ephemeral.algorithm().identifier(), ephemeralPublic.keyData(), "", createdAt.toEpochMilli());
            EncryptedPacket packet = cryptoService.encryptSessionExchange(receiver.kemPublicKey(), receiver.owner(),
                    senderKeys, sender, gson.toJson(payload), false, compress, aeadAlgorithm);
            putPending(receiver.owner(), new PendingHandshake(receiver, sessionId, Hex.encode(packet.messageId()),
                    ephemeral, createdAt));
            return packet;
        } catch (RuntimeException | CryptoException e) {
            ephemeral.close();
            throw e;
        }
    }

    public synchronized DecryptedExchange decrypt(EncryptedPacket packet, LocalKeyMaterial receiverKeys,
                                                   PublicIdentity sender) throws CryptoException, IOException {
        cleanupExpired();
        requireSignedExchange(packet);
        String plaintext;
        if (isResponse(packet)) {
            PendingHandshake pendingHandshake = pending.get(normalize(packet.sender()));
            if (pendingHandshake == null) {
                throw new CryptoException("No pending ephemeral KEM exchange with " + packet.sender());
            }
            plaintext = cryptoService.decryptSessionExchangeResponse(packet,
                    receiverKeys.kemPublicKey().owner(), pendingHandshake.ephemeral(), sender);
        } else {
            plaintext = cryptoService.decrypt(packet, receiverKeys, sender);
        }
        try {
            SessionExchangePayload payload = gson.fromJson(plaintext, SessionExchangePayload.class);
            if (payload == null) {
                throw new IOException("Session exchange payload is empty");
            }
            return new DecryptedExchange(payload, plaintext);
        } catch (RuntimeException e) {
            throw new IOException("Session exchange payload is invalid", e);
        }
    }

    public synchronized boolean complete(EncryptedPacket packet, DecryptedExchange exchange,
                                         PublicIdentity sender, LocalKeyMaterial receiverKeys,
                                         boolean compress, AeadAlgorithm aeadAlgorithm,
                                         PacketSender packetSender) throws Exception {
        SessionExchangePayload payload = exchange.payload();
        validateCommon(packet, payload, sender, receiverKeys);
        if (isResponse(packet)) {
            completeResponse(packet, payload, sender);
            return true;
        } else {
            return completeRequest(packet, payload, sender, receiverKeys, compress, aeadAlgorithm, packetSender);
        }
    }

    private boolean completeRequest(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender,
                                    LocalKeyMaterial receiverKeys, boolean compress, AeadAlgorithm aeadAlgorithm,
                                    PacketSender packetSender) throws Exception {
        if (payload.kind() != SessionExchangePayload.Kind.REQUEST || !payload.requestMessageId().isEmpty()
                || !payload.sessionSecret().isEmpty()) {
            throw new IOException("Invalid session exchange request fields");
        }
        if (Base64Url.decode(payload.sessionId()).length != CryptoService.MESSAGE_ID_BYTES) {
            throw new IOException("Invalid session exchange ID");
        }
        PendingHandshake simultaneous = pending.get(normalize(sender.owner()));
        if (simultaneous != null) {
            if (receiverKeys.kemPublicKey().owner().compareToIgnoreCase(sender.owner()) < 0) {
                return false;
            }
            pending.remove(normalize(sender.owner()));
            simultaneous.ephemeral().close();
        }
        KemAlgorithm.fromIdentifier(payload.ephemeralKem());
        KeyRecord ephemeralPublic = cryptoService.validateEphemeralKemPublicKey(payload.ephemeralKem(),
                payload.initiator(), payload.initiatorUuid(), payload.ephemeralPublicKey(),
                Instant.ofEpochMilli(payload.createdAtMillis()));
        SessionRecord session = sessionService.newSession(sender.owner(), fingerprint(sender), payload.sessionId());
        SessionExchangePayload response = new SessionExchangePayload(SessionExchangePayload.VERSION,
                SessionExchangePayload.Kind.RESPONSE, payload.initiator(), payload.initiatorUuid(),
                payload.responder(), payload.responderUuid(), session.sessionId(), Hex.encode(packet.messageId()),
                payload.initiatorFingerprint(), payload.responderFingerprint(), payload.ephemeralKem(), "",
                session.secret(), System.currentTimeMillis());
        EncryptedPacket responsePacket = cryptoService.encryptSessionExchange(ephemeralPublic, sender.owner(),
                receiverKeys, receiverKeys.kemPublicKey().owner(), gson.toJson(response), true, compress, aeadAlgorithm);
        packetSender.send(responsePacket, sender.owner());
        sessionService.save(session);
        return true;
    }

    private void completeResponse(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender)
            throws IOException {
        PendingHandshake pendingHandshake = pending.get(normalize(sender.owner()));
        if (pendingHandshake == null || payload.kind() != SessionExchangePayload.Kind.RESPONSE
                || !pendingHandshake.sessionId().equals(payload.sessionId())
                || !pendingHandshake.requestMessageId().equalsIgnoreCase(payload.requestMessageId())
                || !pendingHandshake.peer().uuid().equalsIgnoreCase(payload.responderUuid())
                || !payload.ephemeralPublicKey().isEmpty()
                || !pendingHandshake.ephemeral().algorithm().identifier().equalsIgnoreCase(payload.ephemeralKem())
                || Base64Url.decode(payload.sessionSecret()).length != 32) {
            throw new IOException("Session exchange response does not match the pending request");
        }
        sessionService.acceptRemoteSession(sender.owner(), fingerprint(sender), payload.sessionId(),
                payload.sessionSecret());
        pending.remove(normalize(sender.owner()));
        pendingHandshake.ephemeral().close();
    }

    private static void validateCommon(EncryptedPacket packet, SessionExchangePayload payload, PublicIdentity sender,
                                       LocalKeyMaterial receiverKeys) throws IOException {
        PublicIdentity receiver = new PublicIdentity(receiverKeys.kemPublicKey().owner(),
                receiverKeys.kemPublicKey().uuid(), receiverKeys.kemPublicKey(), receiverKeys.signaturePublicKey());
        if (payload.version() != SessionExchangePayload.VERSION
                || !payload.initiator().equalsIgnoreCase(isResponse(packet) ? receiver.owner() : sender.owner())
                || !payload.responder().equalsIgnoreCase(isResponse(packet) ? sender.owner() : receiver.owner())
                || !payload.initiatorUuid().equalsIgnoreCase(isResponse(packet) ? receiver.uuid() : sender.uuid())
                || !payload.responderUuid().equalsIgnoreCase(isResponse(packet) ? sender.uuid() : receiver.uuid())
                || !payload.initiatorFingerprint().equalsIgnoreCase(
                isResponse(packet) ? fingerprint(receiver) : fingerprint(sender))
                || !payload.responderFingerprint().equalsIgnoreCase(
                isResponse(packet) ? fingerprint(sender) : fingerprint(receiver))
                || Math.abs(payload.createdAtMillis() - packet.timestampMillis()) > Duration.ofSeconds(5).toMillis()) {
            throw new IOException("Session exchange transcript identity mismatch");
        }
    }

    private void putPending(String peer, PendingHandshake value) {
        String normalized = normalize(peer);
        PendingHandshake replaced = pending.put(normalized, value);
        if (replaced != null) {
            replaced.ephemeral().close();
        }
        EXPIRY_EXECUTOR.schedule(() -> expire(normalized, value), PENDING_TTL.toMillis(), TimeUnit.MILLISECONDS);
        while (pending.size() > MAX_PENDING) {
            String oldest = pending.keySet().iterator().next();
            pending.remove(oldest).ephemeral().close();
        }
    }

    private synchronized void expire(String peer, PendingHandshake expected) {
        if (pending.get(peer) == expected) {
            pending.remove(peer);
            expected.ephemeral().close();
        }
    }

    private void cleanupExpired() {
        Instant cutoff = Instant.now().minus(PENDING_TTL);
        pending.entrySet().removeIf(entry -> {
            if (entry.getValue().createdAt().isBefore(cutoff)) {
                entry.getValue().ephemeral().close();
                return true;
            }
            return false;
        });
    }

    private static void requireSignedExchange(EncryptedPacket packet) throws CryptoException {
        if (packet.type() != PacketType.SESSION_EXCHANGE || !packet.signed()) {
            throw new CryptoException("Session exchange packets must use the signed SESSION_EXCHANGE type");
        }
    }

    private static boolean isResponse(EncryptedPacket packet) {
        return (packet.flags() & CryptoService.FLAG_SESSION_RESPONSE) != 0;
    }

    private static String fingerprint(LocalKeyMaterial material) {
        return material.kemPublicKey().fingerprint() + ":" + material.signaturePublicKey().fingerprint();
    }

    private static String fingerprint(PublicIdentity identity) {
        return identity.kemPublicKey().fingerprint() + ":" + identity.signaturePublicKey().fingerprint();
    }

    private static String normalize(String player) {
        return player.toLowerCase(Locale.ROOT);
    }

    @Override
    public synchronized void close() {
        pending.values().forEach(value -> value.ephemeral().close());
        pending.clear();
    }

    public record DecryptedExchange(SessionExchangePayload payload, String plaintext) {
    }

    @FunctionalInterface
    public interface PacketSender {
        void send(EncryptedPacket packet, String receiver) throws Exception;
    }

    private record PendingHandshake(PublicIdentity peer, String sessionId, String requestMessageId,
                                    EphemeralKemKeyPair ephemeral, Instant createdAt) {
    }
}
