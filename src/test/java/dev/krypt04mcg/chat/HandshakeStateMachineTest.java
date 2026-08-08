package dev.krypt04mcg.chat;

import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class HandshakeStateMachineTest {
    @TempDir
    private Path tempDir;

    @Test
    void signedSessionHandshakeAcceptsOnceAndRejectsReplay() throws Exception {
        Fixture fixture = fixture();
        SessionService aliceSessions = new SessionService(tempDir.resolve("alice"));
        SessionHandshakeService aliceHandshake = new SessionHandshakeService(fixture.crypto, aliceSessions);
        EncryptedPacket packet = aliceHandshake.begin(fixture.bobKeys.ownPublicIdentity(), fixture.aliceMaterial,
                KemAlgorithm.ML_KEM_768, false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        List<String> fragments = fixture.fragments.fragment(fixture.codec.encode(packet), packet.messageId(), 96);

        for (String fragment : fragments) {
            fixture.handler.handle("alice", fragment);
        }

        assertTrue(fixture.sessionService.find("alice").isPresent());
        assertEquals(1, fixture.responses.size());
        EncryptedPacket response = fixture.responses.getFirst();
        assertEquals("ML-KEM-768", response.algorithms().kem());
        assertThrows(Exception.class, () -> fixture.crypto.decrypt(response, fixture.aliceMaterial,
                fixture.bobKeys.ownPublicIdentity()));
        SessionHandshakeService.DecryptedExchange decrypted = aliceHandshake.decrypt(response,
                fixture.aliceMaterial, fixture.bobKeys.ownPublicIdentity());
        aliceHandshake.complete(response, decrypted, fixture.bobKeys.ownPublicIdentity(), fixture.aliceMaterial,
                false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM, (ignored, receiver) -> {
                    throw new AssertionError("Response completion must not send another packet");
                });
        assertEquals(fixture.sessionService.find("alice").orElseThrow().secret(),
                aliceSessions.find("bob").orElseThrow().secret());
        assertTrue(!fixture.history.recordAcceptedPacket("alice", packet.messageId(), packet.nonce()));

        for (String fragment : fragments) {
            fixture.handler.handle("alice", fragment);
        }

        assertTrue(fixture.decryptedMessages.isEmpty());
        assertEquals(1, fixture.responses.size());
    }

    @Test
    void outOfOrderAndDuplicateFragmentsStillProduceSinglePlaintext() throws Exception {
        Fixture fixture = fixture();
        EncryptedPacket packet = fixture.crypto.encryptFor(fixture.bobKeys.ownPublicIdentity(),
                fixture.aliceMaterial, "alice", "hello state machine", true, false);
        List<String> fragments = new ArrayList<>(fixture.fragments.fragment(fixture.codec.encode(packet), packet.messageId(), 96));

        fixture.handler.handle("alice", fragments.get(1));
        fixture.handler.handle("alice", fragments.get(1));
        fixture.handler.handle("alice", fragments.get(0));
        for (int i = 2; i < fragments.size(); i++) {
            fixture.handler.handle("alice", fragments.get(i));
        }

        assertEquals(List.of("hello state machine"), fixture.decryptedMessages);
    }

    @Test
    void missingFragmentsDoNotAdvanceStateMachine() throws Exception {
        Fixture fixture = fixture();
        EncryptedPacket packet = fixture.crypto.encryptFor(fixture.bobKeys.ownPublicIdentity(),
                fixture.aliceMaterial, "alice", "missing fragment", true, false);
        List<String> fragments = fixture.fragments.fragment(fixture.codec.encode(packet), packet.messageId(), 80);

        for (int i = 0; i < fragments.size() - 1; i++) {
            fixture.handler.handle("alice", fragments.get(i));
        }

        assertTrue(fixture.decryptedMessages.isEmpty());
        assertTrue(fixture.sessionService.find("alice").isEmpty());
    }

    @Test
    void distrustedAndTransportSenderMismatchedPacketsAreRejectedBeforeDisplay() throws Exception {
        Fixture fixture = fixture();
        PublicIdentity alice = publicIdentity(fixture.aliceMaterial);
        EncryptedPacket packet = fixture.crypto.encryptFor(fixture.bobKeys.ownPublicIdentity(),
                fixture.aliceMaterial, "alice", "must not display", true, false);
        List<String> fragments = fixture.fragments.fragment(fixture.codec.encode(packet), packet.messageId(), 96);

        fixture.trust.markDistrusted("alice", alice);
        for (String fragment : fragments) {
            fixture.handler.handle("alice", fragment);
        }
        assertTrue(fixture.decryptedMessages.isEmpty());

        Fixture mismatchFixture = fixture();
        mismatchFixture.trust.markTofuTrusted("alice", publicIdentity(mismatchFixture.aliceMaterial));
        EncryptedPacket mismatched = mismatchFixture.crypto.encryptFor(mismatchFixture.bobKeys.ownPublicIdentity(),
                mismatchFixture.aliceMaterial, "alice", "also blocked", true, false);
        for (String fragment : mismatchFixture.fragments.fragment(mismatchFixture.codec.encode(mismatched),
                mismatched.messageId(), 96)) {
            mismatchFixture.handler.handle("mallory", fragment);
        }
        assertTrue(mismatchFixture.decryptedMessages.isEmpty());
    }

    @Test
    void decryptionHistoryRejectsDuplicateMessageIdOrNonce() throws Exception {
        DecryptionHistoryService history = new DecryptionHistoryService(tempDir);
        byte[] messageId = randomBytes(16);
        byte[] nonce = randomBytes(12);

        assertTrue(history.recordAcceptedPacket("alice", messageId, nonce));
        assertTrue(!history.recordAcceptedPacket("alice", messageId, randomBytes(12)));
        assertTrue(!history.recordAcceptedPacket("alice", randomBytes(16), nonce));
        assertTrue(history.recordAcceptedPacket("bob", messageId, nonce));
    }

    @Test
    void simultaneousExchangesConvergeOnOneSession() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid");
        PublicIdentity aliceIdentity = publicIdentity(alice);
        PublicIdentity bobIdentity = publicIdentity(bob);
        SessionService aliceSessions = new SessionService(tempDir.resolve("simultaneous-alice"));
        SessionService bobSessions = new SessionService(tempDir.resolve("simultaneous-bob"));
        SessionHandshakeService aliceHandshake = new SessionHandshakeService(crypto, aliceSessions);
        SessionHandshakeService bobHandshake = new SessionHandshakeService(crypto, bobSessions);
        EncryptedPacket aliceRequest = aliceHandshake.begin(bobIdentity, alice, KemAlgorithm.ML_KEM_768,
                false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);
        EncryptedPacket bobRequest = bobHandshake.begin(aliceIdentity, bob, KemAlgorithm.ML_KEM_768,
                false, dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM);

        SessionHandshakeService.DecryptedExchange atAlice = aliceHandshake.decrypt(bobRequest, alice, bobIdentity);
        assertTrue(!aliceHandshake.complete(bobRequest, atAlice, bobIdentity, alice, false,
                dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM, (packet, receiver) -> {
                }));

        List<EncryptedPacket> responses = new ArrayList<>();
        SessionHandshakeService.DecryptedExchange atBob = bobHandshake.decrypt(aliceRequest, bob, aliceIdentity);
        assertTrue(bobHandshake.complete(aliceRequest, atBob, aliceIdentity, bob, false,
                dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM,
                (packet, receiver) -> responses.add(packet)));
        SessionHandshakeService.DecryptedExchange response = aliceHandshake.decrypt(responses.getFirst(),
                alice, bobIdentity);
        assertTrue(aliceHandshake.complete(responses.getFirst(), response, bobIdentity, alice, false,
                dev.krypt04mcg.config.AeadAlgorithm.AES_256_GCM, (packet, receiver) -> {
                }));

        assertEquals(aliceSessions.find("bob").orElseThrow().secret(),
                bobSessions.find("alice").orElseThrow().secret());
    }

    private Fixture fixture() throws Exception {
        CryptoService crypto = new CryptoService();
        KeyStoreService bobKeys = new KeyStoreService(tempDir.resolve("bob"), crypto);
        bobKeys.init("bob", "bob-uuid");
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid");
        Files.writeString(tempDir.resolve("bob").resolve("keys").resolve("public").resolve("alice.json"),
                JsonSupport.prettyGson().toJson(publicIdentity(alice)));
        PacketCodec codec = new PacketCodec();
        FragmentService fragments = new FragmentService();
        SessionService sessionService = new SessionService(tempDir.resolve("bob"));
        List<String> systemMessages = new ArrayList<>();
        List<String> decryptedMessages = new ArrayList<>();
        DecryptionHistoryService history = new DecryptionHistoryService(tempDir.resolve("bob"));
        KeyTrustService trust = new KeyTrustService(tempDir.resolve("bob"));
        SessionHandshakeService handshake = new SessionHandshakeService(crypto, sessionService);
        List<EncryptedPacket> responses = new ArrayList<>();
        ChatReceiveHandler handler = new ChatReceiveHandler(new Krypt04McgConfig(), bobKeys, trust, crypto,
                codec, fragments, new FragmentReassembler(), history, sessionService, handshake,
                (packet, receiver) -> responses.add(packet),
                systemMessages::add, (player, message) -> decryptedMessages.add(message));
        return new Fixture(crypto, bobKeys, alice, codec, fragments, sessionService, history, trust, systemMessages,
                decryptedMessages, responses, handler);
    }

    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private record Fixture(CryptoService crypto, KeyStoreService bobKeys, LocalKeyMaterial aliceMaterial,
                           PacketCodec codec, FragmentService fragments, SessionService sessionService,
                           DecryptionHistoryService history, KeyTrustService trust, List<String> systemMessages,
                           List<String> decryptedMessages, List<EncryptedPacket> responses,
                           ChatReceiveHandler handler) {
    }
}
