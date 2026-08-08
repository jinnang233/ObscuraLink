package dev.krypt04mcg.chat;

import com.google.gson.Gson;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.CachedSentMessage;
import dev.krypt04mcg.model.ChatSendFragment;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.SessionMessagePayload;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SentMessageCacheService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.Hex;
import dev.krypt04mcg.util.JsonSupport;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

public final class ChatSendService {
    private final Krypt04McgConfig config;
    private final KeyStoreService keyStoreService;
    private final KeyTrustService keyTrustService;
    private final SessionService sessionService;
    private final SessionHandshakeService sessionHandshakeService;
    private final SentMessageCacheService sentMessageCacheService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final Gson gson = JsonSupport.prettyGson();
    private Consumer<ChatSendFragment> chatSender;
    private final Consumer<String> system;

    public ChatSendService(Krypt04McgConfig config, KeyStoreService keyStoreService, KeyTrustService keyTrustService,
                           SessionService sessionService, SessionHandshakeService sessionHandshakeService,
                           SentMessageCacheService sentMessageCacheService,
                           CryptoService cryptoService, PacketCodec packetCodec, FragmentService fragmentService,
                           Consumer<ChatSendFragment> chatSender, Consumer<String> system) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.keyTrustService = keyTrustService;
        this.sessionService = sessionService;
        this.sessionHandshakeService = sessionHandshakeService;
        this.sentMessageCacheService = sentMessageCacheService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.chatSender = Objects.requireNonNull(chatSender, "chatSender");
        this.system = system;
    }

    public void setChatSender(Consumer<ChatSendFragment> chatSender) {
        this.chatSender = Objects.requireNonNull(chatSender, "chatSender");
    }

    public boolean sendKemMessage(String receiver, String message, boolean sign) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            EncryptedPacket packet = cryptoService.encryptFor(identity, keyStoreService.local(),
                    keyStoreService.local().kemPublicKey().owner(), message, sign, config.enableCompression,
                    config.aeadAlgorithm);
            sendPacket(packet, receiver);
            system.accept(ClientMessages.tr("text.krypt04mcg.sent_encrypted", receiver));
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    public boolean exchange(String receiver) {
        try {
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            EncryptedPacket packet = sessionHandshakeService.begin(identity, keyStoreService.local(),
                    config.ephemeralKemAlgorithm, config.enableCompression, config.aeadAlgorithm);
            sendPacket(packet, receiver);
            system.accept(ClientMessages.tr("text.krypt04mcg.session_prepared", receiver));
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    public boolean sendSessionMessage(String receiver, String message) {
        try {
            SessionRecord session = sessionService.find(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_session", receiver)));
            if (sessionService.isExpired(session, config.sessionTtlMinutes, config.maxMessagesPerSession, config.rotateAfterBytes)) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.session_expired", receiver));
            }
            PublicIdentity identity = keyStoreService.findPublicIdentity(receiver)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_public_key", receiver)));
            ensureSendAllowed(receiver, identity);
            String peerFingerprint = KeyTrustService.fingerprintPair(identity);
            if (!session.peerFingerprint().equalsIgnoreCase(peerFingerprint)) {
                throw new IllegalStateException("Session identity binding no longer matches " + receiver);
            }
            long sequence = session.nextSendSequence();
            String payload = gson.toJson(new SessionMessagePayload(SessionMessagePayload.VERSION,
                    session.sessionId(), sequence, message));
            EncryptedPacket packet = cryptoService.encryptWithSession(identity, keyStoreService.local(),
                    keyStoreService.local().kemPublicKey().owner(), Base64Url.decode(session.secret()), payload,
                    true, config.enableCompression, config.aeadAlgorithm);
            sendPacket(packet, receiver);
            sessionService.recordSentMessage(receiver, sequence,
                    message.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            system.accept(ClientMessages.tr("text.krypt04mcg.sent_encrypted", receiver));
            return true;
        } catch (Exception e) {
            error(e);
            return false;
        }
    }

    public void sendGroupMessage(String groupName, List<String> members, String message) {
        if (members.isEmpty()) {
            system.accept(ClientMessages.tr("text.krypt04mcg.error.group_empty", groupName));
            return;
        }
        system.accept(ClientMessages.tr("text.krypt04mcg.group_sending", groupName, members.size()));
        for (String member : members) {
            sendKemMessage(member, message, true);
        }
    }

    public void resendLatest() {
        try {
            CachedSentMessage cached = sentMessageCacheService.latest()
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_cached_message")));
            resend(cached);
        } catch (Exception e) {
            error(e);
        }
    }

    public void resend(String messageId) {
        try {
            CachedSentMessage cached = sentMessageCacheService.find(messageId)
                    .orElseThrow(() -> new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.no_cached_message_id", messageId)));
            resend(cached);
        } catch (Exception e) {
            error(e);
        }
    }

    private void resend(CachedSentMessage cached) {
        sendFragments(cached.receiver(), cached.fragments());
        system.accept(ClientMessages.tr("text.krypt04mcg.resending", cached.receiver(), cached.messageId()));
    }

    public void sendPacket(EncryptedPacket packet, String receiver) throws Exception {
        byte[] encoded = packetCodec.encode(packet);
        List<String> fragments = fragmentService.fragment(encoded, packet.messageId(), config.fragmentSize, config.packetPrefix);
        sentMessageCacheService.remember(Hex.encode(packet.messageId()), receiver, fragments);
        sendFragments(receiver, fragments);
    }

    private void sendFragments(String receiver, List<String> fragments) {
        Thread sender = new Thread(() -> {
            for (String fragment : fragments) {
                chatSender.accept(new ChatSendFragment(receiver, fragment, EncryptedPacket.VERSION));
                if (config.showProgress) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.fragment_sent"));
                }
                sleep(config.sendDelayMs);
            }
        }, "Krypt04Mcg Sender");
        sender.setDaemon(true);
        sender.start();
    }

    private void ensureSendAllowed(String receiver, PublicIdentity identity) throws Exception {
        TrustState trustState = keyTrustService.trustState(receiver, identity);
        if (trustState == TrustState.DISTRUSTED) {
            throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", receiver));
        }
        if (trustState == TrustState.TOFU_TRUSTED) {
            system.accept(ClientMessages.tr("text.krypt04mcg.warning.tofu_unverified", identity.owner()));
        }
    }

    private void error(Exception e) {
        system.accept(ClientMessages.tr("text.krypt04mcg.error.generic", e.getMessage()));
    }

    private static void sleep(int millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
