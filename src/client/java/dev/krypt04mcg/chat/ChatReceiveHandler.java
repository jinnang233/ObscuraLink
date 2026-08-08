package dev.krypt04mcg.chat;

import com.google.gson.Gson;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.FragmentProgress;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionMessagePayload;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SessionHandshakeService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;
import dev.krypt04mcg.util.JsonSupport;
import dev.krypt04mcg.util.Hex;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class ChatReceiveHandler {
    private final Krypt04McgConfig config;
    private final KeyStoreService keyStoreService;
    private final KeyTrustService keyTrustService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final FragmentReassembler reassembler;
    private final DecryptionHistoryService decryptionHistoryService;
    private final SessionService sessionService;
    private final SessionHandshakeService sessionHandshakeService;
    private final SessionHandshakeService.PacketSender packetSender;
    private final Gson gson = JsonSupport.prettyGson();
    private final Consumer<String> system;
    private final BiConsumer<String, String> decryptedMessageSink;

    public ChatReceiveHandler(Krypt04McgConfig config, KeyStoreService keyStoreService,
                              KeyTrustService keyTrustService, CryptoService cryptoService,
                              PacketCodec packetCodec, FragmentService fragmentService,
                              FragmentReassembler reassembler, DecryptionHistoryService decryptionHistoryService,
                              SessionService sessionService, SessionHandshakeService sessionHandshakeService,
                              SessionHandshakeService.PacketSender packetSender, Consumer<String> system,
                              BiConsumer<String, String> decryptedMessageSink) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.keyTrustService = keyTrustService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.reassembler = reassembler;
        this.decryptionHistoryService = decryptionHistoryService;
        this.sessionService = sessionService;
        this.sessionHandshakeService = sessionHandshakeService;
        this.packetSender = packetSender;
        this.system = system;
        this.decryptedMessageSink = decryptedMessageSink;
    }

    public boolean shouldHide(String raw) {
        return config.hideEncryptedRawMessage && extractFragmentLine(raw).isPresent();
    }

    public void handle(String transportSender, String raw) {
        Optional<String> fragmentLine = extractFragmentLine(raw);
        if (fragmentLine.isEmpty()) {
            return;
        }
        String displaySender = transportSender == null || transportSender.isBlank() ? "unknown" : transportSender;
        try {
            for (FragmentProgress timeout : reassembler.cleanupTimedOut()) {
                if (config.showReceiveProgress) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.receive_timeout", displaySender,
                            timeout.received(), timeout.total()));
                }
            }
            Fragment fragment = fragmentService.parse(fragmentLine.get(), config.packetPrefix);
            String reassemblyId = normalizeTransportSender(transportSender) + ":" + fragment.messageId();
            Fragment senderBoundFragment = new Fragment(reassemblyId, fragment.index(), fragment.total(), fragment.payload());
            Optional<byte[]> packetBytes = reassembler.accept(senderBoundFragment);
            if (packetBytes.isEmpty()) {
                if (config.showReceiveProgress) {
                    reassembler.progress(reassemblyId).ifPresent(progress ->
                            system.accept(ClientMessages.tr("text.krypt04mcg.receiving", displaySender,
                                    progress.received(), progress.total())));
                }
                return;
            }
            if (config.showReceiveProgress) {
                system.accept(ClientMessages.tr("text.krypt04mcg.receive_complete", displaySender));
            }
            EncryptedPacket packet = packetCodec.decode(packetBytes.get());
            if (!fragment.messageId().equalsIgnoreCase(Hex.encode(packet.messageId()))) {
                throw new IllegalArgumentException("Fragment message ID does not match the encrypted packet");
            }
            requireTransportIdentity(transportSender, packet);
            if (!packet.receiver().equalsIgnoreCase(keyStoreService.local().kemPublicKey().owner())) {
                if (config.verboseMessages) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.ignored_packet", packet.receiver()));
                }
                return;
            }
            if (keyTrustService.trustState(packet.sender(), null) == TrustState.DISTRUSTED) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", packet.sender()));
            }
            PublicIdentity sender = keyStoreService.findPublicIdentity(packet.sender())
                    .orElseThrow(() -> new IllegalStateException(
                            ClientMessages.tr("text.krypt04mcg.error.no_sender_public_key", packet.sender())));
            TrustState trustState = keyTrustService.trustState(packet.sender(), sender);
            if (trustState == TrustState.DISTRUSTED) {
                throw new IllegalStateException(ClientMessages.tr("text.krypt04mcg.error.distrusted_key", packet.sender()));
            }

            SessionHandshakeService.DecryptedExchange exchange = null;
            SessionMessagePayload sessionMessage = null;
            String plaintext;
            switch (packet.type()) {
                case KEM_MESSAGE, SIGNED_KEM_MESSAGE ->
                        plaintext = cryptoService.decrypt(packet, keyStoreService.local(), sender);
                case SESSION_EXCHANGE -> {
                    exchange = sessionHandshakeService.decrypt(packet, keyStoreService.local(), sender);
                    plaintext = exchange.plaintext();
                }
                case SESSION_MESSAGE -> {
                    if (!packet.signed()) {
                        throw new IllegalStateException("Session messages must be signed");
                    }
                    SessionRecord session = sessionService.find(packet.sender())
                            .orElseThrow(() -> new IllegalStateException(
                                    ClientMessages.tr("text.krypt04mcg.error.no_session", packet.sender())));
                    if (!session.peerFingerprint().equalsIgnoreCase(KeyTrustService.fingerprintPair(sender))) {
                        throw new IllegalStateException("Session identity binding mismatch for " + packet.sender());
                    }
                    String decrypted = cryptoService.decryptWithSession(packet, keyStoreService.local(), sender,
                            Base64Url.decode(session.secret()));
                    sessionMessage = parseSessionMessage(decrypted, session);
                    plaintext = sessionMessage.message();
                }
                default -> throw new IllegalStateException("Unsupported packet type: " + packet.type());
            }

            validateFreshness(packet);
            if (!decryptionHistoryService.recordAcceptedPacket(packet.sender(), packet.messageId(), packet.nonce())) {
                throw new IllegalStateException("Replay or repeated nonce detected for " + packet.sender());
            }
            if (exchange != null) {
                boolean established = sessionHandshakeService.complete(packet, exchange, sender, keyStoreService.local(),
                        config.enableCompression, config.aeadAlgorithm, packetSender);
                decryptionHistoryService.recordSuccess(packet.sender());
                if (established) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.session_accepted", packet.sender()));
                }
                return;
            }
            if (sessionMessage != null) {
                sessionService.recordReceivedMessage(packet.sender(), sessionMessage.sessionId(),
                        sessionMessage.sequence(), plaintext.getBytes(StandardCharsets.UTF_8).length);
            }
            decryptionHistoryService.recordSuccess(packet.sender());
            String signatureStatus = packet.signed()
                    ? ClientMessages.tr("text.krypt04mcg.signature.valid") + " / "
                    + ClientMessages.tr("text.krypt04mcg.trust." + trustState.name())
                    : ClientMessages.tr("text.krypt04mcg.signature.unsigned");
            decryptedMessageSink.accept(packet.sender(), plaintext);
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_display", packet.sender(),
                    signatureStatus, plaintext));
        } catch (Exception e) {
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_invalid", displaySender, e.getMessage()));
        }
    }

    private SessionMessagePayload parseSessionMessage(String plaintext, SessionRecord session) {
        SessionMessagePayload payload = gson.fromJson(plaintext, SessionMessagePayload.class);
        if (payload == null || payload.version() != SessionMessagePayload.VERSION || payload.message() == null
                || !session.sessionId().equals(payload.sessionId())
                || payload.sequence() != session.nextReceiveSequence()) {
            throw new IllegalArgumentException("Session epoch or sequence is invalid");
        }
        return payload;
    }

    private void validateFreshness(EncryptedPacket packet) {
        if (packet.protocolVersion() < EncryptedPacket.VERSION && !packet.signed()) {
            throw new IllegalArgumentException("Legacy unsigned packets have no authenticated timestamp");
        }
        long now = Instant.now().toEpochMilli();
        long maxAgeSeconds = Math.min(3_600, Math.max(30, config.maxPacketAgeSeconds));
        long maxFutureSeconds = Math.min(300, Math.max(0, config.maxFutureSkewSeconds));
        long oldest = now - maxAgeSeconds * 1_000L;
        long newest = now + maxFutureSeconds * 1_000L;
        if (packet.timestampMillis() < oldest || packet.timestampMillis() > newest) {
            throw new IllegalArgumentException("Packet timestamp is outside the accepted window");
        }
    }

    private static void requireTransportIdentity(String transportSender, EncryptedPacket packet) {
        if (transportSender == null || transportSender.isBlank()) {
            if (!packet.signed()) {
                throw new IllegalArgumentException("Unsigned packet has no authenticated transport sender");
            }
            return;
        }
        if (!transportSender.equalsIgnoreCase(packet.sender())) {
            throw new IllegalArgumentException("Packet sender does not match the Minecraft transport sender");
        }
    }

    private static String normalizeTransportSender(String sender) {
        return sender == null || sender.isBlank() ? "signed-unbound" : sender.toLowerCase(Locale.ROOT);
    }

    private Optional<String> extractFragmentLine(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String prefix = config.packetPrefix == null ? FragmentService.PREFIX : config.packetPrefix;
        String fragment = fragmentService.findFragment(raw, prefix);
        if (fragment == null || !fragmentService.isFragment(fragment, prefix)) {
            return Optional.empty();
        }
        if (config.receiveRegexMode && !Pattern.compile(config.receiveRegex).matcher(fragment).matches()) {
            return Optional.empty();
        }
        return Optional.of(fragment);
    }
}
