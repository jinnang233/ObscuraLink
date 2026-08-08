package dev.krypt04mcg.chat;

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
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.util.Base64Url;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class ChatReceiveHandler {
    private final Krypt04McgConfig config;
    private final KeyStoreService keyStoreService;
    private final CryptoService cryptoService;
    private final PacketCodec packetCodec;
    private final FragmentService fragmentService;
    private final FragmentReassembler reassembler;
    private final DecryptionHistoryService decryptionHistoryService;
    private final SessionService sessionService;
    private final ConcurrentMap<String, String> fragmentSenders = new ConcurrentHashMap<>();
    private final Consumer<String> system;
    private final BiConsumer<String, String> decryptedMessageSink;

    public ChatReceiveHandler(Krypt04McgConfig config, KeyStoreService keyStoreService, CryptoService cryptoService,
                              PacketCodec packetCodec, FragmentService fragmentService, FragmentReassembler reassembler,
                              DecryptionHistoryService decryptionHistoryService, SessionService sessionService,
                              Consumer<String> system, BiConsumer<String, String> decryptedMessageSink) {
        this.config = config;
        this.keyStoreService = keyStoreService;
        this.cryptoService = cryptoService;
        this.packetCodec = packetCodec;
        this.fragmentService = fragmentService;
        this.reassembler = reassembler;
        this.decryptionHistoryService = decryptionHistoryService;
        this.sessionService = sessionService;
        this.system = system;
        this.decryptedMessageSink = decryptedMessageSink;
    }

    public boolean shouldHide(String raw) {
        return config.hideEncryptedRawMessage && extractFragmentLine(raw).isPresent();
    }

    public void handle(String senderName, String raw) {
        Optional<String> fragmentLine = extractFragmentLine(raw);
        if (fragmentLine.isEmpty()) {
            return;
        }
        try {
            for (FragmentProgress timeout : reassembler.cleanupTimedOut()) {
                String sender = fragmentSenders.getOrDefault(timeout.messageId(), senderName);
                fragmentSenders.remove(timeout.messageId());
                if (config.showReceiveProgress) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.receive_timeout", sender, timeout.received(), timeout.total()));
                }
            }
            Fragment fragment = fragmentService.parse(fragmentLine.get(), config.packetPrefix);
            fragmentSenders.putIfAbsent(fragment.messageId(), senderName);
            Optional<byte[]> packetBytes = reassembler.accept(fragment);
            if (packetBytes.isEmpty()) {
                if (config.showReceiveProgress) {
                    reassembler.progress(fragment.messageId()).ifPresent(progress ->
                            system.accept(ClientMessages.tr("text.krypt04mcg.receiving", senderName,
                                    progress.received(), progress.total())));
                }
                return;
            }
            fragmentSenders.remove(fragment.messageId());
            if (config.showReceiveProgress) {
                system.accept(ClientMessages.tr("text.krypt04mcg.receive_complete", senderName));
            }
            EncryptedPacket packet = packetCodec.decode(packetBytes.get());
            if (!packet.receiver().equalsIgnoreCase(keyStoreService.local().kemPublicKey().owner())) {
                if (config.verboseMessages) {
                    system.accept(ClientMessages.tr("text.krypt04mcg.ignored_packet", packet.receiver()));
                }
                return;
            }
            PublicIdentity sender = keyStoreService.findPublicIdentity(packet.sender())
                    .orElseThrow(() -> new IllegalStateException(
                            ClientMessages.tr("text.krypt04mcg.error.no_sender_public_key", packet.sender())));
            String plaintext = switch (packet.type()) {
                case KEM_MESSAGE, SIGNED_KEM_MESSAGE, SESSION_EXCHANGE ->
                        cryptoService.decrypt(packet, keyStoreService.local(), sender);
                case SESSION_MESSAGE -> {
                    SessionRecord session = sessionService.find(packet.sender())
                            .orElseThrow(() -> new IllegalStateException(
                                    ClientMessages.tr("text.krypt04mcg.error.no_session", packet.sender())));
                    yield cryptoService.decryptWithSession(packet, keyStoreService.local(), sender,
                            Base64Url.decode(session.secret()));
                }
            };
            if (packet.type() == PacketType.SESSION_MESSAGE) {
                sessionService.recordMessage(packet.sender(), plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            }
            if (!decryptionHistoryService.recordAcceptedPacket(packet.sender(), packet.messageId(), packet.nonce())) {
                throw new IllegalStateException("Replay or repeated nonce detected for " + packet.sender());
            }
            if (tryAcceptSessionExchange(packet, sender, plaintext)) {
                return;
            }
            decryptionHistoryService.recordSuccess(packet.sender());
            String status = packet.signed()
                    ? ClientMessages.tr("text.krypt04mcg.signature.valid")
                    : ClientMessages.tr("text.krypt04mcg.signature.unsigned");
            decryptedMessageSink.accept(packet.sender(), plaintext);
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_display", packet.sender(), status, plaintext));
        } catch (Exception e) {
            system.accept(ClientMessages.tr("text.krypt04mcg.decrypt_invalid", senderName, e.getMessage()));
        }
    }

    private boolean tryAcceptSessionExchange(EncryptedPacket packet, PublicIdentity sender, String plaintext) throws Exception {
        if (!plaintext.startsWith("/session ")) {
            return false;
        }
        if (!packet.signed()) {
            throw new IllegalArgumentException(ClientMessages.tr("text.krypt04mcg.error.session_exchange_unsigned"));
        }
        String[] parts = plaintext.split("\\s+", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException(ClientMessages.tr("text.krypt04mcg.error.session_exchange_invalid"));
        }
        if (Base64Url.decode(parts[1]).length != CryptoService.MESSAGE_ID_BYTES || Base64Url.decode(parts[2]).length != 32) {
            throw new IllegalArgumentException(ClientMessages.tr("text.krypt04mcg.error.session_exchange_key_material"));
        }
        sessionService.acceptRemoteSession(packet.sender(), sender.kemPublicKey().fingerprint(), parts[1], parts[2]);
        decryptionHistoryService.recordSuccess(packet.sender());
        system.accept(ClientMessages.tr("text.krypt04mcg.session_accepted", packet.sender()));
        return true;
    }

    private Optional<String> extractFragmentLine(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String prefix = config.packetPrefix == null ? FragmentService.PREFIX : config.packetPrefix;
        String fragment = fragmentService.findFragment(raw, prefix);
        if (fragment == null) {
            return Optional.empty();
        }
        if (!fragmentService.isFragment(fragment, prefix)) {
            return Optional.empty();
        }
        if (config.receiveRegexMode && !Pattern.compile(config.receiveRegex).matcher(fragment).matches()) {
            return Optional.empty();
        }
        return Optional.of(fragment);
    }
}
