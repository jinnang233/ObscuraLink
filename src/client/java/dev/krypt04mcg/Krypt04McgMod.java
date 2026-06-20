package dev.krypt04mcg;

import dev.krypt04mcg.chat.ChatReceiveHandler;
import dev.krypt04mcg.chat.ChatConversationStore;
import dev.krypt04mcg.chat.ChatSendService;
import dev.krypt04mcg.client.ClientMessages;
import dev.krypt04mcg.command.CommandRegistrar;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.config.OptionalClothConfig;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.gui.Krypt04McgChatScreen;
import dev.krypt04mcg.input.Krypt04McgKeyBindings;
import dev.krypt04mcg.protocol.PacketCodec;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.GroupService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SentMessageCacheService;
import dev.krypt04mcg.service.SessionService;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.message.v1.ClientReceiveMessageEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.Minecraft;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Krypt04McgMod implements ClientModInitializer {
    public static final String MOD_ID = "krypt04mcg";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);
    private static final String DISCLAIMER_KEY = "text.krypt04mcg.warning.disclaimer";

    private static Krypt04McgMod instance;

    private Krypt04McgConfig config;
    private KeyStoreService keyStoreService;
    private SessionService sessionService;
    private DecryptionHistoryService decryptionHistoryService;
    private GroupService groupService;
    private KeyTrustService keyTrustService;
    private SentMessageCacheService sentMessageCacheService;
    private ChatSendService chatSendService;
    private ChatReceiveHandler chatReceiveHandler;
    private ChatConversationStore conversationStore;

    public static Krypt04McgMod instance() {
        return instance;
    }

    @Override
    public void onInitializeClient() {
        instance = this;
        config = OptionalClothConfig.loadOrDefault();

        PacketCodec packetCodec = new PacketCodec();
        CryptoService cryptoService = new CryptoService();
        FragmentService fragmentService = new FragmentService();
        FragmentReassembler reassembler = new FragmentReassembler();
        Path root = FabricLoader.getInstance().getConfigDir().resolve("krypt04mcg");
        keyStoreService = new KeyStoreService(root, cryptoService);
        sessionService = new SessionService(root);
        decryptionHistoryService = new DecryptionHistoryService(root);
        groupService = new GroupService(root);
        keyTrustService = new KeyTrustService(root);
        sentMessageCacheService = new SentMessageCacheService(root);
        conversationStore = new ChatConversationStore(root, () -> config.enableConversationHistory);

        Minecraft client = Minecraft.getInstance();
        String owner = client.getUser().getName();
        String uuid = client.getUser().getProfileId() == null ? "" : client.getUser().getProfileId().toString();
        try {
            keyStoreService.init(owner, uuid);
        } catch (Exception e) {
            LOGGER.error("Unable to initialize Krypt04Mcg keys", e);
            system(ClientMessages.tr("text.krypt04mcg.error.key_init_failed"));
            return;
        }

        chatSendService = new ChatSendService(config, keyStoreService, keyTrustService, sessionService, sentMessageCacheService, cryptoService, packetCodec,
                fragmentService, this::sendChatLine, this::system);
        chatReceiveHandler = new ChatReceiveHandler(config, keyStoreService, cryptoService, packetCodec, fragmentService,
                reassembler, decryptionHistoryService, sessionService, this::system, conversationStore::incoming);

        CommandRegistrar.register(chatSendService, keyStoreService, keyTrustService, sessionService, decryptionHistoryService,
                groupService, config);
        Krypt04McgKeyBindings.register(this);
        ClientReceiveMessageEvents.ALLOW_CHAT.register((message, signedMessage, sender, params, receptionTimestamp) -> {
            String senderName = sender == null ? "unknown" : sender.name();
            String raw = message.getString();
            if (!isLocalSender(senderName, owner)) {
                chatReceiveHandler.handle(senderName, raw);
            }
            return !chatReceiveHandler.shouldHide(raw);
        });
        ClientReceiveMessageEvents.ALLOW_GAME.register((message, overlay) -> {
            Optional<ShadowMessage> shadowMessage = extractShadowMessage(message.getString());
            shadowMessage
                    .filter(value -> !isLocalSender(value.player(), owner))
                    .ifPresent(value -> chatReceiveHandler.handle(value.player(), value.message()));
            return shadowMessage.map(value -> !chatReceiveHandler.shouldHide(value.message())).orElse(true);
        });
        ClientPlayConnectionEvents.JOIN.register((handler, sender, joinedClient) -> showDisclaimer(joinedClient));
        LOGGER.info("Krypt04Mcg initialized");
    }

    public void openChatScreen() {
        Minecraft client = Minecraft.getInstance();
        if (chatSendService == null || keyStoreService == null || client.player == null) {
            return;
        }
        client.gui.setScreen(new Krypt04McgChatScreen(chatSendService, keyStoreService, groupService, conversationStore));
    }

    private void sendChatLine(String line) {
        Minecraft client = Minecraft.getInstance();
        if (!line.startsWith(FragmentService.PREFIX + " ")) {
            LOGGER.warn("Refusing to send non-Krypt04Mcg chat line");
            return;
        }
        if (client.getConnection() != null) {
            client.getConnection().sendChat(line);
        }
    }

    private void system(String message) {
        Minecraft client = Minecraft.getInstance();
        client.execute(() -> {
            if (client.gui != null) {
                client.gui.hud.getChat().addClientSystemMessage(Component.literal(message));
            }
        });
    }

    private void showDisclaimer(Minecraft client) {
        LOGGER.debug(ClientMessages.tr(DISCLAIMER_KEY));
        client.execute(() -> {
            if (client.gui != null) {
                client.gui.hud.getChat().addClientSystemMessage(Component.empty()
                        .append(Component.literal("[Krypt04Mcg] ").withStyle(ChatFormatting.RED, ChatFormatting.BOLD))
                        .append(Component.translatable(DISCLAIMER_KEY).withStyle(ChatFormatting.GOLD)));
            }
        });
    }

    private Optional<ShadowMessage> extractShadowMessage(String raw) {
        if (!config.shadowListenMode || raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            Matcher matcher = Pattern.compile(config.shadowListenRegex).matcher(raw);
            if (!matcher.matches()) {
                return Optional.empty();
            }
            String player = matcher.group("player");
            String message = matcher.group("message");
            if (player == null || message == null) {
                return Optional.empty();
            }
            return Optional.of(new ShadowMessage(player, message));
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Invalid Krypt04Mcg shadow listen regex: {}", config.shadowListenRegex, e);
            return Optional.empty();
        }
    }

    private static boolean isLocalSender(String senderName, String localName) {
        return senderName != null && localName != null && senderName.equalsIgnoreCase(localName);
    }

    private record ShadowMessage(String player, String message) {
    }
}
