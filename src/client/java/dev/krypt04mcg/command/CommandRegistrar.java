package dev.krypt04mcg.command;

import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.context.ParsedCommandNode;
import com.mojang.brigadier.context.StringRange;
import dev.krypt04mcg.chat.ChatSendService;
import dev.krypt04mcg.config.Krypt04McgConfig;
import dev.krypt04mcg.model.GroupRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.model.SessionRecord;
import dev.krypt04mcg.model.TrustState;
import dev.krypt04mcg.service.DecryptionHistoryService;
import dev.krypt04mcg.service.GroupService;
import dev.krypt04mcg.service.KeyStoreService;
import dev.krypt04mcg.service.KeyTrustService;
import dev.krypt04mcg.service.SessionService;
import dev.krypt04mcg.client.ClientMessages;
import net.fabricmc.fabric.api.client.command.v2.ClientCommands;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.commands.arguments.EntityArgument;
import net.minecraft.network.chat.Component;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public final class CommandRegistrar {
    private static final DateTimeFormatter STATUS_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private CommandRegistrar() {
    }

    public static void register(ChatSendService chatSendService, KeyStoreService keyStoreService,
                                KeyTrustService keyTrustService, SessionService sessionService,
                                DecryptionHistoryService decryptionHistoryService, GroupService groupService,
                                Krypt04McgConfig config) {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            dispatcher.register(rootCommand("Krypt04Mcg:enc", chatSendService, keyStoreService, keyTrustService,
                    sessionService, decryptionHistoryService, groupService, config));
            dispatcher.register(rootCommand("enc", chatSendService, keyStoreService, keyTrustService,
                    sessionService, decryptionHistoryService, groupService, config));
        });
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> rootCommand(String name,
                                                                                 ChatSendService chatSendService,
                                                                                 KeyStoreService keyStoreService,
                                                                                 KeyTrustService keyTrustService,
                                                                                 SessionService sessionService,
                                                                                 DecryptionHistoryService decryptionHistoryService,
                                                                                 GroupService groupService,
                                                                                 Krypt04McgConfig config) {
        return ClientCommands.literal(name)
                    .then(tellCommand(chatSendService, false))
                    .then(tellCommand(chatSendService, true))
                    .then(exchangeCommand(chatSendService))
                    .then(etellCommand(chatSendService))
                    .then(gtellCommand(chatSendService, groupService))
                    .then(groupCommand(groupService))
                    .then(resendCommand(chatSendService))
                    .then(sessionCommand(chatSendService, sessionService, config))
                    .then(showAlgorithmsCommand(config, keyStoreService))
                    .then(statusCommand(keyStoreService, keyTrustService, sessionService, decryptionHistoryService, config))
                    .then(keyCommand(keyStoreService, keyTrustService, config));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> tellCommand(ChatSendService chatSendService, boolean signed) {
        return ClientCommands.literal(signed ? "stell" : "tell")
                .then(ClientCommands.argument("receiver", EntityArgument.player())
                        .then(ClientCommands.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    chatSendService.sendKemMessage(
                                            playerName(ctx, "receiver"),
                                            StringArgumentType.getString(ctx, "message"),
                                            signed);
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> exchangeCommand(ChatSendService chatSendService) {
        return ClientCommands.literal("exchange")
                .then(ClientCommands.argument("receiver", EntityArgument.player())
                        .executes(ctx -> {
                            chatSendService.exchange(playerName(ctx, "receiver"));
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> etellCommand(ChatSendService chatSendService) {
        return ClientCommands.literal("etell")
                .then(ClientCommands.argument("receiver", EntityArgument.player())
                        .then(ClientCommands.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    chatSendService.sendSessionMessage(
                                            playerName(ctx, "receiver"),
                                            StringArgumentType.getString(ctx, "message"));
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> gtellCommand(ChatSendService chatSendService,
                                                                                 GroupService groupService) {
        return ClientCommands.literal("gtell")
                .then(ClientCommands.argument("group", StringArgumentType.word())
                        .then(ClientCommands.argument("message", StringArgumentType.greedyString())
                                .executes(ctx -> {
                                    String group = StringArgumentType.getString(ctx, "group");
                                    try {
                                        GroupRecord record = groupService.find(group)
                                                .orElseThrow(() -> new IllegalStateException(
                                                        tr("text.krypt04mcg.command.error.no_group", group)));
                                        chatSendService.sendGroupMessage(record.name(), record.members(),
                                                StringArgumentType.getString(ctx, "message"));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> groupCommand(GroupService groupService) {
        return ClientCommands.literal("group")
                .then(ClientCommands.literal("create")
                        .then(ClientCommands.argument("name", StringArgumentType.word())
                                .then(ClientCommands.argument("members", StringArgumentType.greedyString())
                                        .executes(ctx -> {
                                            String name = StringArgumentType.getString(ctx, "name");
                                            List<String> members = parseMembers(StringArgumentType.getString(ctx, "members"));
                                            try {
                                                GroupRecord group = groupService.create(name, members);
                                                feedback(ctx.getSource(), tr("text.krypt04mcg.command.group_created",
                                                        group.name(), group.members().size()));
                                                return 1;
                                            } catch (Exception e) {
                                                error(ctx.getSource(), e);
                                                return 0;
                                            }
                                        }))))
                .then(ClientCommands.literal("list")
                        .executes(ctx -> {
                            try {
                                List<GroupRecord> groups = groupService.list();
                                if (groups.isEmpty()) {
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.no_groups"));
                                }
                                for (GroupRecord group : groups) {
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.group_list_entry",
                                            group.name(), String.join(", ", group.members())));
                                }
                                return groups.size();
                            } catch (Exception e) {
                                error(ctx.getSource(), e);
                                return 0;
                            }
                        }))
                .then(ClientCommands.literal("delete")
                        .then(ClientCommands.argument("name", StringArgumentType.word())
                                .executes(ctx -> {
                                    String name = StringArgumentType.getString(ctx, "name");
                                    try {
                                        groupService.delete(name);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.group_deleted", name));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> resendCommand(ChatSendService chatSendService) {
        return ClientCommands.literal("resend")
                .executes(ctx -> {
                    chatSendService.resendLatest();
                    return 1;
                })
                .then(ClientCommands.argument("messageId", StringArgumentType.word())
                        .executes(ctx -> {
                            chatSendService.resend(StringArgumentType.getString(ctx, "messageId"));
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> sessionCommand(ChatSendService chatSendService,
                                                                                   SessionService sessionService,
                                                                                   Krypt04McgConfig config) {
        return ClientCommands.literal("session")
                .then(ClientCommands.literal("list")
                        .executes(ctx -> {
                            try {
                                List<SessionRecord> sessions = sessionService.list();
                                if (sessions.isEmpty()) {
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.no_sessions"));
                                }
                                for (SessionRecord session : sessions) {
                                    String status = sessionService.isExpired(session, config.sessionTtlMinutes,
                                            config.maxMessagesPerSession, config.rotateAfterBytes)
                                            ? tr("text.krypt04mcg.command.session_expired")
                                            : tr("text.krypt04mcg.command.session_active");
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.session_list_entry",
                                            session.peer(), status, session.messageCount(), session.bytesUsed()));
                                }
                                return sessions.size();
                            } catch (Exception e) {
                                error(ctx.getSource(), e);
                                return 0;
                            }
                        }))
                .then(ClientCommands.literal("clear")
                        .then(ClientCommands.argument("player", StringArgumentType.word())
                                .executes(ctx -> {
                                    String player = StringArgumentType.getString(ctx, "player");
                                    try {
                                        sessionService.clear(player);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.session_cleared", player));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })))
                .then(ClientCommands.literal("refresh")
                        .then(ClientCommands.argument("player", EntityArgument.player())
                                .executes(ctx -> {
                                    chatSendService.exchange(playerName(ctx, "player"));
                                    return 1;
                                })));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> showAlgorithmsCommand(Krypt04McgConfig config,
                                                                                           KeyStoreService keyStoreService) {
        return ClientCommands.literal("showalgs")
                .executes(ctx -> {
                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.algorithms",
                            config.kemAlgorithm.identifier(), config.ephemeralKemAlgorithm.identifier(),
                            config.signatureAlgorithm.identifier(),
                            config.aeadAlgorithm.identifier()));
                    LocalKeyMaterial local = keyStoreService.local();
                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.active_key_algorithms",
                            local.kemPublicKey().algorithm(), local.signaturePublicKey().algorithm()));
                    return 1;
                });
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> statusCommand(KeyStoreService keyStoreService,
                                                                                  KeyTrustService keyTrustService,
                                                                                  SessionService sessionService,
                                                                                  DecryptionHistoryService decryptionHistoryService,
                                                                                  Krypt04McgConfig config) {
        return ClientCommands.literal("status")
                .then(ClientCommands.argument("player", EntityArgument.player())
                        .executes(ctx -> {
                            showStatus(ctx.getSource(), playerName(ctx, "player"),
                                    keyStoreService, keyTrustService, sessionService, decryptionHistoryService, config);
                            return 1;
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> keyCommand(KeyStoreService keyStoreService,
                                                                               KeyTrustService keyTrustService,
                                                                               Krypt04McgConfig config) {
        return ClientCommands.literal("key")
                .then(ClientCommands.literal("list")
                        .executes(ctx -> {
                            try {
                                List<PublicIdentity> identities = keyStoreService.listPublicIdentities();
                                if (identities.isEmpty()) {
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.no_imported_keys"));
                                }
                                for (PublicIdentity identity : identities) {
                                    feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_list_entry",
                                            identity.owner(), identity.kemPublicKey().fingerprint(),
                                            identity.signaturePublicKey().fingerprint()));
                                }
                                return identities.size();
                            } catch (Exception e) {
                                error(ctx.getSource(), e);
                                return 0;
                            }
                        }))
                .then(ClientCommands.literal("fingerprint")
                        .then(ClientCommands.argument("player", StringArgumentType.word())
                                .executes(ctx -> {
                                    String player = StringArgumentType.getString(ctx, "player");
                                    try {
                                        PublicIdentity identity = keyStoreService.findPublicIdentity(player)
                                                .orElseThrow(() -> new IllegalStateException(
                                                        tr("text.krypt04mcg.error.no_public_key", player)));
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_fingerprint",
                                                player, identity.kemPublicKey().fingerprint(),
                                                identity.signaturePublicKey().fingerprint()));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })))
                .then(ClientCommands.literal("export")
                        .executes(ctx -> {
                            try {
                                KeyStoreService.PublicKeyExport exported = keyStoreService.exportOwnPublicFile();
                                PublicIdentity identity = exported.identity();
                                feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_exported",
                                        exported.path(), identity.kemPublicKey().fingerprint(),
                                        identity.signaturePublicKey().fingerprint()));
                                return 1;
                            } catch (Exception e) {
                                error(ctx.getSource(), e);
                                return 0;
                            }
                        }))
                .then(ClientCommands.literal("import")
                        .then(ClientCommands.argument("player", StringArgumentType.word())
                                .then(ClientCommands.argument("data_or_file", StringArgumentType.greedyString())
                                        .executes(ctx -> {
                                            String player = StringArgumentType.getString(ctx, "player");
                                            try {
                                                PublicIdentity imported = keyStoreService.importPublicIdentity(player,
                                                        StringArgumentType.getString(ctx, "data_or_file"));
                                                keyTrustService.rememberTofu(player, imported);
                                                feedback(ctx.getSource(),
                                                        tr("text.krypt04mcg.command.key_imported_tofu", player));
                                                return 1;
                                            } catch (Exception e) {
                                                error(ctx.getSource(), e);
                                                return 0;
                                            }
                                        }))))
                .then(ClientCommands.literal("regenerate")
                        .executes(ctx -> {
                            feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_regenerate_confirm",
                                    keyStoreService.regenerationFingerprint(), config.kemAlgorithm.identifier(),
                                    config.signatureAlgorithm.identifier(), keyStoreService.regenerationFingerprint()));
                            return 1;
                        })
                        .then(ClientCommands.argument("fingerprint", StringArgumentType.word())
                                .executes(ctx -> {
                                    try {
                                        LocalKeyMaterial regenerated = keyStoreService.regenerate(
                                                StringArgumentType.getString(ctx, "fingerprint"),
                                                config.kemAlgorithm, config.signatureAlgorithm);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_regenerated",
                                                regenerated.kemPublicKey().fingerprint(),
                                                regenerated.signaturePublicKey().fingerprint(),
                                                regenerated.kemPublicKey().algorithm(),
                                                regenerated.signaturePublicKey().algorithm()));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })))
                .then(verifyCommand(keyStoreService, keyTrustService))
                .then(trustCommand("trust", keyStoreService, keyTrustService, TrustState.TOFU_TRUSTED))
                .then(trustCommand("distrust", keyStoreService, keyTrustService, TrustState.DISTRUSTED));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> trustCommand(String name, KeyStoreService keyStoreService,
                                                                                 KeyTrustService keyTrustService,
                                                                                 TrustState trustState) {
        return ClientCommands.literal(name)
                .then(ClientCommands.argument("player", StringArgumentType.word())
                        .executes(ctx -> {
                            String player = StringArgumentType.getString(ctx, "player");
                            try {
                                PublicIdentity identity = keyStoreService.findPublicIdentity(player)
                                        .orElseThrow(() -> new IllegalStateException(
                                                tr("text.krypt04mcg.error.no_public_key", player)));
                                switch (trustState) {
                                    case TOFU_TRUSTED -> {
                                        keyTrustService.markTofuTrusted(player, identity);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_trusted", player));
                                    }
                                    case DISTRUSTED -> {
                                        keyTrustService.markDistrusted(player, identity);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_distrusted", player));
                                    }
                                    default -> throw new IllegalArgumentException(
                                            tr("text.krypt04mcg.command.error.unsupported_trust_state", trustState));
                                }
                                return 1;
                            } catch (Exception e) {
                                error(ctx.getSource(), e);
                                return 0;
                            }
                        }));
    }

    private static LiteralArgumentBuilder<FabricClientCommandSource> verifyCommand(KeyStoreService keyStoreService,
                                                                                  KeyTrustService keyTrustService) {
        return ClientCommands.literal("verify")
                .then(ClientCommands.argument("player", StringArgumentType.word())
                        .then(ClientCommands.argument("fingerprint", StringArgumentType.word())
                                .executes(ctx -> {
                                    String player = StringArgumentType.getString(ctx, "player");
                                    String fingerprint = StringArgumentType.getString(ctx, "fingerprint");
                                    try {
                                        PublicIdentity identity = keyStoreService.findPublicIdentity(player)
                                                .orElseThrow(() -> new IllegalStateException(
                                                        tr("text.krypt04mcg.error.no_public_key", player)));
                                        if (!keyTrustService.fingerprintMatches(identity, fingerprint)) {
                                            feedback(ctx.getSource(),
                                                    tr("text.krypt04mcg.command.error.fingerprint_mismatch", player));
                                            return 0;
                                        }
                                        keyTrustService.markVerified(player, identity);
                                        feedback(ctx.getSource(), tr("text.krypt04mcg.command.key_verified", player));
                                        return 1;
                                    } catch (Exception e) {
                                        error(ctx.getSource(), e);
                                        return 0;
                                    }
                                })));
    }

    private static void showStatus(FabricClientCommandSource source, String player, KeyStoreService keyStoreService,
                                   KeyTrustService keyTrustService, SessionService sessionService,
                                   DecryptionHistoryService decryptionHistoryService, Krypt04McgConfig config) {
        try {
            Optional<PublicIdentity> identity = keyStoreService.findPublicIdentity(player);
            Optional<SessionRecord> session = sessionService.find(player);
            TrustState trustState = keyTrustService.trustState(player, identity.orElse(null));
            String keyStatus = identity.map(value -> tr("text.krypt04mcg.status.key_imported", trustStateLabel(trustState)))
                    .orElse(tr("text.krypt04mcg.status.key_not_imported"));
            String signatureStatus = identity.map(value -> value.signaturePublicKey() == null
                            ? tr("text.krypt04mcg.status.unavailable")
                            : tr("text.krypt04mcg.status.available"))
                    .orElse(tr("text.krypt04mcg.status.unavailable"));
            String sessionStatus = session.map(value -> {
                boolean expired = sessionService.isExpired(value, config.sessionTtlMinutes,
                        config.maxMessagesPerSession, config.rotateAfterBytes);
                String state = expired ? tr("text.krypt04mcg.status.session_expired")
                        : tr("text.krypt04mcg.status.session_established");
                return tr("text.krypt04mcg.status.session_details", state, value.sessionId(),
                        value.messageCount(), value.bytesUsed());
            }).orElse(tr("text.krypt04mcg.status.session_not_established"));
            String lastDecrypt = decryptionHistoryService.lastSuccess(player)
                    .map(STATUS_TIME_FORMATTER::format)
                    .orElse(tr("text.krypt04mcg.status.never"));

            feedback(source, tr("text.krypt04mcg.status.player", player));
            feedback(source, tr("text.krypt04mcg.status.public_key", keyStatus));
            identity.ifPresent(value -> feedback(source, tr("text.krypt04mcg.status.fingerprint",
                    value.kemPublicKey().fingerprint(), value.signaturePublicKey().fingerprint())));
            feedback(source, tr("text.krypt04mcg.status.signature", signatureStatus));
            feedback(source, tr("text.krypt04mcg.status.session", sessionStatus));
            feedback(source, tr("text.krypt04mcg.status.last_decrypt", lastDecrypt));
            feedback(source, tr("text.krypt04mcg.status.algorithms",
                    config.kemAlgorithm.identifier(), config.ephemeralKemAlgorithm.identifier(),
                    config.signatureAlgorithm.identifier(),
                    config.aeadAlgorithm.identifier()));
        } catch (Exception e) {
            error(source, e);
        }
    }

    private static List<String> parseMembers(String raw) {
        return Pattern.compile("[,\\s]+")
                .splitAsStream(raw.trim())
                .filter(value -> !value.isBlank())
                .toList();
    }

    private static String playerName(CommandContext<FabricClientCommandSource> ctx, String name) {
        String raw = rawArgument(ctx, name);
        if ("@s".equals(raw)) {
            return ctx.getSource().getPlayer().getGameProfile().name();
        }
        return raw;
    }

    private static String rawArgument(CommandContext<FabricClientCommandSource> ctx, String name) {
        for (ParsedCommandNode<FabricClientCommandSource> node : ctx.getNodes()) {
            if (name.equals(node.getNode().getName())) {
                StringRange range = node.getRange();
                return ctx.getInput().substring(range.getStart(), range.getEnd());
            }
        }
        throw new IllegalStateException(tr("text.krypt04mcg.error.generic", "Missing argument: " + name));
    }

    private static void feedback(FabricClientCommandSource source, String message) {
        source.sendFeedback(Component.literal(ClientMessages.messagePrefixWithSpace() + message));
    }

    private static void error(FabricClientCommandSource source, Exception e) {
        feedback(source, tr("text.krypt04mcg.error.generic", e.getMessage()));
    }

    private static String trustStateLabel(TrustState trustState) {
        return tr("text.krypt04mcg.trust." + trustState.name());
    }

    private static String tr(String key, Object... args) {
        return ClientMessages.tr(key, args);
    }
}
