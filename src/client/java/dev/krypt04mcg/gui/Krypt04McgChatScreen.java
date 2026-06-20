package dev.krypt04mcg.gui;

import dev.krypt04mcg.chat.ChatConversationStore;
import dev.krypt04mcg.chat.ChatSendService;
import dev.krypt04mcg.model.GroupRecord;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.service.GroupService;
import dev.krypt04mcg.service.KeyStoreService;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.AbstractWidget;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.narration.NarrationElementOutput;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class Krypt04McgChatScreen extends Screen {
    private static final int PANEL_COLOR = 0xE812171C;
    private static final int HEADER_COLOR = 0xF01B2730;
    private static final int LIST_COLOR = 0xD91D252D;
    private static final int SELECTED_COLOR = 0xFF2D5F73;
    private static final int OUTGOING_COLOR = 0xFF8DDBA4;
    private static final int INCOMING_COLOR = 0xFFE6EEF7;
    private static final int BUTTON_GAP = 6;

    private final ChatSendService chatSendService;
    private final KeyStoreService keyStoreService;
    private final GroupService groupService;
    private final ChatConversationStore conversationStore;
    private final List<Target> targets = new ArrayList<>();
    private final List<TargetRowWidget> targetRows = new ArrayList<>();
    private EditBox playerBox;
    private EditBox messageBox;
    private int selectedTarget;
    private int panelX;
    private int panelY;
    private int panelWidth;
    private int panelHeight;
    private int listWidth;
    private int listScrollOffset;

    public Krypt04McgChatScreen(ChatSendService chatSendService, KeyStoreService keyStoreService,
                                GroupService groupService,
                                ChatConversationStore conversationStore) {
        super(Component.translatable("text.krypt04mcg.gui.title"));
        this.chatSendService = chatSendService;
        this.keyStoreService = keyStoreService;
        this.groupService = groupService;
        this.conversationStore = conversationStore;
    }

    @Override
    protected void init() {
        loadTargets();
        panelWidth = Math.min(620, width - 32);
        panelHeight = Math.min(320, height - 32);
        panelX = (width - panelWidth) / 2;
        panelY = Math.max(16, (height - panelHeight) / 2);
        listWidth = Math.min(170, Math.max(126, panelWidth / 3));

        addTargetRows();

        int rightX = panelX + listWidth + 14;
        int rightWidth = panelWidth - listWidth - 28;
        playerBox = new EditBox(font, rightX, panelY + 38, rightWidth, 20,
                Component.translatable("text.krypt04mcg.gui.player"));
        playerBox.setMaxLength(32);
        playerBox.setHint(Component.translatable("text.krypt04mcg.gui.player_hint"));
        if (!targets.isEmpty()) {
            selectedTarget = Math.min(selectedTarget, targets.size() - 1);
            playerBox.setValue(targets.get(selectedTarget).inputName());
        }
        addRenderableWidget(playerBox);

        int buttonWidth = Math.max(62, (rightWidth - BUTTON_GAP * 3) / 4);
        int buttonY = panelY + panelHeight - 28;
        messageBox = new EditBox(font, rightX, panelY + panelHeight - 54, rightWidth, 20,
                Component.translatable("text.krypt04mcg.gui.message"));
        messageBox.setMaxLength(512);
        messageBox.setHint(Component.translatable("text.krypt04mcg.gui.message_hint"));
        addRenderableWidget(messageBox);
        setInitialFocus(messageBox);

        addRenderableWidget(Button.builder(Component.translatable("text.krypt04mcg.gui.exchange"), button -> exchange())
                .bounds(rightX, buttonY, buttonWidth, 20)
                .build());
        addRenderableWidget(Button.builder(Component.translatable("text.krypt04mcg.gui.send_unsigned"), button -> sendUnsigned())
                .bounds(rightX + buttonWidth + BUTTON_GAP, buttonY, buttonWidth, 20)
                .build());
        addRenderableWidget(Button.builder(Component.translatable("text.krypt04mcg.gui.session"), button -> sendSession())
                .bounds(rightX + (buttonWidth + BUTTON_GAP) * 2, buttonY, buttonWidth, 20)
                .build());
        addRenderableWidget(Button.builder(Component.translatable("text.krypt04mcg.gui.send"), button -> sendSigned())
                .bounds(rightX + rightWidth - buttonWidth, buttonY, buttonWidth, 20)
                .build());
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(panelX, panelY, panelX + panelWidth, panelY + panelHeight, PANEL_COLOR);
        graphics.fill(panelX, panelY, panelX + panelWidth, panelY + 26, HEADER_COLOR);
        graphics.fill(panelX, panelY + 26, panelX + listWidth, panelY + panelHeight, LIST_COLOR);

        Target target = currentTarget();
        String receiver = target.displayName();
        int rightX = panelX + listWidth + 14;
        int rightWidth = panelWidth - listWidth - 28;
        int historyTop = panelY + 78;
        int historyBottom = panelY + panelHeight - 62;
        graphics.fill(rightX, historyTop, rightX + rightWidth, historyBottom, 0x6A071016);

        graphics.nextStratum();
        graphics.text(font, title, panelX + 12, panelY + 9, 0xE8F3FF, false);
        graphics.text(font, Component.translatable("text.krypt04mcg.gui.players"), panelX + 12, panelY + 36, 0xAFC4D6, false);
        graphics.text(font, Component.translatable("text.krypt04mcg.gui.player"), rightX, panelY + 28, 0xAFC4D6, false);
        graphics.text(font, Component.translatable("text.krypt04mcg.gui.conversation", receiver.isEmpty() ? "-" : receiver),
                rightX, panelY + 66, 0xAFC4D6, false);
        drawHistory(graphics, receiver, rightX + 8, historyTop + 8, rightWidth - 16, historyBottom - historyTop - 16);

        if (targets.isEmpty()) {
            graphics.text(font, Component.translatable("text.krypt04mcg.gui.no_players"), panelX + 12,
                    panelY + 56, 0xD8A657, false);
        }
        super.extractRenderState(graphics, mouseX, mouseY, partialTick);
    }

    @Override
    public boolean keyPressed(KeyEvent event) {
        if (event.key() == 257 || event.key() == 335) {
            sendSigned();
            return true;
        }
        return super.keyPressed(event);
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (mouseX >= panelX && mouseX <= panelX + listWidth
                && mouseY >= panelY + 26 && mouseY <= panelY + panelHeight) {
            int maxOffset = Math.max(0, targets.size() - visibleTargetRows());
            listScrollOffset = Math.clamp(listScrollOffset - (int) Math.signum(scrollY), 0, maxOffset);
            refreshTargetRows();
            return true;
        }
        return super.mouseScrolled(mouseX, mouseY, scrollX, scrollY);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    private void addTargetRows() {
        targetRows.clear();
        int rowHeight = 20;
        int listX = panelX + 8;
        int listY = panelY + 50;
        for (int i = 0; i < visibleTargetRows(); i++) {
            TargetRowWidget row = new TargetRowWidget(i, listX, listY + i * rowHeight, listWidth - 16, 18);
            targetRows.add(row);
            addRenderableWidget(row);
        }
    }

    private int visibleTargetRows() {
        return Math.max(0, (panelHeight - 64) / 20);
    }

    private void selectTarget(int index) {
        if (index < 0 || index >= targets.size()) {
            return;
        }
        selectedTarget = index;
        ensureSelectedTargetVisible();
        refreshTargetRows();
        playerBox.setValue(targets.get(selectedTarget).inputName());
    }

    private void ensureSelectedTargetVisible() {
        int visibleRows = visibleTargetRows();
        if (selectedTarget < listScrollOffset) {
            listScrollOffset = selectedTarget;
        } else if (selectedTarget >= listScrollOffset + visibleRows) {
            listScrollOffset = selectedTarget - visibleRows + 1;
        }
        listScrollOffset = Math.clamp(listScrollOffset, 0, Math.max(0, targets.size() - visibleRows));
        refreshTargetRows();
    }

    private void refreshTargetRows() {
        for (TargetRowWidget row : targetRows) {
            row.refresh();
        }
    }

    private void drawHistory(GuiGraphicsExtractor graphics, String receiver, int x, int y, int width, int height) {
        if (receiver.isEmpty()) {
            graphics.text(font, Component.translatable("text.krypt04mcg.gui.empty_conversation"), x, y, 0x8899A6, false);
            return;
        }
        Target target = currentTarget();
        List<String> lines = historyLines(target, width);
        int maxLines = Math.max(1, height / 10);
        int start = Math.max(0, lines.size() - maxLines);
        for (int i = start; i < lines.size(); i++) {
            String line = lines.get(i);
            int color = line.startsWith(">") ? OUTGOING_COLOR : INCOMING_COLOR;
            graphics.text(font, line, x, y + (i - start) * 10, color, false);
        }
    }

    private List<String> historyLines(Target target, int width) {
        List<String> lines = new ArrayList<>();
        List<ChatConversationStore.Entry> entries = target.group()
                ? conversationStore.messagesForGroup(target.name())
                : conversationStore.messagesFor(target.name());
        for (ChatConversationStore.Entry entry : entries) {
            String prefix = entry.outgoing() ? "> " : "< ";
            for (String wrapped : wrap(prefix + entry.message(), width)) {
                lines.add(wrapped);
            }
        }
        return lines;
    }

    private List<String> wrap(String text, int maxWidth) {
        List<String> lines = new ArrayList<>();
        String remaining = text;
        while (font.width(remaining) > maxWidth) {
            String line = font.plainSubstrByWidth(remaining, maxWidth);
            if (line.isEmpty()) {
                int end = remaining.offsetByCodePoints(0, 1);
                line = remaining.substring(0, end);
            }
            int breakAt = line.lastIndexOf(' ');
            if (breakAt > 2 && line.length() < remaining.length()) {
                line = line.substring(0, breakAt);
            }
            lines.add(line);
            remaining = remaining.substring(line.length()).stripLeading();
            if (!remaining.isEmpty()) {
                remaining = "  " + remaining;
            }
        }
        lines.add(remaining);
        return lines;
    }

    private String truncate(String text, int maxWidth) {
        if (font.width(text) <= maxWidth) {
            return text;
        }
        String suffix = "...";
        return font.plainSubstrByWidth(text, Math.max(1, maxWidth - font.width(suffix))) + suffix;
    }

    private void sendSigned() {
        sendKem(true);
    }

    private void sendUnsigned() {
        sendKem(false);
    }

    private void sendKem(boolean sign) {
        Target target = currentTarget();
        String message = messageBox.getValue().trim();
        if (target.name().isEmpty() || message.isEmpty()) {
            return;
        }
        if (target.group()) {
            if (target.members().isEmpty()) {
                return;
            }
            chatSendService.sendGroupMessage(target.name(), target.members(), message);
            conversationStore.outgoingGroup(target.name(), message);
            rememberTarget(target);
            messageBox.setValue("");
        } else if (chatSendService.sendKemMessage(target.name(), message, sign)) {
            conversationStore.outgoing(target.name(), message);
            rememberTarget(target);
            messageBox.setValue("");
        }
        messageBox.setFocused(true);
    }

    private void sendSession() {
        Target target = currentTarget();
        String message = messageBox.getValue().trim();
        if (target.group() || target.name().isEmpty() || message.isEmpty()) {
            return;
        }
        if (chatSendService.sendSessionMessage(target.name(), message)) {
            conversationStore.outgoing(target.name(), message);
            rememberTarget(target);
            messageBox.setValue("");
        }
        messageBox.setFocused(true);
    }

    private void exchange() {
        Target target = currentTarget();
        if (!target.group() && !target.name().isEmpty()) {
            if (chatSendService.exchange(target.name())) {
                rememberTarget(target);
            }
        }
    }

    private Target currentTarget() {
        String value = playerBox == null ? "" : playerBox.getValue().trim();
        if (value.startsWith("#")) {
            String groupName = value.substring(1).trim();
            return findGroupTarget(groupName).orElse(new Target(groupName, true, List.of()));
        }
        if (selectedTarget >= 0 && selectedTarget < targets.size()) {
            Target selected = targets.get(selectedTarget);
            if (selected.inputName().equalsIgnoreCase(value)) {
                return selected;
            }
        }
        return new Target(value, false, List.of());
    }

    private void rememberTarget(Target target) {
        if (target.name().isEmpty()) {
            return;
        }
        if (targets.stream().noneMatch(value -> value.sameTarget(target))) {
            targets.add(target);
            targets.sort(Target::compareTo);
            refreshTargetRows();
        }
    }

    private void loadTargets() {
        targets.clear();
        try {
            String localOwner = keyStoreService.local().kemPublicKey().owner();
            Set<String> names = new LinkedHashSet<>();
            keyStoreService.listPublicIdentities().stream()
                    .map(PublicIdentity::owner)
                    .filter(owner -> owner != null && !owner.isBlank())
                    .filter(owner -> !owner.equalsIgnoreCase(localOwner))
                    .forEach(names::add);
            names.addAll(conversationStore.peers());
            names.stream()
                    .sorted(Comparator.comparing(String::toLowerCase))
                    .map(name -> new Target(name, false, List.of()))
                    .forEach(targets::add);
            Set<String> groupNames = new LinkedHashSet<>(conversationStore.groups());
            for (GroupRecord group : groupService.list()) {
                groupNames.add(group.name());
                rememberTarget(new Target(group.name(), true, group.members()));
            }
            groupNames.stream()
                    .map(name -> findGroupTarget(name).orElse(new Target(name, true, List.of())))
                    .forEach(this::rememberTarget);
        } catch (Exception e) {
            Minecraft.getInstance().gui.hud.getChat().addClientSystemMessage(Component.literal("[Krypt04Mcg][ERROR] " + e.getMessage()));
        }
    }

    private Optional<Target> findGroupTarget(String groupName) {
        try {
            return groupService.find(groupName)
                    .map(group -> new Target(group.name(), true, group.members()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private record Target(String name, boolean group, List<String> members) implements Comparable<Target> {
        private String inputName() {
            return group ? "#" + name : name;
        }

        private String displayName() {
            return inputName();
        }

        private boolean sameTarget(Target other) {
            return group == other.group && name.equalsIgnoreCase(other.name);
        }

        @Override
        public int compareTo(Target other) {
            if (group != other.group) {
                return group ? 1 : -1;
            }
            return name.compareToIgnoreCase(other.name);
        }
    }

    private final class TargetRowWidget extends AbstractWidget {
        private final int visibleIndex;

        private TargetRowWidget(int visibleIndex, int x, int y, int width, int height) {
            super(x, y, width, height, Component.empty());
            this.visibleIndex = visibleIndex;
            refresh();
        }

        @Override
        protected void extractWidgetRenderState(GuiGraphicsExtractor graphics, int mouseX, int mouseY, float partialTick) {
            int targetIndex = targetIndex();
            if (targetIndex >= targets.size()) {
                return;
            }
            boolean selected = targetIndex == selectedTarget;
            if (selected || isHovered()) {
                graphics.fill(getX(), getY(), getRight(), getBottom(), selected ? SELECTED_COLOR : 0x66344952);
            }
            graphics.nextStratum();
            graphics.text(font, truncate(targets.get(targetIndex).displayName(), getWidth() - 8),
                    getX() + 6, getY() + 5, 0xFFFFFFFF, false);
        }

        @Override
        public void onClick(MouseButtonEvent event, boolean doubleClick) {
            int targetIndex = targetIndex();
            if (targetIndex < targets.size()) {
                selectTarget(targetIndex);
            }
        }

        @Override
        protected void updateWidgetNarration(NarrationElementOutput narrationElementOutput) {
            defaultButtonNarrationText(narrationElementOutput);
        }

        private void refresh() {
            int targetIndex = targetIndex();
            visible = targetIndex < targets.size();
            setMessage(visible
                    ? Component.translatable("text.krypt04mcg.gui.target", targets.get(targetIndex).displayName())
                    : Component.empty());
        }

        private int targetIndex() {
            return listScrollOffset + visibleIndex;
        }
    }
}
