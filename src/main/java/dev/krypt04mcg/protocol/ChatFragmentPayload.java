package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

public record ChatFragmentPayload(String receiver, String fragment, int version) implements CustomPacketPayload {
    public static final Identifier CHANNEL = Identifier.fromNamespaceAndPath("krypt04mcg", "chat_fragment");
    public static final Type<ChatFragmentPayload> TYPE = new Type<>(CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, ChatFragmentPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.receiver());
                buf.writeUtf(payload.fragment());
                buf.writeVarInt(payload.version());
            },
            buf -> new ChatFragmentPayload(buf.readUtf(), buf.readUtf(), buf.readVarInt()));

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
