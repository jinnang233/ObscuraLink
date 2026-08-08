package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

public record ServerboundChatFragmentPayload(String receiver, String fragment, int version)
        implements CustomPacketPayload {
    public static final Type<ServerboundChatFragmentPayload> TYPE = new Type<>(ChatFragmentPayload.CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, ServerboundChatFragmentPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.receiver());
                buf.writeUtf(payload.fragment());
                buf.writeVarInt(payload.version());
            },
            buf -> new ServerboundChatFragmentPayload(buf.readUtf(), buf.readUtf(), buf.readVarInt()));

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
