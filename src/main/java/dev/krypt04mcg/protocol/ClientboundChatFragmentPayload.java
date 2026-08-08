package dev.krypt04mcg.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

public record ClientboundChatFragmentPayload(String sender, String fragment, int version)
        implements CustomPacketPayload {
    public static final Type<ClientboundChatFragmentPayload> TYPE = new Type<>(ChatFragmentPayload.CHANNEL);
    public static final StreamCodec<FriendlyByteBuf, ClientboundChatFragmentPayload> CODEC = StreamCodec.of(
            (buf, payload) -> {
                buf.writeUtf(payload.sender());
                buf.writeUtf(payload.fragment());
                buf.writeVarInt(payload.version());
            },
            buf -> new ClientboundChatFragmentPayload(buf.readUtf(), buf.readUtf(), buf.readVarInt()));

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
