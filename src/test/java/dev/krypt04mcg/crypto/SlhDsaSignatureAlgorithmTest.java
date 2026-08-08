package dev.krypt04mcg.crypto;

import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.fragment.FragmentReassembler;
import dev.krypt04mcg.fragment.FragmentService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.Fragment;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SlhDsaSignatureAlgorithmTest {
    private static final byte[] MESSAGE = "SLH-DSA variant test".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void installProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void exposesEveryBouncyCastleSlhDsaVariant() {
        assertEquals(24, slhDsaAlgorithms().size());
    }

    @Test
    void largestSlhDsaSignatureSurvivesDefaultPacketFragmentation() throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "alice-uuid", KemAlgorithm.ML_KEM_512,
                SignatureAlgorithm.SLH_DSA_SHAKE_256F_WITH_SHAKE256);
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "bob-uuid", KemAlgorithm.ML_KEM_512,
                SignatureAlgorithm.FALCON_512);
        PublicIdentity alicePublic = publicIdentity(alice);
        PublicIdentity bobPublic = publicIdentity(bob);
        EncryptedPacket packet = crypto.encryptFor(bobPublic, alice, "alice", "largest SLH-DSA signature", true);

        PacketCodec codec = new PacketCodec();
        FragmentService fragmentService = new FragmentService();
        List<String> encodedFragments = fragmentService.fragment(codec.encode(packet), packet.messageId(), 180);
        assertTrue(encodedFragments.size() > 256);
        assertTrue(encodedFragments.size() <= FragmentReassembler.DEFAULT_MAX_FRAGMENTS_PER_MESSAGE);

        FragmentReassembler reassembler = new FragmentReassembler();
        Optional<byte[]> reassembled = Optional.empty();
        for (String encodedFragment : encodedFragments) {
            Fragment fragment = fragmentService.parse(encodedFragment);
            reassembled = reassembler.accept(fragment);
        }

        EncryptedPacket decoded = codec.decode(reassembled.orElseThrow());
        assertEquals("largest SLH-DSA signature", crypto.decrypt(decoded, bob, alicePublic));
    }

    @TestFactory
    Stream<DynamicTest> everySlhDsaVariantGeneratesPersistsSignsAndVerifies() {
        return slhDsaAlgorithms().stream()
                .map(algorithm -> DynamicTest.dynamicTest(algorithm.identifier(), () -> exercise(algorithm)));
    }

    private static List<SignatureAlgorithm> slhDsaAlgorithms() {
        return Stream.of(SignatureAlgorithm.values())
                .filter(algorithm -> algorithm.identifier().startsWith("SLH-DSA-"))
                .toList();
    }

    private static void exercise(SignatureAlgorithm algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.jcaName(), algorithm.provider());
        generator.initialize(algorithm.parameterSpec());
        KeyPair generated = generator.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm.jcaName(), algorithm.provider());
        var privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(generated.getPrivate().getEncoded()));
        var publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(generated.getPublic().getEncoded()));

        Signature signer = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(algorithm.jcaName(), algorithm.provider());
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        assertTrue(verifier.verify(signature));
    }

    private static PublicIdentity publicIdentity(LocalKeyMaterial material) {
        return new PublicIdentity(material.kemPublicKey().owner(), material.kemPublicKey().uuid(),
                material.kemPublicKey(), material.signaturePublicKey());
    }
}
