/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import static org.junit.Assert.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for {@link AesCipherFactory#computeChunkIVForAesGcm}, the per-chunk GCM nonce derivation
 * used by the encrypted translog.
 *
 * <p>AES-GCM requires a unique nonce per (key) message. The translog encrypts each 8&nbsp;KB chunk
 * as an independent GCM message under one per-file key, so each chunk must get a distinct nonce.
 * GCM derives its 96-bit nonce from the first 12 bytes of the supplied IV; these tests assert that
 * the chunk index varies those bytes (and therefore the keystream/tag), that distinct files get
 * distinct nonces, and that the construction round-trips.
 */
public class ChunkIVDerivationTests extends OpenSearchTestCase {

    private static byte[] baseIV(int seed) {
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) {
            iv[i] = (byte) (seed * 31 + i * 7 + 1);
        }
        return iv;
    }

    /** Each chunk index yields a distinct 12-byte GCM nonce within a file. */
    public void testNoncesUniqueWithinFile() {
        byte[] base = baseIV(1);
        Set<String> seen = new HashSet<>();
        for (long idx = 0; idx < 200_000; idx++) {
            byte[] nonce = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(base, idx), 12);
            assertTrue("duplicate nonce at chunk " + idx, seen.add(Arrays.toString(nonce)));
        }
    }

    /** The chunk index must land in the GCM nonce bytes (0..11), not only the unused trailing bytes. */
    public void testChunkIndexVariesNonceBytes() {
        byte[] base = baseIV(2);
        byte[] n0 = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(base, 0), 12);
        byte[] n1 = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(base, 1), 12);
        assertFalse("chunk index must change the 12-byte GCM nonce", Arrays.equals(n0, n1));
    }

    /** Distinct files (distinct baseIV) get distinct nonces for the same chunk index. */
    public void testNonceDiffersAcrossFiles() {
        byte[] baseA = baseIV(3);
        byte[] baseB = baseIV(4);
        byte[] a = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(baseA, 1364), 12);
        byte[] b = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(baseB, 1364), 12);
        assertFalse("same chunk index in different files must use different nonces", Arrays.equals(a, b));
    }

    /** Two chunks must encrypt under distinct IVs (so they do not share a GCM keystream). */
    public void testDistinctIvProducesDistinctKeystream() throws Exception {
        byte[] key32 = new byte[32];
        Arrays.fill(key32, (byte) 0x5C);
        SecretKeySpec key256 = new SecretKeySpec(key32, "AES");
        byte[] base = baseIV(6);

        byte[] p0 = "chunk-zero-plaintext-AAAAAAAAAAAA".getBytes(StandardCharsets.UTF_8);
        byte[] p1 = "chunk-one--plaintext-BBBBBBBBBBBB".getBytes(StandardCharsets.UTF_8);

        byte[] c0 = AesGcmCipherFactory.encryptWithTag(key256, AesCipherFactory.computeChunkIVForAesGcm(base, 0), p0, p0.length);
        byte[] c1 = AesGcmCipherFactory.encryptWithTag(key256, AesCipherFactory.computeChunkIVForAesGcm(base, 1), p1, p1.length);

        // ciphertext bodies (strip 16-byte tag)
        byte[] body0 = Arrays.copyOf(c0, p0.length);
        byte[] body1 = Arrays.copyOf(c1, p1.length);

        // If the two chunks shared an IV, body0 ^ body1 would equal p0 ^ p1 (identical keystreams
        // cancel). With distinct per-chunk IVs that identity must NOT hold.
        byte[] xorBodies = xor(body0, body1);
        byte[] xorPlain = xor(p0, p1);
        assertFalse("chunks 0 and 1 produced the same keystream (shared IV)", Arrays.equals(xorBodies, xorPlain));
    }

    /** Round-trip: encrypt then decrypt each chunk with its own derived nonce. */
    public void testGcmRoundTripPerChunk() throws Exception {
        byte[] key32 = new byte[32];
        Arrays.fill(key32, (byte) 0x11);
        SecretKeySpec key = new SecretKeySpec(key32, "AES");
        byte[] base = baseIV(7);

        for (long idx : new long[] { 0, 1, 2, 1364, 0xFFFFFFFFL }) {
            byte[] pt = ("payload-for-chunk-" + idx + "-padding").getBytes(StandardCharsets.UTF_8);
            byte[] iv = AesCipherFactory.computeChunkIVForAesGcm(base, idx);
            byte[] ct = AesGcmCipherFactory.encryptWithTag(key, iv, pt, pt.length);
            byte[] dt = AesGcmCipherFactory.decryptWithTag(key, AesCipherFactory.computeChunkIVForAesGcm(base, idx), ct);
            assertArrayEquals("round-trip failed at chunk " + idx, pt, dt);
        }
    }

    /**
     * Backward compatibility property: a chunk written with the legacy IV scheme
     * (computeOffsetIVForAesGcmEncrypted, whose GCM nonce does not vary per chunk) fails
     * authentication under the new per-chunk nonce, so the reader's fallback to the legacy nonce is
     * both necessary and sufficient to recover it. This holds for every chunk index (the new and
     * legacy nonces differ even at index 0).
     */
    public void testLegacyChunkFailsNewNonceButRecoversWithLegacyNonce() throws Exception {
        byte[] key32 = new byte[32];
        Arrays.fill(key32, (byte) 0x22);
        SecretKeySpec key = new SecretKeySpec(key32, "AES");
        byte[] base = baseIV(8);

        // Include chunk 0 explicitly: it ALSO needs the fallback (new vs legacy nonce differ at 0).
        for (long chunkIndex : new long[] { 0, 1, 1364 }) {
            long legacyOffset = chunkIndex * 8192L;
            byte[] pt = ("old-format-chunk-" + chunkIndex + "-data").getBytes(StandardCharsets.UTF_8);
            // legacy write: the legacy IV scheme (GCM nonce does not vary per chunk)
            byte[] legacyCt = AesGcmCipherFactory.encryptWithTag(
                key, AesCipherFactory.computeOffsetIVForAesGcmEncrypted(base, legacyOffset), pt, pt.length);

            // new nonce must NOT authenticate the legacy ciphertext (even at chunk 0)
            boolean newNonceFailed = false;
            try {
                AesGcmCipherFactory.decryptWithTag(key, AesCipherFactory.computeChunkIVForAesGcm(base, chunkIndex), legacyCt);
            } catch (AesGcmCipherFactory.JavaCryptoException expected) {
                newNonceFailed = true;
            }
            assertTrue("legacy ciphertext unexpectedly authenticated under new nonce at chunk " + chunkIndex, newNonceFailed);

            // legacy nonce (the reader's fallback) recovers it
            byte[] recovered = AesGcmCipherFactory.decryptWithTag(
                key, AesCipherFactory.computeOffsetIVForAesGcmEncrypted(base, legacyOffset), legacyCt);
            assertArrayEquals("fallback must recover legacy chunk " + chunkIndex, pt, recovered);
        }
    }

    /**
     * The new per-chunk nonce differs from the legacy nonce for EVERY chunk index, including 0:
     * the legacy IV leaves nonce bytes 8..11 as {@code baseIV[8..11]} (its counter goes into bytes
     * 12..15, outside the 12-byte GCM nonce), whereas the new IV writes the chunk index there. This
     * is why the read-side fallback must apply to all chunks of a pre-upgrade file, not just chunk &gt; 0.
     */
    public void testNewNonceDiffersFromLegacyForAllChunksIncludingZero() {
        byte[] base = baseIV(9);
        for (long idx : new long[] { 0, 1, 1364 }) {
            byte[] neu = Arrays.copyOf(AesCipherFactory.computeChunkIVForAesGcm(base, idx), 12);
            byte[] legacy = Arrays.copyOf(AesCipherFactory.computeOffsetIVForAesGcmEncrypted(base, idx * 8192L), 12);
            assertFalse("new and legacy GCM nonce must differ at chunk " + idx, Arrays.equals(neu, legacy));
        }
    }

    public void testRejectsOutOfRangeChunkIndex() {
        byte[] base = baseIV(10);
        expectThrows(IllegalArgumentException.class, () -> AesCipherFactory.computeChunkIVForAesGcm(base, -1L));
        expectThrows(IllegalArgumentException.class, () -> AesCipherFactory.computeChunkIVForAesGcm(base, 0x100000000L));
    }

    public void testRejectsShortBaseIV() {
        expectThrows(IllegalArgumentException.class, () -> AesCipherFactory.computeChunkIVForAesGcm(new byte[8], 0L));
        expectThrows(IllegalArgumentException.class, () -> AesCipherFactory.computeChunkIVForAesGcm(null, 0L));
    }

    private static byte[] xor(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        byte[] r = new byte[n];
        for (int i = 0; i < n; i++) {
            r[i] = (byte) (a[i] ^ b[i]);
        }
        return r;
    }
}
