package com.noise.protocol.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * BLAKE2s (256-bit) per RFC 7693. Pure Kotlin, no external dependencies.
 * 32-bit words, 10 rounds, 64-byte block.
 */
object Blake2s {
    private const val DIGEST_LEN = 32
    private const val BLOCK_LEN = 64
    private const val ROUNDS = 10

    private val IV = intArrayOf(
        0x6A09E667.toInt(), 0xBB67AE85.toInt(), 0x3C6EF372, 0xA54FF53A.toInt(),
        0x510E527F, 0x9B05688C.toInt(), 0x1F83D9AB.toInt(), 0x5BE0CD19
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
    )

    fun hash(data: ByteArray): ByteArray {
        val h = IV.copyOf()
        // Parameter block: fanout=1, depth=1, digestLen=32
        h[0] = h[0] xor (0x01010000 or DIGEST_LEN)

        var bytesCompressed = 0
        var offset = 0
        val remaining = data.size

        // Process full blocks
        while (remaining - offset > BLOCK_LEN) {
            bytesCompressed += BLOCK_LEN
            compress(h, data, offset, bytesCompressed, false)
            offset += BLOCK_LEN
        }

        // Final block (padded with zeros)
        val lastBlock = ByteArray(BLOCK_LEN)
        val lastLen = remaining - offset
        System.arraycopy(data, offset, lastBlock, 0, lastLen)
        bytesCompressed += lastLen
        compress(h, lastBlock, 0, bytesCompressed, true)

        // Serialize hash state to little-endian bytes
        val out = ByteArray(DIGEST_LEN)
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until DIGEST_LEN / 4) {
            buf.putInt(h[i])
        }
        return out
    }

    private fun compress(h: IntArray, block: ByteArray, offset: Int, t: Int, last: Boolean) {
        val v = IntArray(16)
        // v[0..7] = h[0..7]
        System.arraycopy(h, 0, v, 0, 8)
        // v[8..15] = IV[0..7]
        System.arraycopy(IV, 0, v, 8, 8)

        v[12] = v[12] xor t           // low word of counter
        v[13] = v[13] xor 0           // high word (0 for messages < 2^32 bytes)
        if (last) v[14] = v[14].inv() // finalization flag

        // Load message words (little-endian)
        val m = IntArray(16)
        val buf = ByteBuffer.wrap(block, offset, BLOCK_LEN).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 16) {
            m[i] = buf.getInt()
        }

        // 10 rounds of mixing
        for (round in 0 until ROUNDS) {
            val s = SIGMA[round]
            // Column step
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            // Diagonal step
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        // Finalize
        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(12)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(8)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(7)
    }
}

/**
 * BLAKE2b (512-bit) per RFC 7693. Pure Kotlin, no external dependencies.
 * 64-bit words, 12 rounds, 128-byte block.
 */
object Blake2b {
    private const val DIGEST_LEN = 64
    private const val BLOCK_LEN = 128
    private const val ROUNDS = 12

    private val IV = longArrayOf(
        0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, // 0xbb67ae8584caa73b
        0x3c6ef372fe94f82bL, -0x5ab00ac5a0e2c90fL, // 0xa54ff53a5f1d36f1
        0x510e527fade682d1L, -0x64fa9773d4c193e1L, // 0x9b05688c2b3e6c1f
        0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
    )

    fun hash(data: ByteArray): ByteArray {
        val h = IV.copyOf()
        // Parameter block: fanout=1, depth=1, digestLen=64
        h[0] = h[0] xor (0x01010000L or DIGEST_LEN.toLong())

        var bytesCompressed = 0L
        var offset = 0
        val remaining = data.size

        // Process full blocks
        while (remaining - offset > BLOCK_LEN) {
            bytesCompressed += BLOCK_LEN
            compress(h, data, offset, bytesCompressed, false)
            offset += BLOCK_LEN
        }

        // Final block (padded with zeros)
        val lastBlock = ByteArray(BLOCK_LEN)
        val lastLen = remaining - offset
        System.arraycopy(data, offset, lastBlock, 0, lastLen)
        bytesCompressed += lastLen
        compress(h, lastBlock, 0, bytesCompressed, true)

        // Serialize hash state to little-endian bytes
        val out = ByteArray(DIGEST_LEN)
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until DIGEST_LEN / 8) {
            buf.putLong(h[i])
        }
        return out
    }

    private fun compress(h: LongArray, block: ByteArray, offset: Int, t: Long, last: Boolean) {
        val v = LongArray(16)
        System.arraycopy(h, 0, v, 0, 8)
        System.arraycopy(IV, 0, v, 8, 8)

        v[12] = v[12] xor t       // low word of counter
        v[13] = v[13] xor 0L      // high word (0 for messages < 2^64 bytes)
        if (last) v[14] = v[14].inv()

        // Load message words (little-endian)
        val m = LongArray(16)
        val buf = ByteBuffer.wrap(block, offset, BLOCK_LEN).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 16) {
            m[i] = buf.getLong()
        }

        // 12 rounds of mixing (rounds 10-11 wrap sigma to indices 0-1)
        for (round in 0 until ROUNDS) {
            val s = SIGMA[round % 10]
            // Column step
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            // Diagonal step
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }
}
