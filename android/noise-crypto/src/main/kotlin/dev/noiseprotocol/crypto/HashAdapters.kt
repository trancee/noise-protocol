package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.NoiseHashFunction
import dev.noiseprotocol.core.NoiseKeyDerivationFunction

interface NoiseDigest {
    val digestLength: Int
    val blockLength: Int
    fun digest(data: ByteArray): ByteArray
}

abstract class DigestHashAdapter(
    private val digest: NoiseDigest
) : NoiseHashFunction {
    final override val hashLength: Int = digest.digestLength

    final override fun hash(data: ByteArray): ByteArray = digest.digest(data)
}

class Sha256HashAdapter : DigestHashAdapter(SHA256_DIGEST)

class Sha512HashAdapter : DigestHashAdapter(SHA512_DIGEST)

class Blake2sHashAdapter : DigestHashAdapter(BLAKE2S_DIGEST)

class Blake2bHashAdapter : DigestHashAdapter(BLAKE2B_DIGEST)

abstract class HmacHkdfAdapter(
    private val digest: NoiseDigest,
    private val outputLength: Int
) : NoiseKeyDerivationFunction {
    final override fun hkdf(
        chainingKey: ByteArray,
        inputKeyMaterial: ByteArray,
        outputs: Int
    ): List<ByteArray> {
        require(outputs in 1..255) { "HKDF output count must be between 1 and 255." }

        val pseudorandomKey = hmac(chainingKey, inputKeyMaterial)
        val result = ArrayList<ByteArray>(outputs)
        var previous = ByteArray(0)

        for (counter in 1..outputs) {
            previous = hmac(pseudorandomKey, previous + counter.toByte())
            result += previous.copyOf(outputLength)
        }
        return result
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val normalizedKey = ByteArray(digest.blockLength)
        val material = if (key.size > digest.blockLength) digest.digest(key) else key
        material.copyInto(normalizedKey)

        val outerPad = ByteArray(digest.blockLength) { index ->
            (normalizedKey[index].toInt() xor 0x5C).toByte()
        }
        val innerPad = ByteArray(digest.blockLength) { index ->
            (normalizedKey[index].toInt() xor 0x36).toByte()
        }

        val innerHash = digest.digest(innerPad + data)
        return digest.digest(outerPad + innerHash)
    }
}

class HkdfSha256Adapter : HmacHkdfAdapter(
    digest = SHA256_DIGEST,
    outputLength = 32
)

class HkdfSha512Adapter : HmacHkdfAdapter(
    digest = SHA512_DIGEST,
    outputLength = 64
)

class HkdfBlake2sAdapter : HmacHkdfAdapter(
    digest = BLAKE2S_DIGEST,
    outputLength = 32
)

class HkdfBlake2bAdapter : HmacHkdfAdapter(
    digest = BLAKE2B_DIGEST,
    outputLength = 64
)

private val SHA256_DIGEST: NoiseDigest = object : NoiseDigest {
    override val digestLength: Int = 32
    override val blockLength: Int = 64

    override fun digest(data: ByteArray): ByteArray {
        val h = intArrayOf(
            0x6a09e667u.toInt(),
            0xbb67ae85u.toInt(),
            0x3c6ef372u.toInt(),
            0xa54ff53au.toInt(),
            0x510e527fu.toInt(),
            0x9b05688cu.toInt(),
            0x1f83d9abu.toInt(),
            0x5be0cd19u.toInt()
        )

        val bitLength = data.size.toLong() * 8L
        val paddedLength = ((data.size + 9 + 63) / 64) * 64
        val padded = ByteArray(paddedLength)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        writeLongBigEndian(padded, paddedLength - 8, bitLength)

        val w = IntArray(64)
        var offset = 0
        while (offset < padded.size) {
            for (i in 0 until 16) {
                w[i] = readIntBigEndian(padded, offset + i * 4)
            }
            for (i in 16 until 64) {
                val s0 = w[i - 15].rotateRight(7) xor w[i - 15].rotateRight(18) xor (w[i - 15] ushr 3)
                val s1 = w[i - 2].rotateRight(17) xor w[i - 2].rotateRight(19) xor (w[i - 2] ushr 10)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h[0]
            var b = h[1]
            var c = h[2]
            var d = h[3]
            var e = h[4]
            var f = h[5]
            var g = h[6]
            var hh = h[7]

            for (i in 0 until 64) {
                val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = hh + s1 + ch + SHA256_K[i] + w[i]
                val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                hh = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            h[0] += a
            h[1] += b
            h[2] += c
            h[3] += d
            h[4] += e
            h[5] += f
            h[6] += g
            h[7] += hh

            offset += 64
        }

        val result = ByteArray(32)
        for (i in h.indices) {
            writeIntBigEndian(result, i * 4, h[i])
        }
        return result
    }
}

private val SHA512_DIGEST: NoiseDigest = object : NoiseDigest {
    override val digestLength: Int = 64
    override val blockLength: Int = 128

    override fun digest(data: ByteArray): ByteArray {
        val h = longArrayOf(
            0x6a09e667f3bcc908uL.toLong(),
            0xbb67ae8584caa73buL.toLong(),
            0x3c6ef372fe94f82buL.toLong(),
            0xa54ff53a5f1d36f1uL.toLong(),
            0x510e527fade682d1uL.toLong(),
            0x9b05688c2b3e6c1fuL.toLong(),
            0x1f83d9abfb41bd6buL.toLong(),
            0x5be0cd19137e2179uL.toLong()
        )

        val bitLength = data.size.toLong() * 8L
        val paddedLength = ((data.size + 17 + 127) / 128) * 128
        val padded = ByteArray(paddedLength)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        writeLongBigEndian(padded, paddedLength - 16, 0L)
        writeLongBigEndian(padded, paddedLength - 8, bitLength)

        val w = LongArray(80)
        var offset = 0
        while (offset < padded.size) {
            for (i in 0 until 16) {
                w[i] = readLongBigEndian(padded, offset + i * 8)
            }
            for (i in 16 until 80) {
                val s0 = w[i - 15].rotateRight(1) xor w[i - 15].rotateRight(8) xor (w[i - 15] ushr 7)
                val s1 = w[i - 2].rotateRight(19) xor w[i - 2].rotateRight(61) xor (w[i - 2] ushr 6)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h[0]
            var b = h[1]
            var c = h[2]
            var d = h[3]
            var e = h[4]
            var f = h[5]
            var g = h[6]
            var hh = h[7]

            for (i in 0 until 80) {
                val s1 = e.rotateRight(14) xor e.rotateRight(18) xor e.rotateRight(41)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = hh + s1 + ch + SHA512_K[i] + w[i]
                val s0 = a.rotateRight(28) xor a.rotateRight(34) xor a.rotateRight(39)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                hh = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            h[0] += a
            h[1] += b
            h[2] += c
            h[3] += d
            h[4] += e
            h[5] += f
            h[6] += g
            h[7] += hh

            offset += 128
        }

        val result = ByteArray(64)
        for (i in h.indices) {
            writeLongBigEndian(result, i * 8, h[i])
        }
        return result
    }
}

private val BLAKE2S_DIGEST: NoiseDigest = object : NoiseDigest {
    override val digestLength: Int = 32
    override val blockLength: Int = 64

    override fun digest(data: ByteArray): ByteArray {
        val h = BLAKE2S_IV.copyOf()
        h[0] = h[0] xor 0x01010020u.toInt()

        var t0 = 0
        var t1 = 0
        var offset = 0
        while (offset + blockLength < data.size) {
            val block = ByteArray(blockLength)
            data.copyInto(block, endIndex = offset + blockLength, startIndex = offset)
            offset += blockLength
            t0 += blockLength
            if (t0 < 0) {
                t1 += 1
            }
            blake2sCompress(h, block, t0, t1, isLast = false)
        }

        val remaining = data.size - offset
        val finalBlock = ByteArray(blockLength)
        if (remaining > 0) {
            data.copyInto(finalBlock, endIndex = data.size, startIndex = offset)
        }
        t0 += remaining
        if (remaining > 0 && t0 < remaining) {
            t1 += 1
        }
        blake2sCompress(h, finalBlock, t0, t1, isLast = true)

        val output = ByteArray(32)
        for (i in h.indices) {
            writeIntLittleEndian(output, i * 4, h[i])
        }
        return output
    }
}

private val BLAKE2B_DIGEST: NoiseDigest = object : NoiseDigest {
    override val digestLength: Int = 64
    override val blockLength: Int = 128

    override fun digest(data: ByteArray): ByteArray {
        val h = BLAKE2B_IV.copyOf()
        h[0] = h[0] xor 0x01010040uL.toLong()

        var t0 = 0L
        var t1 = 0L
        var offset = 0
        while (offset + blockLength < data.size) {
            val block = ByteArray(blockLength)
            data.copyInto(block, endIndex = offset + blockLength, startIndex = offset)
            offset += blockLength
            val previous = t0
            t0 += blockLength.toLong()
            if (t0 < previous) {
                t1 += 1L
            }
            blake2bCompress(h, block, t0, t1, isLast = false)
        }

        val remaining = data.size - offset
        val finalBlock = ByteArray(blockLength)
        if (remaining > 0) {
            data.copyInto(finalBlock, endIndex = data.size, startIndex = offset)
        }
        val previous = t0
        t0 += remaining.toLong()
        if (t0 < previous) {
            t1 += 1L
        }
        blake2bCompress(h, finalBlock, t0, t1, isLast = true)

        val output = ByteArray(64)
        for (i in h.indices) {
            writeLongLittleEndian(output, i * 8, h[i])
        }
        return output
    }
}

private fun blake2sCompress(
    h: IntArray,
    block: ByteArray,
    t0: Int,
    t1: Int,
    isLast: Boolean
) {
    val m = IntArray(16) { index -> readIntLittleEndian(block, index * 4) }
    val v = IntArray(16)
    for (i in 0 until 8) {
        v[i] = h[i]
        v[i + 8] = BLAKE2S_IV[i]
    }
    v[12] = v[12] xor t0
    v[13] = v[13] xor t1
    if (isLast) {
        v[14] = v[14] xor -0x1
    }

    repeat(10) { round ->
        val s = BLAKE2_SIGMA[round]
        blake2sMix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        blake2sMix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        blake2sMix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        blake2sMix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        blake2sMix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        blake2sMix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        blake2sMix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        blake2sMix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    }

    for (i in 0 until 8) {
        h[i] = h[i] xor v[i] xor v[i + 8]
    }
}

private fun blake2sMix(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
    v[a] = v[a] + v[b] + x
    v[d] = (v[d] xor v[a]).rotateRight(16)
    v[c] += v[d]
    v[b] = (v[b] xor v[c]).rotateRight(12)
    v[a] = v[a] + v[b] + y
    v[d] = (v[d] xor v[a]).rotateRight(8)
    v[c] += v[d]
    v[b] = (v[b] xor v[c]).rotateRight(7)
}

private fun blake2bCompress(
    h: LongArray,
    block: ByteArray,
    t0: Long,
    t1: Long,
    isLast: Boolean
) {
    val m = LongArray(16) { index -> readLongLittleEndian(block, index * 8) }
    val v = LongArray(16)
    for (i in 0 until 8) {
        v[i] = h[i]
        v[i + 8] = BLAKE2B_IV[i]
    }
    v[12] = v[12] xor t0
    v[13] = v[13] xor t1
    if (isLast) {
        v[14] = v[14] xor -1L
    }

    repeat(12) { round ->
        val s = BLAKE2_SIGMA[round]
        blake2bMix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        blake2bMix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        blake2bMix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        blake2bMix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        blake2bMix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        blake2bMix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        blake2bMix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        blake2bMix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    }

    for (i in 0 until 8) {
        h[i] = h[i] xor v[i] xor v[i + 8]
    }
}

private fun blake2bMix(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
    v[a] = v[a] + v[b] + x
    v[d] = (v[d] xor v[a]).rotateRight(32)
    v[c] += v[d]
    v[b] = (v[b] xor v[c]).rotateRight(24)
    v[a] = v[a] + v[b] + y
    v[d] = (v[d] xor v[a]).rotateRight(16)
    v[c] += v[d]
    v[b] = (v[b] xor v[c]).rotateRight(63)
}

private val SHA256_K = intArrayOf(
    0x428a2f98u.toInt(), 0x71374491u.toInt(), 0xb5c0fbcfu.toInt(), 0xe9b5dba5u.toInt(),
    0x3956c25bu.toInt(), 0x59f111f1u.toInt(), 0x923f82a4u.toInt(), 0xab1c5ed5u.toInt(),
    0xd807aa98u.toInt(), 0x12835b01u.toInt(), 0x243185beu.toInt(), 0x550c7dc3u.toInt(),
    0x72be5d74u.toInt(), 0x80deb1feu.toInt(), 0x9bdc06a7u.toInt(), 0xc19bf174u.toInt(),
    0xe49b69c1u.toInt(), 0xefbe4786u.toInt(), 0x0fc19dc6u.toInt(), 0x240ca1ccu.toInt(),
    0x2de92c6fu.toInt(), 0x4a7484aau.toInt(), 0x5cb0a9dcu.toInt(), 0x76f988dau.toInt(),
    0x983e5152u.toInt(), 0xa831c66du.toInt(), 0xb00327c8u.toInt(), 0xbf597fc7u.toInt(),
    0xc6e00bf3u.toInt(), 0xd5a79147u.toInt(), 0x06ca6351u.toInt(), 0x14292967u.toInt(),
    0x27b70a85u.toInt(), 0x2e1b2138u.toInt(), 0x4d2c6dfcu.toInt(), 0x53380d13u.toInt(),
    0x650a7354u.toInt(), 0x766a0abbu.toInt(), 0x81c2c92eu.toInt(), 0x92722c85u.toInt(),
    0xa2bfe8a1u.toInt(), 0xa81a664bu.toInt(), 0xc24b8b70u.toInt(), 0xc76c51a3u.toInt(),
    0xd192e819u.toInt(), 0xd6990624u.toInt(), 0xf40e3585u.toInt(), 0x106aa070u.toInt(),
    0x19a4c116u.toInt(), 0x1e376c08u.toInt(), 0x2748774cu.toInt(), 0x34b0bcb5u.toInt(),
    0x391c0cb3u.toInt(), 0x4ed8aa4au.toInt(), 0x5b9cca4fu.toInt(), 0x682e6ff3u.toInt(),
    0x748f82eeu.toInt(), 0x78a5636fu.toInt(), 0x84c87814u.toInt(), 0x8cc70208u.toInt(),
    0x90befffau.toInt(), 0xa4506cebu.toInt(), 0xbef9a3f7u.toInt(), 0xc67178f2u.toInt()
)

private val SHA512_K = longArrayOf(
    0x428a2f98d728ae22uL.toLong(), 0x7137449123ef65cduL.toLong(),
    0xb5c0fbcfec4d3b2fuL.toLong(), 0xe9b5dba58189dbbcuL.toLong(),
    0x3956c25bf348b538uL.toLong(), 0x59f111f1b605d019uL.toLong(),
    0x923f82a4af194f9buL.toLong(), 0xab1c5ed5da6d8118uL.toLong(),
    0xd807aa98a3030242uL.toLong(), 0x12835b0145706fbeuL.toLong(),
    0x243185be4ee4b28cuL.toLong(), 0x550c7dc3d5ffb4e2uL.toLong(),
    0x72be5d74f27b896fuL.toLong(), 0x80deb1fe3b1696b1uL.toLong(),
    0x9bdc06a725c71235uL.toLong(), 0xc19bf174cf692694uL.toLong(),
    0xe49b69c19ef14ad2uL.toLong(), 0xefbe4786384f25e3uL.toLong(),
    0x0fc19dc68b8cd5b5uL.toLong(), 0x240ca1cc77ac9c65uL.toLong(),
    0x2de92c6f592b0275uL.toLong(), 0x4a7484aa6ea6e483uL.toLong(),
    0x5cb0a9dcbd41fbd4uL.toLong(), 0x76f988da831153b5uL.toLong(),
    0x983e5152ee66dfabuL.toLong(), 0xa831c66d2db43210uL.toLong(),
    0xb00327c898fb213fuL.toLong(), 0xbf597fc7beef0ee4uL.toLong(),
    0xc6e00bf33da88fc2uL.toLong(), 0xd5a79147930aa725uL.toLong(),
    0x06ca6351e003826fuL.toLong(), 0x142929670a0e6e70uL.toLong(),
    0x27b70a8546d22ffcuL.toLong(), 0x2e1b21385c26c926uL.toLong(),
    0x4d2c6dfc5ac42aeduL.toLong(), 0x53380d139d95b3dfuL.toLong(),
    0x650a73548baf63deuL.toLong(), 0x766a0abb3c77b2a8uL.toLong(),
    0x81c2c92e47edaee6uL.toLong(), 0x92722c851482353buL.toLong(),
    0xa2bfe8a14cf10364uL.toLong(), 0xa81a664bbc423001uL.toLong(),
    0xc24b8b70d0f89791uL.toLong(), 0xc76c51a30654be30uL.toLong(),
    0xd192e819d6ef5218uL.toLong(), 0xd69906245565a910uL.toLong(),
    0xf40e35855771202auL.toLong(), 0x106aa07032bbd1b8uL.toLong(),
    0x19a4c116b8d2d0c8uL.toLong(), 0x1e376c085141ab53uL.toLong(),
    0x2748774cdf8eeb99uL.toLong(), 0x34b0bcb5e19b48a8uL.toLong(),
    0x391c0cb3c5c95a63uL.toLong(), 0x4ed8aa4ae3418acbuL.toLong(),
    0x5b9cca4f7763e373uL.toLong(), 0x682e6ff3d6b2b8a3uL.toLong(),
    0x748f82ee5defb2fcuL.toLong(), 0x78a5636f43172f60uL.toLong(),
    0x84c87814a1f0ab72uL.toLong(), 0x8cc702081a6439ecuL.toLong(),
    0x90befffA23631e28uL.toLong(), 0xa4506cebde82bde9uL.toLong(),
    0xbef9a3f7b2c67915uL.toLong(), 0xc67178f2e372532buL.toLong(),
    0xca273eceea26619cuL.toLong(), 0xd186b8c721c0c207uL.toLong(),
    0xeada7dd6cde0eb1euL.toLong(), 0xf57d4f7fee6ed178uL.toLong(),
    0x06f067aa72176fbauL.toLong(), 0x0a637dc5a2c898a6uL.toLong(),
    0x113f9804bef90daeuL.toLong(), 0x1b710b35131c471buL.toLong(),
    0x28db77f523047d84uL.toLong(), 0x32caab7b40c72493uL.toLong(),
    0x3c9ebe0a15c9bebcuL.toLong(), 0x431d67c49c100d4cuL.toLong(),
    0x4cc5d4becb3e42b6uL.toLong(), 0x597f299cfc657e2auL.toLong(),
    0x5fcb6fab3ad6faecuL.toLong(), 0x6c44198c4a475817uL.toLong()
)

private val BLAKE2S_IV = intArrayOf(
    0x6A09E667u.toInt(),
    0xBB67AE85u.toInt(),
    0x3C6EF372u.toInt(),
    0xA54FF53Au.toInt(),
    0x510E527Fu.toInt(),
    0x9B05688Cu.toInt(),
    0x1F83D9ABu.toInt(),
    0x5BE0CD19u.toInt()
)

private val BLAKE2B_IV = longArrayOf(
    0x6A09E667F3BCC908uL.toLong(),
    0xBB67AE8584CAA73BuL.toLong(),
    0x3C6EF372FE94F82BuL.toLong(),
    0xA54FF53A5F1D36F1uL.toLong(),
    0x510E527FADE682D1uL.toLong(),
    0x9B05688C2B3E6C1FuL.toLong(),
    0x1F83D9ABFB41BD6BuL.toLong(),
    0x5BE0CD19137E2179uL.toLong()
)

private val BLAKE2_SIGMA = arrayOf(
    intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
)

private fun readIntBigEndian(data: ByteArray, offset: Int): Int {
    return ((data[offset].toInt() and 0xFF) shl 24) or
        ((data[offset + 1].toInt() and 0xFF) shl 16) or
        ((data[offset + 2].toInt() and 0xFF) shl 8) or
        (data[offset + 3].toInt() and 0xFF)
}

private fun writeIntBigEndian(data: ByteArray, offset: Int, value: Int) {
    data[offset] = (value ushr 24).toByte()
    data[offset + 1] = (value ushr 16).toByte()
    data[offset + 2] = (value ushr 8).toByte()
    data[offset + 3] = value.toByte()
}

private fun readLongBigEndian(data: ByteArray, offset: Int): Long {
    var result = 0L
    for (i in 0 until 8) {
        result = (result shl 8) or ((data[offset + i].toLong()) and 0xFFL)
    }
    return result
}

private fun writeLongBigEndian(data: ByteArray, offset: Int, value: Long) {
    for (i in 0 until 8) {
        data[offset + i] = (value ushr (56 - i * 8)).toByte()
    }
}

private fun readIntLittleEndian(data: ByteArray, offset: Int): Int {
    return (data[offset].toInt() and 0xFF) or
        ((data[offset + 1].toInt() and 0xFF) shl 8) or
        ((data[offset + 2].toInt() and 0xFF) shl 16) or
        ((data[offset + 3].toInt() and 0xFF) shl 24)
}

private fun writeIntLittleEndian(data: ByteArray, offset: Int, value: Int) {
    data[offset] = value.toByte()
    data[offset + 1] = (value ushr 8).toByte()
    data[offset + 2] = (value ushr 16).toByte()
    data[offset + 3] = (value ushr 24).toByte()
}

private fun readLongLittleEndian(data: ByteArray, offset: Int): Long {
    var result = 0L
    for (i in 0 until 8) {
        result = result or ((data[offset + i].toLong() and 0xFFL) shl (i * 8))
    }
    return result
}

private fun writeLongLittleEndian(data: ByteArray, offset: Int, value: Long) {
    for (i in 0 until 8) {
        data[offset + i] = (value ushr (i * 8)).toByte()
    }
}
