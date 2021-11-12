package data.md5

import data.utils.readIntLittleEndian
import data.utils.toBytes
import data.utils.toBytesLittleEndian
import data.utils.toHexString
import kotlin.math.abs
import kotlin.math.sin

class CustomMd5Computer : Md5Computer {

    companion object {

        private const val WORD_A = 0x67452301
        private const val WORD_B = 0xEFCDAB89L.toInt()
        private const val WORD_C = 0x98BADCFEL.toInt()
        private const val WORD_D = 0x10325476

        private val K = IntArray(64) { i ->
            (abs(sin(i + 1.0)) * (1L shl 32)).toLong().toInt()
        }

        private val SHIFTS = intArrayOf(
            7, 12, 17, 22,
            5, 9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
        )
    }

    override fun hash(message: ByteArray): String {
        val padding = generatePaddingAndLengthBytes(message.size)

        val messageWithPadding = message + padding
        val messageWithPaddingAsInt = messageWithPadding.readIntLittleEndian()

        return processMessageIn16WordBlocks(messageWithPaddingAsInt).uppercase()
    }

    private fun generatePaddingAndLengthBytes(messageSize: Int): ByteArray {
        val paddingAndLengthSize = calculatePaddingAndLengthSize(messageSize)
        val paddingSize = paddingAndLengthSize - 8

        val paddingAndLength = ByteArray(paddingAndLengthSize)

        appendPadding(paddingAndLength, paddingSize)
        appendLength(paddingAndLength, messageSize)

        return paddingAndLength
    }

    private fun calculatePaddingAndLengthSize(messageSize: Int): Int {
        val sizeOfMessageInLastBlock = messageSize % 64

        var paddingAndLengthSize = (64 - sizeOfMessageInLastBlock)
        if (paddingAndLengthSize <= 8) paddingAndLengthSize += 64

        return paddingAndLengthSize
    }

    private fun appendPadding(paddingAndLength: ByteArray, paddingSize: Int) {
        paddingAndLength[0] = 128.toByte() // 1000 0000
        for (i in 1 until paddingSize) {
            paddingAndLength[i] = 0
        }
    }

    private fun appendLength(paddingAndLength: ByteArray, messageLength: Int) {
        (messageLength * Byte.SIZE_BITS).toBytesLittleEndian(
            buffer = paddingAndLength,
            offset = paddingAndLength.size - 8,
        )
        0.toBytes(
            buffer = paddingAndLength,
            offset = paddingAndLength.size - 4,
        )
    }

    private fun processMessageIn16WordBlocks(data: IntArray): String {
        var wordA = WORD_A
        var wordB = WORD_B
        var wordC = WORD_C
        var wordD = WORD_D
        var f = 0
        var blockIndex = 0

        for (block in data.indices step 16) {
            val originalA = wordA
            val originalB = wordB
            val originalC = wordC
            val originalD = wordD

            repeat(64) { j ->
                when (j) {
                    in 0..15 -> {
                        f = f(wordB, wordC, wordD)
                        blockIndex = j
                    }
                    in 16..31 -> {
                        f = g(wordB, wordC, wordD)
                        blockIndex = (5 * j + 1) % 16
                    }
                    in 32..47 -> {
                        f = h(wordB, wordC, wordD)
                        blockIndex = (3 * j + 5) % 16
                    }
                    in 48..63 -> {
                        f = i(wordB, wordC, wordD)
                        blockIndex = (7 * j) % 16
                    }
                }
                f += wordA + K[j] + data[block + blockIndex]
                val temp = Integer.rotateLeft(f, SHIFTS[(j ushr 4 shl 2) or (j and 3)])
                wordA = wordD
                wordD = wordC
                wordC = wordB
                wordB += temp
            }
            wordA += originalA
            wordB += originalB
            wordC += originalC
            wordD += originalD
        }

        val hash = createHashArray(wordA, wordB, wordC, wordD)

        return hash.toHexString()
    }

    private fun createHashArray(wordA: Int, wordB: Int, wordC: Int, wordD: Int): ByteArray {
        return intArrayOf(wordA, wordB, wordC, wordD).toBytesLittleEndian()
    }

    private fun f(x: Int, y: Int, z: Int): Int {
        return (x and y) or (x.inv() and z)
    }

    private fun g(x: Int, y: Int, z: Int): Int {
        return (x and z) or (y and z.inv())
    }

    private fun h(x: Int, y: Int, z: Int): Int {
        return x xor y xor z
    }

    private fun i(x: Int, y: Int, z: Int): Int {
        return y xor (x or z.inv())
    }

}