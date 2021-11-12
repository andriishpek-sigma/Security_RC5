package data.rc5

class RC5Key(
    private val key: ByteArray,
    wordSize: Int,
    val numberOfRounds: Int
) {

    companion object {
        private const val P = -0x481eae9d
        private const val Q = -0x61c88647
    }

    private val wordSizeBits = wordSize
    private val wordSizeBytes = wordSize / Byte.SIZE_BITS
    private val keySizeBytes: Int = key.size

    private val numberOfWords: Int = resolveNumberOfWords(numberOfRounds)

    private val c: Int = resolveC()

    val words = generateWords()

    private fun generateWords(): IntArray {
        val L = IntArray(numberOfWords)
        var number: Int

        var a = 0
        var b = 0

        var x = 0
        var y = 0

        val words = IntArray(numberOfWords)
        for (i in keySizeBytes - 1 downTo 0) {
            L[i / wordSizeBytes] = (L[i / wordSizeBytes] shl 8) + key[i]
        }

        words[0] = P
        for (i in 1 until numberOfWords) {
            words[i] = words[i - 1] + Q
        }

        val n: Int = if (keySizeBytes > c) {
            keySizeBytes
        } else {
            c
        }

        for (i in 0 until 3 * n) {
            words[x] = Integer.rotateLeft(words[x] + a + b, 3)
            a = words[x]
            number = (a + b) % wordSizeBits
            L[y] = Integer.rotateLeft(L[y] + a + b, number)
            b = L[y]
            x = (x + 1) % numberOfWords
            y = (y + 1) % c
        }

        return words
    }

    private fun resolveNumberOfWords(numberOfRounds: Int): Int {
        val numberOfWords = (numberOfRounds + 1) * 2

        require(numberOfWords > (keySizeBytes - 1) / wordSizeBytes) {
            "The key is too long for the number of rounds"
        }
        return numberOfWords
    }

    private fun resolveC(): Int {
        val c = keySizeBytes / wordSizeBytes
        return if (c == 0) 1 else c
    }
}
