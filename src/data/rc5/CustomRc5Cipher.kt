package data.rc5

class CustomRc5Cipher(
    private val wordSize: Int,
    private val rounds: Int,
): Rc5Cipher {

    private val rc5Utility: RC5Utility = RC5Utility(wordSize)

    override fun encrypt(data: ByteArray, keyword: String): ByteArray {
        val key = generateKey(keyword)
        val dataWithAddition = makeAddition(data)
        return rc5Utility.encrypt(dataWithAddition, key)
    }

    override fun decrypt(data: ByteArray, keyword: String): ByteArray {
        val key = generateKey(keyword)
        val decryptedData = rc5Utility.decrypt(data, key)
        return removeAddition(decryptedData)
    }

    private fun makeAddition(data: ByteArray): ByteArray {
        val blockLengthBytes = 2 * wordSize / Byte.SIZE_BITS

        val additionLength = blockLengthBytes - data.size % blockLengthBytes
        val additionByte = additionLength.toByte()

        val padding = ByteArray(additionLength) { additionByte }
        return data + padding
    }

    private fun removeAddition(data: ByteArray): ByteArray {
        val lastByte = data.lastOrNull() ?: return data
        val paddingLength = lastByte.toInt()

        if (paddingLength > data.size) {
            return data
        }

        var isPaddingDetected = true
        for (i in (data.size - 1)..data.size - paddingLength)  {
            if (data[i] != lastByte) {
                isPaddingDetected = false
                break
            }
        }

        if (!isPaddingDetected) return data
        return data.copyOfRange(0, data.size - paddingLength)
    }

    private fun generateKey(keyword: String) = RC5Key(keyword.encodeToByteArray(), wordSize, rounds)

}