package data.rc5

interface Rc5Cipher {

    fun encrypt(data: ByteArray, keyword: String): ByteArray

    fun decrypt(data: ByteArray, keyword: String): ByteArray

}