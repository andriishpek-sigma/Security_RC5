package data.rc5

import data.md5.Md5Computer
import data.md5.hash

class Rc5WithKeyMd5Cipher(
    private val rc5Cipher: Rc5Cipher,
    private val md5Computer: Md5Computer
): Rc5Cipher {

    override fun encrypt(data: ByteArray, keyword: String): ByteArray {
        val keyHash = md5Computer.hash(keyword)
        return rc5Cipher.encrypt(data, keyHash)
    }

    override fun decrypt(data: ByteArray, keyword: String): ByteArray {
        val keyHash = md5Computer.hash(keyword)
        return rc5Cipher.decrypt(data, keyHash)
    }
}