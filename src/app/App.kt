package app

import data.md5.CustomMd5Computer
import data.rc5.CustomRc5Cipher
import data.rc5.Rc5WithKeyMd5Cipher
import java.io.File

class App {

    companion object {
        private const val KEY_FILE = "key.txt"
        private const val INPUT_FILE = "input.txt"
        private const val ENCRYPTED_NAME = "encrypted.txt"
        private const val DECRYPTED_NAME = "decrypted.txt"
    }

    private val rc5 = Rc5WithKeyMd5Cipher(
        CustomRc5Cipher(32, 16),
        CustomMd5Computer()
    )

    fun execute() {
        val key = readFile(KEY_FILE).decodeToString()
        println("Key loaded: '$key'")

        val input = readFile(INPUT_FILE)
        println("Input loaded. Length: ${input.size}")

        val encrypted = rc5.encrypt(input, key)
        writeFile(ENCRYPTED_NAME, encrypted)
        println("Encrypted size: ${encrypted.size}. Saved into $ENCRYPTED_NAME")

        val decrypted = rc5.decrypt(encrypted, key)
        writeFile(DECRYPTED_NAME, decrypted)
        println("Decrypted size: ${decrypted.size}. Saved into $DECRYPTED_NAME")

        val isEqual = input.contentEquals(decrypted)
        println("Is input and decrypted data equal? ${if (isEqual) "Yes" else "No"}")
    }

    private fun readFile(name: String): ByteArray {
        return fileNameInDir(name).readBytes()
    }

    private fun writeFile(name: String, data: ByteArray) {
        return fileNameInDir(name).writeBytes(data)
    }

    private fun fileNameInDir(name: String): File {
        return File("data", name).also {
            it.parentFile.mkdirs()
            it.createNewFile()
        }
    }

}