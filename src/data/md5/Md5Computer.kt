package data.md5

interface Md5Computer {

    fun hash(message: ByteArray): String

}