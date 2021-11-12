package data.utils

import kotlin.experimental.xor

fun ByteArray.toHexString(): String {
    return joinToString(separator = "") { it.toHexString() }
}

fun Byte.toHexString(): String {
    return "%02x".format(this)
}

infix fun ByteArray.xor(other: ByteArray) : ByteArray {
    if (size != other.size) {
        throw RuntimeException("Block length must be equal")
    }

    return ByteArray(size) { i ->
        val one = this[i].toInt()
        val two = other[i].toInt()
        val xor = one xor two
        (0xff and xor).toByte()
    }
}

