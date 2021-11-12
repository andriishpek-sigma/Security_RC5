package data.utils

fun ByteArray.readIntLittleEndian(): IntArray {
    val lastIntExtraSize = if (size % 4 == 0) 0 else 1
    val intSize = size / 4 + lastIntExtraSize

    return IntArray(intSize) { index ->
        readIntLittleEndian(index * 4)
    }
}

fun IntArray.toBytesLittleEndian(): ByteArray {
    val bytes = ByteArray(size * 4)
    forEachIndexed { index, int ->
        int.toBytesLittleEndian(bytes, index * 4)
    }
    return bytes
}

fun Int.toBytes(
    buffer: ByteArray,
    offset: Int = 0,
) {
    buffer[offset + 0] = (this shr 24).asPositiveByte
    buffer[offset + 1] = (this shr 16).asPositiveByte
    buffer[offset + 2] = (this shr 8).asPositiveByte
    buffer[offset + 3] = (this shr 0).asPositiveByte
}

fun Int.toBytesLittleEndian(
    buffer: ByteArray,
    offset: Int = 0,
) {
    buffer[offset + 0] = (this shr 0).asPositiveByte
    buffer[offset + 1] = (this shr 8).asPositiveByte
    buffer[offset + 2] = (this shr 16).asPositiveByte
    buffer[offset + 3] = (this shr 24).asPositiveByte
}

fun ByteArray.readInt(
    offset: Int = 0
): Int {
    var result = 0
    result += this[offset + 0].asPositiveInt shl 24
    result += this[offset + 1].asPositiveInt shl 16
    result += this[offset + 2].asPositiveInt shl 8
    result += this[offset + 3].asPositiveInt shl 0
    return result
}

fun ByteArray.readIntLittleEndian(
    offset: Int = 0
): Int {
    var result = 0
    result += this[offset + 0].asPositiveInt shl 0
    result += this[offset + 1].asPositiveInt shl 8
    result += this[offset + 2].asPositiveInt shl 16
    result += this[offset + 3].asPositiveInt shl 24
    return result
}


val Int.to32bitString: String
    get() = Integer.toBinaryString(this).padStart(Int.SIZE_BITS, '0')

val Int.asPositiveByte: Byte
    get() = (this and 0xff).toByte()

val Byte.asPositiveInt: Int
    get() = toInt() and 0xff