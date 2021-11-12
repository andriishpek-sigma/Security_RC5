package data.utils

fun ByteArray.readLongLittleEndian(): LongArray {
    val lastIntExtraSize = if (size % 8 == 0) 0 else 1
    val intSize = size / 8 + lastIntExtraSize

    return LongArray(intSize) { index ->
        readLongLittleEndian(index * 8)
    }
}

fun LongArray.toBytesLittleEndian(): ByteArray {
    val bytes = ByteArray(size * 8)
    forEachIndexed { index, int ->
        int.toBytesLittleEndian(bytes, index * 8)
    }
    return bytes
}

fun Long.toBytes(
    buffer: ByteArray,
    offset: Int = 0,
) {
    buffer[offset + 0] = (this shr 56).asPositiveByte
    buffer[offset + 1] = (this shr 48).asPositiveByte
    buffer[offset + 2] = (this shr 40).asPositiveByte
    buffer[offset + 3] = (this shr 32).asPositiveByte
    buffer[offset + 4] = (this shr 24).asPositiveByte
    buffer[offset + 5] = (this shr 16).asPositiveByte
    buffer[offset + 6] = (this shr 8).asPositiveByte
    buffer[offset + 7] = (this shr 0).asPositiveByte
}

fun Long.toBytesLittleEndian(
    buffer: ByteArray,
    offset: Int = 0,
) {
    buffer[offset + 0] = (this shr 0).asPositiveByte
    buffer[offset + 1] = (this shr 8).asPositiveByte
    buffer[offset + 2] = (this shr 16).asPositiveByte
    buffer[offset + 3] = (this shr 24).asPositiveByte
    buffer[offset + 4] = (this shr 32).asPositiveByte
    buffer[offset + 5] = (this shr 40).asPositiveByte
    buffer[offset + 6] = (this shr 48).asPositiveByte
    buffer[offset + 7] = (this shr 56).asPositiveByte
}

fun ByteArray.readLong(
    offset: Int = 0
): Long {
    var result = 0L
    result += this[offset + 0].asPositiveInt shl 56
    result += this[offset + 1].asPositiveInt shl 48
    result += this[offset + 2].asPositiveInt shl 40
    result += this[offset + 3].asPositiveInt shl 32
    result += this[offset + 4].asPositiveInt shl 24
    result += this[offset + 5].asPositiveInt shl 16
    result += this[offset + 6].asPositiveInt shl 8
    result += this[offset + 7].asPositiveInt shl 0
    return result
}

fun ByteArray.readLongLittleEndian(
    offset: Int = 0
): Long {
    var result = 0L
    result += this[offset + 0].asPositiveInt shl 0
    result += this[offset + 1].asPositiveInt shl 8
    result += this[offset + 2].asPositiveInt shl 16
    result += this[offset + 3].asPositiveInt shl 24
    result += this[offset + 4].asPositiveInt shl 32
    result += this[offset + 5].asPositiveInt shl 40
    result += this[offset + 6].asPositiveInt shl 48
    result += this[offset + 7].asPositiveInt shl 56
    return result
}

//val Long.to64bitString: String
//    get() = Long.toBinaryString(this).padStart(Long.SIZE_BITS, '0')

val Long.asPositiveByte: Byte
    get() = (this and 0xff).toByte()

val Byte.asPositiveLong: Long
    get() = toLong() and 0xff