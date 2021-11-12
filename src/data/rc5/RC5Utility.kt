package data.rc5

import data.generator.CustomRandomGenerator.invoke
import java.math.BigInteger
import java.util.ArrayList

class RC5Utility(private val sizeOfPartInBit: Int) {

    private val sizeOfPartInByte: Int

    var initVector: ByteArray
    private fun divisionIntoParts(data: ByteArray): IntArray {
        val tmp = IntArray(2)
        var n = data.size
        val nB = n / 2
        val nA = n - nB
        var j: Int
        val a = ByteArray(sizeOfPartInBit)
        val b = ByteArray(sizeOfPartInBit)
        n--
        j = sizeOfPartInBit - 1
        for (i in 0 until nB) {
            b[j] = data[n]
            n--
            j--
        }
        j = sizeOfPartInBit - 1
        for (i in nA - 1 downTo 0) {
            a[j] = data[n]
            n--
            j--
        }
        tmp[0] = BigInteger(a).toInt()
        tmp[1] = BigInteger(b).toInt()
        return tmp
    }

    private fun assemblingParts(a: Int, b: Int): ByteArray {
        val tmp = ByteArray(2 * sizeOfPartInByte)
        val byteA = BigInteger("" + a).toByteArray()
        val byteB = BigInteger("" + b).toByteArray()

        for (i in 0 until sizeOfPartInByte) {
            tmp[i] = byteA[i]
            tmp[sizeOfPartInByte + i] = byteB[i]
        }
        return tmp
    }

    private fun encryptBlock(data: ByteArray, key: RC5Key): ByteArray {
        var a: Int
        var b: Int
        var number: Int
        val s = key.words
        val parts = divisionIntoParts(data)
        a = parts[0]
        b = parts[1]
        a = a + s[0]
        b = b + s[1]
        for (i in 1..key.numberOfRounds) {
            a = a xor b
            number = b % sizeOfPartInBit
            a = Integer.rotateLeft(a, number)
            a = a + s[2 * i]
            b = b xor a
            number = a % sizeOfPartInBit
            b = Integer.rotateLeft(b, number)
            b = b + s[2 * i + 1]
        }
        return assemblingParts(a, b)
    }

    private fun decryptBlock(data: ByteArray, key: RC5Key): ByteArray {
        var a: Int
        var b: Int
        var number: Int
        val s = key.words
        val parts = divisionIntoParts(data)
        a = parts[0]
        b = parts[1]
        for (i in key.numberOfRounds downTo 1) {
            number = a % sizeOfPartInBit
            b = b - s[2 * i + 1]
            b = Integer.rotateRight(b, number)
            b = b xor a
            number = b % sizeOfPartInBit
            a = a - s[2 * i]
            a = Integer.rotateRight(a, number)
            a = a xor b
        }
        a = a - s[0]
        b = b - s[1]
        return assemblingParts(a, b)
    }

    private fun divisionIntoBlocks(data: ByteArray): List<ByteArray> {
        val n = data.size
        val sizeOfBlock = 2 * sizeOfPartInByte
        val divBlock = if (n > sizeOfBlock) n % sizeOfBlock else sizeOfBlock - n
        if (divBlock != 0) {
            println("Data size must be a multiple of $sizeOfBlock")
        }
        val numbersOfBlocks = n / sizeOfBlock
        var tmp: ByteArray
        var counter = 0
        val parts: MutableList<ByteArray> = ArrayList()
        for (i in 0 until numbersOfBlocks) {
            tmp = ByteArray(sizeOfBlock)
            for (j in 0 until sizeOfBlock) {
                tmp[j] = data[counter]
                counter++
            }
            parts.add(tmp)
        }
        return parts
    }

    private fun assemblyOfBlocks(blocks: List<ByteArray>): ByteArray {
        val sizeOfBlock = 2 * sizeOfPartInByte
        val n = blocks.size * sizeOfBlock
        val outputData = ByteArray(n)
        var counter = 0
        for (block in blocks) {
            for (i in 0 until sizeOfBlock) {
                outputData[counter] = block[i]
                counter++
            }
        }
        return outputData
    }

    fun encrypt(data: ByteArray, key: RC5Key): ByteArray {
        val inputBlocks = divisionIntoBlocks(data)
        val outputBlocks: MutableList<ByteArray> = ArrayList()
        var tmp: ByteArray
        val prevBlock = initVector.clone()
        for (block in inputBlocks) {
            tmp = encryptBlock(block, key)
            for (i in 0..7) {
                prevBlock[i] = tmp[i]
            }
            outputBlocks.add(tmp)
        }
        return assemblyOfBlocks(outputBlocks)
    }

    fun decrypt(data: ByteArray, key: RC5Key): ByteArray {
        val inputBlocks = divisionIntoBlocks(data)
        val outputBlocks: MutableList<ByteArray> = ArrayList()
        var tmp: ByteArray
        val prevBlock = initVector.clone()
        for (block in inputBlocks) {
            tmp = decryptBlock(block, key)
            for (i in 0..7) {
                prevBlock[i] = tmp[i]
            }
            outputBlocks.add(tmp)
        }
        return assemblyOfBlocks(outputBlocks)
    }

    init {
        sizeOfPartInByte = sizeOfPartInBit / 8

        val tmpLong = invoke().nextSequence(8)
        val tmp = IntArray(8)
        for (i in tmpLong.indices) {
            tmp[i] = tmpLong[i].toInt()
        }
        initVector = ByteArray(8)
        for (i in tmp.indices) {
            initVector[i] = tmp[i].toByte()
        }
    }
}