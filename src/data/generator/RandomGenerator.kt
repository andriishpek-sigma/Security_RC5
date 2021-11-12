package data.generator

interface RandomGenerator {

    fun nextValue(): Long

    fun nextSequence(size: Int): Array<Long>

}