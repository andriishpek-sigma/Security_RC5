package data.generator

class RandomGeneratorImpl(
    private val multiplier: Long,
    private val increment: Long,
    private val modulus: Long,
    initialValue: Long,
) : RandomGenerator {

    private var lastValue: Long = initialValue

    override fun nextValue(): Long {
        lastValue = (multiplier * lastValue + increment) % modulus
        return lastValue
    }

    override fun nextSequence(size: Int): Array<Long> {
        return Array(size) { nextValue() }
    }

}