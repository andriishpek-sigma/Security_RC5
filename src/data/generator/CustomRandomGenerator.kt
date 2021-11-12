package data.generator

object CustomRandomGenerator {

    const val MODULUS = 2147483649L
    const val MULTIPLIER = 65536L
    const val INCREMENT = 28657L
    const val INITIAL_VALUE = 33L

    @JvmStatic
    operator fun invoke() = RandomGeneratorImpl(MULTIPLIER, INCREMENT, MODULUS, INITIAL_VALUE)

}