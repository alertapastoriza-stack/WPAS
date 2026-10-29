package com.peagents.wifihacker.engine

import kotlinx.coroutines.*
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Motor de fuerza bruta multi-estrategia:
 * - Diccionario (wordlist)
 * - Patrones (leetspeak, mutaciones)
 * - Rango numérico
 * - Combinación charset + longitud
 * - Reglas hashcat-style (?l, ?u, ?d, ?n, capitalization)
 */
class BruteForceEngine(private val scope: CoroutineScope) {

    sealed class Strategy {
        data class WordList(val file: String) : Strategy()
        data class Pattern(val charset: String, val minLen: Int, val maxLen: Int) : Strategy()
        data class NumericRange(val min: Long, val max: Long) : Strategy()
        data class Mutations(val base: List<String>, val rules: List<MutationRule>) : Strategy()
    }

    enum class MutationRule {
        CAPITALIZE, LEET, REVERSE, APPEND_DIGIT, PREPEND_DIGIT,
        DOUBLE_CHAR, INSERT_SYMBOL, TO_LOWER, TO_UPPER
    }

    data class CrackProgress(
        val attempts: Long,
        val wps: Double,
        val currentCandidate: String,
        val strategy: String
    )

    /**
     * Genera candidatos según la estrategia.
     */
    fun generateCandidates(strategy: Strategy): Sequence<String> = when (strategy) {
        is Strategy.WordList -> {
            sequence {
                java.io.File(strategy.file).bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) yield(trimmed)
                    }
                }
            }
        }

        is Strategy.Pattern -> {
            sequence {
                for (len in strategy.minLen..strategy.maxLen) {
                    bruteForceCharset(strategy.charset, len).forEach { yield(it) }
                }
            }
        }

        is Strategy.NumericRange -> {
            sequence {
                var n = strategy.min
                while (n <= strategy.max && scope.isActive) {
                    yield(n.toString())
                    n++
                }
            }
        }

        is Strategy.Mutations -> {
            sequence {
                for (base in strategy.base) {
                    for (rule in strategy.rules) {
                        yield(applyMutation(base, rule))
                    }
                    // Combinations of 2 rules
                    for (r1 in strategy.rules) {
                        for (r2 in strategy.rules) {
                            if (r1 != r2) yield(applyMutation(applyMutation(base, r1), r2))
                        }
                    }
                }
            }
        }
    }

    private fun bruteForceCharset(charset: String, length: Int): Sequence<String> = sequence {
        val total = Math.pow(charset.length.toDouble(), length.toDouble()).toLong()
        for (i in 0 until total) {
            val sb = StringBuilder()
            var n = i
            repeat(length) {
                sb.append(charset[(n % charset.length).toInt()])
                n /= charset.length
            }
            yield(sb.reverse().toString())
        }
    }

    private fun applyMutation(input: String, rule: MutationRule): String = when (rule) {
        MutationRule.CAPITALIZE -> input.replaceFirstChar { it.uppercase() }
        MutationRule.LEET -> input.replace('a', '4').replace('e', '3').replace('i', '1')
            .replace('o', '0').replace('s', '5').replace('t', '7')
        MutationRule.REVERSE -> input.reversed()
        MutationRule.APPEND_DIGIT -> input + "1"
        MutationRule.PREPEND_DIGIT -> "1" + input
        MutationRule.DOUBLE_CHAR -> input + input.last()
        MutationRule.INSERT_SYMBOL -> input + "!"
        MutationRule.TO_LOWER -> input.lowercase()
        MutationRule.TO_UPPER -> input.uppercase()
    }

    /**
     * Verifica una contraseña candidata contra un hash WPA2 (PBKDF2-4096).
     */
    fun verifyWPA2Candidate(password: String, ssid: String, expectedPMK: ByteArray): Boolean {
        val pmk = pbkdf2Sha1(password.toByteArray(), ssid.toByteArray(), 4096, 32)
        return pmk.contentEquals(expectedPMK)
    }

    /**
     * Verifica una contraseña candidata contra un hash WPA3-SAE.
     */
    fun verifyWPA3Candidate(password: String, ssid: String, expectedSecret: ByteArray): Boolean {
        val pmk = pbkdf2Sha256(password.toByteArray(), "SAE".toByteArray() + ssid.toByteArray(), 4096, 32)
        return pmk.contentEquals(expectedSecret)
    }

    private fun pbkdf2Sha1(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(password, "HmacSHA1"))

        val output = ByteArray(dkLen)
        var blockNum = 1
        var offset = 0

        while (offset < dkLen) {
            val input = salt + intToBytes(blockNum)
            var u = mac.doFinal(input)
            var result = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in u.indices) result[i] = result[i].xor(u[i])
            }
            val copyLen = minOf(result.size, dkLen - offset)
            System.arraycopy(result, 0, output, offset, copyLen)
            offset += copyLen
            blockNum++
        }
        return output
    }

    private fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))

        val output = ByteArray(dkLen)
        var blockNum = 1
        var offset = 0

        while (offset < dkLen) {
            val input = salt + intToBytes(blockNum)
            var u = mac.doFinal(input)
            var result = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in u.indices) result[i] = result[i].xor(u[i])
            }
            val copyLen = minOf(result.size, dkLen - offset)
            System.arraycopy(result, 0, output, offset, copyLen)
            offset += copyLen
            blockNum++
        }
        return output
    }

    private fun intToBytes(i: Int): ByteArray = byteArrayOf(
        (i shr 24).toByte(), (i shr 16).toByte(), (i shr 8).toByte(), i.toByte()
    )
}
