package com.security.ransomwaredefense.security

import java.io.File
import kotlin.math.log2

object EntropyAnalyzer {

    fun calculateEntropy(file: File): Double {
        if (!file.exists() || !file.isFile || file.length() == 0L) return 0.0
        return try {
            val bytes = file.readBytes()
            calculateEntropyFromBytes(bytes)
        } catch (e: Exception) {
            0.0
        }
    }

    fun calculateEntropyFromBytes(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val frequency = IntArray(256)
        for (byte in bytes) frequency[byte.toInt() and 0xFF]++
        val size = bytes.size.toDouble()
        var entropy = 0.0
        for (count in frequency) {
            if (count > 0) {
                val probability = count / size
                entropy -= probability * log2(probability)
            }
        }
        return entropy
    }

    fun isHighEntropy(entropy: Double): Boolean = entropy > 7.2

    fun getEntropyLabel(entropy: Double): String = when {
        entropy < 3.0 -> "Very Low (plain text)"
        entropy < 5.0 -> "Low (structured data)"
        entropy < 7.0 -> "Medium (compressed/media)"
        entropy < 7.5 -> "High (possibly encrypted)"
        else -> "Very High (likely encrypted)"
    }

    fun analyzeDirectory(directory: File): Map<String, Double> {
        val results = mutableMapOf<String, Double>()
        if (!directory.exists()) return results
        directory.walkTopDown()
            .filter { it.isFile && it.length() < 10 * 1024 * 1024 }
            .take(20)
            .forEach { file ->
                results[file.absolutePath] = calculateEntropy(file)
            }
        return results
    }
}