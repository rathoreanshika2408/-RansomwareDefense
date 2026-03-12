package com.security.ransomwaredefense.ml

import android.content.Context
import com.security.ransomwaredefense.data.BehaviorSnapshot
import com.security.ransomwaredefense.data.MLResult
import com.security.ransomwaredefense.data.ThreatLevel
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

class ThreatClassifier(private val context: Context) {

    private var interpreter: Interpreter? = null
    private val modelFileName = "threat_classifier.tflite"

    init {
        loadModel()
    }

    private fun loadModel() {
        try {
            val assetFileDescriptor = context.assets.openFd(modelFileName)
            val fileInputStream = FileInputStream(assetFileDescriptor.fileDescriptor)
            val fileChannel = fileInputStream.channel
            val startOffset = assetFileDescriptor.startOffset
            val declaredLength = assetFileDescriptor.declaredLength
            val modelBuffer = fileChannel.map(
                FileChannel.MapMode.READ_ONLY, startOffset, declaredLength
            )
            interpreter = Interpreter(modelBuffer)
        } catch (e: Exception) {
            interpreter = null
        }
    }

    fun classify(snapshot: BehaviorSnapshot): MLResult {
        return try {
            if (interpreter != null) {
                classifyWithModel(snapshot)
            } else {
                classifyWithRules(snapshot)
            }
        } catch (e: Exception) {
            classifyWithRules(snapshot)
        }
    }

    private fun classifyWithModel(snapshot: BehaviorSnapshot): MLResult {
        val inputBuffer = ByteBuffer.allocateDirect(4 * 4).apply {
            order(ByteOrder.nativeOrder())
            putFloat(snapshot.filesModifiedPerSecond)
            putFloat(snapshot.averageEntropy)
            putFloat(snapshot.decoyFileAccessed)
            putFloat(snapshot.unusualExtensionRatio)
        }

        val outputBuffer = Array(1) { FloatArray(3) }
        interpreter?.run(inputBuffer, outputBuffer)

        val scores = outputBuffer[0]
        val maxIndex = scores.indices.maxByOrNull { scores[it] } ?: 0

        val threatLevel = when (maxIndex) {
            0 -> ThreatLevel.NORMAL
            1 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.RANSOMWARE_LIKE
        }

        return MLResult(
            threatLevel = threatLevel,
            confidence = scores[maxIndex],
            normalScore = scores[0],
            suspiciousScore = scores[1],
            ransomwareScore = scores[2]
        )
    }

    private fun classifyWithRules(snapshot: BehaviorSnapshot): MLResult {
        val isRansomware = snapshot.filesModifiedPerSecond > 8f &&
                snapshot.averageEntropy > 7.0f
        val isSuspicious = snapshot.filesModifiedPerSecond > 3f ||
                snapshot.averageEntropy > 6.5f ||
                snapshot.decoyFileAccessed > 0f

        val threatLevel = when {
            isRansomware -> ThreatLevel.RANSOMWARE_LIKE
            isSuspicious -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.NORMAL
        }

        val confidence = when (threatLevel) {
            ThreatLevel.RANSOMWARE_LIKE -> 0.85f
            ThreatLevel.SUSPICIOUS -> 0.65f
            ThreatLevel.NORMAL -> 0.90f
        }

        return MLResult(
            threatLevel = threatLevel,
            confidence = confidence,
            normalScore = if (threatLevel == ThreatLevel.NORMAL) confidence else 0.1f,
            suspiciousScore = if (threatLevel == ThreatLevel.SUSPICIOUS) confidence else 0.1f,
            ransomwareScore = if (threatLevel == ThreatLevel.RANSOMWARE_LIKE) confidence else 0.05f
        )
    }

    fun close() {
        interpreter?.close()
    }
}