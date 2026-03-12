package com.security.ransomwaredefense.data

import androidx.room.*

enum class ThreatLevel {
    NORMAL, SUSPICIOUS, RANSOMWARE_LIKE
}

data class FileEvent(
    val filePath: String,
    val eventType: String,
    val timestamp: Long,
    val isHoneypot: Boolean,
    val entropy: Double = 0.0
)

data class BehaviorSnapshot(
    val filesModifiedPerSecond: Float,
    val averageEntropy: Float,
    val decoyFileAccessed: Float,
    val unusualExtensionRatio: Float,
    val timestamp: Long = System.currentTimeMillis()
)

data class MLResult(
    val threatLevel: ThreatLevel,
    val confidence: Float,
    val normalScore: Float,
    val suspiciousScore: Float,
    val ransomwareScore: Float
)

data class RiskScore(
    val score: Int,
    val threatLevel: ThreatLevel,
    val entropyContribution: Int,
    val mlContribution: Int,
    val decoyContribution: Int,
    val explanation: String
)

@Entity(tableName = "threat_logs")
data class ThreatLog(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val timestamp: Long,
    val threatLevel: String,
    val riskScore: Int,
    val description: String,
    val filePath: String = "",
    val mlConfidence: Float = 0f
)

@Entity(tableName = "behavior_history")
data class BehaviorHistory(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val timestamp: Long,
    val riskScore: Int,
    val filesModifiedPerSecond: Float,
    val averageEntropy: Float
)