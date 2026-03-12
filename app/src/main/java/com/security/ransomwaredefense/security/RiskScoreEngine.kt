package com.security.ransomwaredefense.security

import com.security.ransomwaredefense.data.BehaviorSnapshot
import com.security.ransomwaredefense.data.MLResult
import com.security.ransomwaredefense.data.RiskScore
import com.security.ransomwaredefense.data.ThreatLevel

object RiskScoreEngine {

    fun calculateRiskScore(
        snapshot: BehaviorSnapshot,
        mlResult: MLResult,
        honeypotTriggered: Boolean
    ): RiskScore {

        // ML contribution (45%)
        val mlScore = when (mlResult.threatLevel) {
            ThreatLevel.RANSOMWARE_LIKE -> 45
            ThreatLevel.SUSPICIOUS -> 25
            ThreatLevel.NORMAL -> 0
        }

        // Entropy contribution (30%)
        val entropyScore = when {
            snapshot.averageEntropy > 7.5f -> 30
            snapshot.averageEntropy > 7.0f -> 20
            snapshot.averageEntropy > 6.0f -> 10
            else -> 0
        }

        // Honeypot contribution (15%)
        val decoyScore = if (honeypotTriggered) 15 else 0

        // Behavior contribution (10%)
        val behaviorScore = when {
            snapshot.filesModifiedPerSecond > 10f -> 10
            snapshot.filesModifiedPerSecond > 5f -> 6
            snapshot.filesModifiedPerSecond > 2f -> 3
            else -> 0
        }

        val totalScore = (mlScore + entropyScore + decoyScore + behaviorScore).coerceIn(0, 100)

        val threatLevel = when {
            totalScore >= 70 -> ThreatLevel.RANSOMWARE_LIKE
            totalScore >= 40 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.NORMAL
        }

        val explanation = buildExplanation(
            totalScore, mlScore, entropyScore, decoyScore, behaviorScore,
            snapshot, honeypotTriggered
        )

        return RiskScore(
            score = totalScore,
            threatLevel = threatLevel,
            entropyContribution = entropyScore,
            mlContribution = mlScore,
            decoyContribution = decoyScore,
            explanation = explanation
        )
    }

    private fun buildExplanation(
        total: Int,
        ml: Int,
        entropy: Int,
        decoy: Int,
        behavior: Int,
        snapshot: BehaviorSnapshot,
        honeypotTriggered: Boolean
    ): String {
        val parts = mutableListOf<String>()
        if (ml > 0) parts.add("ML model detected threat (score: $ml)")
        if (entropy > 0) parts.add("High file entropy ${snapshot.averageEntropy} (score: $entropy)")
        if (decoy > 0) parts.add("Honeypot file accessed! (score: $decoy)")
        if (behavior > 0) parts.add("Rapid file modifications: ${snapshot.filesModifiedPerSecond}/sec (score: $behavior)")
        if (parts.isEmpty()) parts.add("All systems normal")
        return parts.joinToString(" | ")
    }
}