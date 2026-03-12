package com.security.ransomwaredefense

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.security.ransomwaredefense.data.*
import com.security.ransomwaredefense.ml.ThreatClassifier
import com.security.ransomwaredefense.monitors.FileMonitorService
import com.security.ransomwaredefense.security.EntropyAnalyzer
import com.security.ransomwaredefense.security.HoneypotManager
import com.security.ransomwaredefense.security.RiskScoreEngine
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val db = AppDatabase.getInstance(application)
    private val threatLogDao = db.threatLogDao()
    private val behaviorDao = db.behaviorHistoryDao()
    private val classifier = ThreatClassifier(application)
    private val honeypotManager = HoneypotManager(application)

    private val _riskScore = MutableStateFlow(0)
    val riskScore: StateFlow<Int> = _riskScore

    private val _threatLevel = MutableStateFlow(ThreatLevel.NORMAL)
    val threatLevel: StateFlow<ThreatLevel> = _threatLevel

    private val _currentExplanation = MutableStateFlow("System monitoring active...")
    val currentExplanation: StateFlow<String> = _currentExplanation

    private val _fileEvents = MutableStateFlow<List<FileEvent>>(emptyList())
    val fileEvents: StateFlow<List<FileEvent>> = _fileEvents

    private val _isSimulating = MutableStateFlow(false)
    val isSimulating: StateFlow<Boolean> = _isSimulating

    private val _filesPerSecond = MutableStateFlow(0f)
    val filesPerSecond: StateFlow<Float> = _filesPerSecond

    private val _avgEntropy = MutableStateFlow(0f)
    val avgEntropy: StateFlow<Float> = _avgEntropy

    private val _honeypotTriggered = MutableStateFlow(false)
    val honeypotTriggered: StateFlow<Boolean> = _honeypotTriggered

    val threatLogs: StateFlow<List<ThreatLog>> = threatLogDao.getAllLogs()
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    init {
        FileMonitorService.onBehaviorSnapshot = { snapshot ->
            viewModelScope.launch { processBehaviorSnapshot(snapshot) }
        }
        FileMonitorService.onFileEvent = { event ->
            viewModelScope.launch {
                val current = _fileEvents.value.toMutableList()
                current.add(0, event)
                if (current.size > 50) current.removeAt(current.size - 1)
                _fileEvents.value = current
                if (event.isHoneypot) _honeypotTriggered.value = true
            }
        }
    }

    fun startMonitoringService() {
        val context = getApplication<Application>()
        val intent = Intent(context, FileMonitorService::class.java)
        context.startForegroundService(intent)
    }

    private suspend fun processBehaviorSnapshot(snapshot: BehaviorSnapshot) {
        val mlResult = classifier.classify(snapshot)
        val riskScore = RiskScoreEngine.calculateRiskScore(
            snapshot, mlResult, _honeypotTriggered.value
        )

        _riskScore.value = riskScore.score
        _threatLevel.value = riskScore.threatLevel
        _currentExplanation.value = riskScore.explanation
        _filesPerSecond.value = snapshot.filesModifiedPerSecond
        _avgEntropy.value = snapshot.averageEntropy

        if (riskScore.score > 40) {
            val log = ThreatLog(
                timestamp = System.currentTimeMillis(),
                threatLevel = riskScore.threatLevel.name,
                riskScore = riskScore.score,
                description = riskScore.explanation,
                mlConfidence = mlResult.confidence
            )
            threatLogDao.insert(log)
            behaviorDao.insert(
                BehaviorHistory(
                    timestamp = snapshot.timestamp,
                    riskScore = riskScore.score,
                    filesModifiedPerSecond = snapshot.filesModifiedPerSecond,
                    averageEntropy = snapshot.averageEntropy
                )
            )
        }
    }

    fun simulateRansomwareAttack() {
        viewModelScope.launch {
            _isSimulating.value = true
            val context = getApplication<Application>()
            val simDir = File(context.cacheDir, "sim_attack")
            simDir.mkdirs()

            repeat(30) { i ->
                val file = File(simDir, "file_$i.enc")
                val randomBytes = ByteArray(1024) { (Math.random() * 256).toInt().toByte() }
                file.writeBytes(randomBytes)
                delay(100)
            }

            _honeypotTriggered.value = true

            val snapshot = BehaviorSnapshot(
                filesModifiedPerSecond = 12f,
                averageEntropy = 7.8f,
                decoyFileAccessed = 1f,
                unusualExtensionRatio = 0.9f
            )
            processBehaviorSnapshot(snapshot)
            delay(3000)
            simDir.deleteRecursively()
            _isSimulating.value = false
        }
    }

    fun resetAlerts() {
        _honeypotTriggered.value = false
        _riskScore.value = 0
        _threatLevel.value = ThreatLevel.NORMAL
        _currentExplanation.value = "System monitoring active..."
    }

    override fun onCleared() {
        super.onCleared()
        classifier.close()
    }
}