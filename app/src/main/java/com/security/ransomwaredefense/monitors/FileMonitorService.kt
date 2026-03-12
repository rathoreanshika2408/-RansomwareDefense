package com.security.ransomwaredefense.monitors

import android.app.*
import android.content.Intent
import android.os.*
import androidx.core.app.NotificationCompat
import com.security.ransomwaredefense.data.*
import com.security.ransomwaredefense.security.EntropyAnalyzer
import com.security.ransomwaredefense.security.HoneypotManager
import kotlinx.coroutines.*
import java.io.File

class FileMonitorService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val fileEvents = mutableListOf<FileEvent>()
    private var fileObserver: FileObserver? = null
    private lateinit var honeypotManager: HoneypotManager
    private var fileModifiedCount = 0
    private var lastCountReset = System.currentTimeMillis()

    companion object {
        const val CHANNEL_ID = "ransomware_defense_channel"
        const val NOTIFICATION_ID = 1001
        const val ACTION_THREAT_DETECTED = "com.security.ransomwaredefense.THREAT_DETECTED"
        var onFileEvent: ((FileEvent) -> Unit)? = null
        var onBehaviorSnapshot: ((BehaviorSnapshot) -> Unit)? = null
    }

    override fun onCreate() {
        super.onCreate()
        honeypotManager = HoneypotManager(this)
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("🛡️ Monitoring Active"))
        honeypotManager.createHoneypotFiles()
        startMonitoring()
        startBehaviorAnalysis()
    }

    private fun startMonitoring() {
        val dirsToWatch = listOf(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES)
        )

        dirsToWatch.forEach { dir ->
            if (dir.exists()) {
                watchDirectory(dir)
            }
        }
    }

    private fun watchDirectory(dir: File) {
        val observer = object : FileObserver(File(dir.absolutePath),
            CREATE or MODIFY or DELETE or MOVED_FROM or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                path ?: return
                val fullPath = "${dir.absolutePath}/$path"
                val eventType = when (event and ALL_EVENTS) {
                    CREATE -> "CREATE"
                    MODIFY -> "MODIFY"
                    DELETE -> "DELETE"
                    MOVED_FROM -> "MOVED_FROM"
                    MOVED_TO -> "MOVED_TO"
                    else -> "UNKNOWN"
                }

                val isHoneypot = honeypotManager.isHoneypotFile(fullPath)
                val entropy = try {
                    EntropyAnalyzer.calculateEntropy(File(fullPath))
                } catch (e: Exception) { 0.0 }

                val fileEvent = FileEvent(
                    filePath = fullPath,
                    eventType = eventType,
                    timestamp = System.currentTimeMillis(),
                    isHoneypot = isHoneypot,
                    entropy = entropy
                )

                fileModifiedCount++
                synchronized(fileEvents) {
                    fileEvents.add(fileEvent)
                    if (fileEvents.size > 200) fileEvents.removeAt(0)
                }

                onFileEvent?.invoke(fileEvent)

                if (isHoneypot) {
                    sendThreatAlert("⚠️ Honeypot file accessed: $path")
                }
            }
        }
        observer.startWatching()
        fileObserver = observer
    }

    private fun startBehaviorAnalysis() {
        serviceScope.launch {
            while (isActive) {
                delay(2000)
                val now = System.currentTimeMillis()
                val elapsed = (now - lastCountReset) / 1000.0f
                val filesPerSecond = if (elapsed > 0) fileModifiedCount / elapsed else 0f

                val recentEvents = synchronized(fileEvents) { fileEvents.takeLast(20) }
                val avgEntropy = if (recentEvents.isNotEmpty())
                    recentEvents.map { it.entropy }.average().toFloat() else 0f
                val decoyAccessed = if (recentEvents.any { it.isHoneypot }) 1f else 0f
                val unusualExtensions = recentEvents.count { event ->
                    listOf(".enc", ".locked", ".crypto", ".crypt")
                        .any { event.filePath.endsWith(it) }
                }.toFloat() / recentEvents.size.coerceAtLeast(1)

                val snapshot = BehaviorSnapshot(
                    filesModifiedPerSecond = filesPerSecond,
                    averageEntropy = avgEntropy,
                    decoyFileAccessed = decoyAccessed,
                    unusualExtensionRatio = unusualExtensions
                )

                onBehaviorSnapshot?.invoke(snapshot)
                fileModifiedCount = 0
                lastCountReset = now
            }
        }
    }

    fun sendThreatAlert(message: String) {
        val notification = buildNotification(message)
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID + 1, notification)
    }

    private fun buildNotification(message: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Ransomware Defense")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Ransomware Defense",
            NotificationManager.IMPORTANCE_HIGH
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        fileObserver?.stopWatching()
        serviceScope.cancel()
    }
}