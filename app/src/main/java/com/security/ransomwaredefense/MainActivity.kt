package com.security.ransomwaredefense

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import com.security.ransomwaredefense.data.ThreatLevel
import com.security.ransomwaredefense.ui.theme.RansomwareDefenseTheme
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //viewModel.startMonitoringService()
        setContent {
            RansomwareDefenseTheme {
                MainScreen(viewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: MainViewModel) {
    val riskScore by viewModel.riskScore.collectAsState()
    val threatLevel by viewModel.threatLevel.collectAsState()
    val explanation by viewModel.currentExplanation.collectAsState()
    val isSimulating by viewModel.isSimulating.collectAsState()
    val fileEvents by viewModel.fileEvents.collectAsState()
    val threatLogs by viewModel.threatLogs.collectAsState()
    val filesPerSecond by viewModel.filesPerSecond.collectAsState()
    val avgEntropy by viewModel.avgEntropy.collectAsState()
    val honeypotTriggered by viewModel.honeypotTriggered.collectAsState()

    var selectedTab by remember { mutableIntStateOf(0) }

    val threatColor = when (threatLevel) {
        ThreatLevel.NORMAL -> Color(0xFF4CAF50)
        ThreatLevel.SUSPICIOUS -> Color(0xFFFF9800)
        ThreatLevel.RANSOMWARE_LIKE -> Color(0xFFF44336)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = null,
                            tint = Color(0xFF4CAF50))
                        Spacer(Modifier.width(8.dp))
                        Text("Ransomware Defense", fontWeight = FontWeight.Bold)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF1A1A2E)
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF0F0F1A))
                .padding(padding)
        ) {
            // Risk Score Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("RISK SCORE", color = Color.Gray, fontSize = 12.sp)
                    Spacer(Modifier.height(8.dp))
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { riskScore / 100f },
                            modifier = Modifier.size(120.dp),
                            color = threatColor,
                            strokeWidth = 10.dp,
                            trackColor = Color(0xFF2A2A3E)
                        )
                        Text(
                            "$riskScore",
                            fontSize = 32.sp,
                            fontWeight = FontWeight.Bold,
                            color = threatColor
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        color = threatColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(20.dp)
                    ) {
                        Text(
                            threatLevel.name.replace("_", " "),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                            color = threatColor,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(explanation, color = Color.Gray, fontSize = 11.sp)
                }
            }

            // Metrics Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                MetricCard("Files/sec",
                    "%.1f".format(filesPerSecond),
                    Color(0xFF2196F3), Modifier.weight(1f))
                MetricCard("Entropy",
                    "%.2f".format(avgEntropy),
                    Color(0xFF9C27B0), Modifier.weight(1f))
                MetricCard("Honeypot",
                    if (honeypotTriggered) "⚠️ HIT" else "Safe",
                    if (honeypotTriggered) Color(0xFFF44336) else Color(0xFF4CAF50),
                    Modifier.weight(1f))
            }

            Spacer(Modifier.height(12.dp))

            // Simulate Button
            Button(
                onClick = { viewModel.simulateRansomwareAttack() },
                enabled = !isSimulating,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFF44336)
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                if (isSimulating) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = Color.White,
                        strokeWidth = 2.dp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Simulating Attack...")
                } else {
                    Icon(Icons.Default.Warning, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Simulate Ransomware Attack", fontWeight = FontWeight.Bold)
                }
            }

            Spacer(Modifier.height(8.dp))

            // Reset Button
            OutlinedButton(
                onClick = { viewModel.resetAlerts() },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Reset Alerts", color = Color.Gray)
            }

            Spacer(Modifier.height(12.dp))

            // Tabs
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = Color(0xFF1A1A2E)
            ) {
                Tab(selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Live Events", color = Color.White) })
                Tab(selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Threat Logs", color = Color.White) })
            }

            when (selectedTab) {
                0 -> EventsList(fileEvents)
                1 -> ThreatLogsList(threatLogs)
            }
        }
    }
}

@Composable
fun MetricCard(title: String, value: String, color: Color, modifier: Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(title, color = Color.Gray, fontSize = 10.sp)
            Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        }
    }
}

@Composable
fun EventsList(events: List<com.security.ransomwaredefense.data.FileEvent>) {
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        if (events.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp),
                    contentAlignment = Alignment.Center) {
                    Text("No file events yet...", color = Color.Gray)
                }
            }
        }
        items(events) { event ->
            EventItem(event)
        }
    }
}

@Composable
fun EventItem(event: com.security.ransomwaredefense.data.FileEvent) {
    val color = if (event.isHoneypot) Color(0xFFF44336) else Color(0xFF4CAF50)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
        Spacer(Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(event.filePath.substringAfterLast("/"),
                color = Color.White, fontSize = 12.sp)
            Text("${event.eventType} • entropy: ${"%.2f".format(event.entropy)}",
                color = Color.Gray, fontSize = 10.sp)
        }
        Text(SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            .format(Date(event.timestamp)),
            color = Color.Gray, fontSize = 10.sp)
    }
}

@Composable
fun ThreatLogsList(logs: List<com.security.ransomwaredefense.data.ThreatLog>) {
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        if (logs.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp),
                    contentAlignment = Alignment.Center) {
                    Text("No threats logged yet", color = Color.Gray)
                }
            }
        }
        items(logs) { log ->
            ThreatLogItem(log)
        }
    }
}

@Composable
fun ThreatLogItem(log: com.security.ransomwaredefense.data.ThreatLog) {
    val color = when (log.threatLevel) {
        "RANSOMWARE_LIKE" -> Color(0xFFF44336)
        "SUSPICIOUS" -> Color(0xFFFF9800)
        else -> Color(0xFF4CAF50)
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A2E)),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(color = color.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)) {
                Text(log.threatLevel.replace("_", " "),
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Risk: ${log.riskScore}/100", color = Color.White, fontSize = 12.sp)
                Text(log.description, color = Color.Gray, fontSize = 10.sp, maxLines = 2)
            }
        }
    }
}