package cn.fatalc.catched.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import cn.fatalc.catched.ScanUiState
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.ui.components.DetectionCard
import cn.fatalc.catched.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(
    groups: List<String>,
    checksForGroup: (String) -> List<Check>,
    uiState: ScanUiState,
    onStartScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    LaunchedEffect(Unit) {
        if (!uiState.isScanning && uiState.results.isEmpty()) {
            onStartScan()
        }
    }

    Column(modifier = modifier.fillMaxSize().background(DarkBackground)) {
        TopAppBar(
            title = { Text("Catched", fontWeight = FontWeight.SemiBold) },
            actions = {
                if (uiState.isScanning) {
                    Text(
                        "${(uiState.progress * 100).toInt()}%",
                        style = MaterialTheme.typography.labelLarge,
                        color = AccentBlue,
                        modifier = Modifier.padding(end = 12.dp)
                    )
                } else if (uiState.results.isNotEmpty()) {
                    IconButton(onClick = onStartScan) {
                        Icon(Icons.Default.Refresh, contentDescription = "重新扫描")
                    }
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = DarkBackground,
                titleContentColor = TextPrimary,
                actionIconContentColor = TextPrimary
            )
        )

        if (uiState.isScanning) {
            LinearProgressIndicator(
                progress = { uiState.progress },
                modifier = Modifier.fillMaxWidth(),
                color = AccentBlue,
                trackColor = DarkSurfaceVariant
            )
        }

        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(horizontal = 16.dp)
        ) {
            Spacer(Modifier.height(8.dp))

            // 概览
            if (!uiState.isScanning && uiState.results.isNotEmpty()) {
                val total = groups.sumOf { checksForGroup(it).size }
                val detected = uiState.results.values.count { it.detected }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = DarkCard)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        StatItem("检测项", "$total", AccentBlue)
                        StatItem("检出", "$detected", if (detected > 0) DangerRed else SafeGreen)
                        StatItem("通过", "${total - detected}", SafeGreen)
                        StatItem("耗时", "${uiState.scanTimeMs}ms", TextSecondary)
                    }
                }
                Spacer(Modifier.height(16.dp))
            }

            // 分组卡片
            groups.forEach { group ->
                DetectionCard(
                    groupName = group,
                    checks = checksForGroup(group),
                    results = uiState.results,
                    isScanning = uiState.isScanning
                )
                Spacer(Modifier.height(12.dp))
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun StatItem(label: String, value: String, color: androidx.compose.ui.graphics.Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = color)
        Text(label, style = MaterialTheme.typography.bodySmall, color = TextTertiary)
    }
}
