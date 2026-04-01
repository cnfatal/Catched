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
import androidx.compose.ui.res.stringResource
import cn.fatalc.catched.R
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
            title = { Text(stringResource(R.string.app_name), fontWeight = FontWeight.SemiBold) },
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
                        Icon(Icons.Default.Refresh, contentDescription = stringResource(R.string.scan_re_scan))
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
                
                OverallStatus(total = total, detected = detected, isScanning = uiState.isScanning)
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
private fun OverallStatus(total: Int, detected: Int, isScanning: Boolean) {
    val size = 160.dp
    val color = when {
        isScanning -> AccentBlue
        detected > 0 -> DangerRed
        else -> SafeGreen
    }
    
    val icon = when {
        isScanning -> Icons.Default.Sync
        detected > 0 -> Icons.Default.Warning
        else -> Icons.Default.CheckCircle
    }
    
    val text = when {
        isScanning -> stringResource(R.string.scan_in_progress)
        detected > 0 -> stringResource(R.string.status_detected_count, detected)
        else -> stringResource(R.string.status_safe)
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            shape = androidx.compose.foundation.shape.CircleShape,
            color = color.copy(alpha = 0.1f),
            modifier = Modifier.size(size)
        ) {
            Column(
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(48.dp))
                Spacer(Modifier.height(8.dp))
                Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = color)
                if (!isScanning) {
                    Text("$total " + stringResource(R.string.stat_items), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        }
    }
}
