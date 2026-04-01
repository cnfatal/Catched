package cn.fatalc.catched.ui.components

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import cn.fatalc.catched.R
import cn.fatalc.catched.model.Check
import cn.fatalc.catched.model.CheckResult
import cn.fatalc.catched.ui.theme.*

@Composable
fun DetectionCard(
    groupName: String,
    checks: List<Check>,
    results: Map<String, CheckResult>,
    isScanning: Boolean,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    val scanned = checks.count { it.id in results }
    val detected = checks.count { results[it.id]?.detected == true }
    val allDone = scanned == checks.size
    val progress = if (checks.isNotEmpty()) scanned.toFloat() / checks.size else 0f

    val headerColor = when {
        !allDone -> TextTertiary
        detected == 0 -> SafeGreen
        else -> DangerRed
    }

    val progressColor = when {
        !allDone -> AccentBlue
        detected == 0 -> SafeGreen
        else -> DangerRed
    }

    Card(
        modifier = modifier.fillMaxWidth().clickable { expanded = !expanded },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DarkCard)
    ) {
        Column {
            // 头部
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    if (isScanning && !allDone && scanned > 0) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(12.dp), color = AccentBlue, strokeWidth = 2.dp
                        )
                    } else {
                        Box(modifier = Modifier.size(10.dp).clip(CircleShape).background(headerColor))
                    }
                    Spacer(Modifier.width(12.dp))
                    Text(
                        groupName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        when {
                            scanned == 0 -> "${checks.size} items"
                            !allDone -> "$scanned/${checks.size}"
                            detected > 0 -> "$detected/${checks.size}"
                            else -> "${checks.size} pass"
                        },
                        style = MaterialTheme.typography.labelMedium,
                        color = headerColor
                    )
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = null, tint = TextTertiary, modifier = Modifier.size(20.dp)
                    )
                }
            }

            // 检出比例条
            if (allDone) {
                val ratio = if (checks.isNotEmpty()) detected.toFloat() / checks.size else 0f
                LinearProgressIndicator(
                    progress = { ratio },
                    modifier = Modifier.fillMaxWidth().height(3.dp),
                    color = if (detected > 0) DangerRed else SafeGreen,
                    trackColor = SafeGreen.copy(alpha = 0.3f)
                )
            } else if (isScanning) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().height(3.dp),
                    color = AccentBlue,
                    trackColor = DarkSurfaceVariant
                )
            } else {
                Spacer(Modifier.height(3.dp).fillMaxWidth().background(DarkSurfaceVariant))
            }

            // 展开内容
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                    checks.forEachIndexed { index, check ->
                        CheckRow(check, results[check.id])
                        if (index < checks.lastIndex) {
                            HorizontalDivider(
                                color = DividerColor,
                                modifier = Modifier.padding(horizontal = 8.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CheckRow(check: Check, result: CheckResult?) {
    val color = when {
        result == null -> TextTertiary
        result.detected -> DangerRed
        else -> SafeGreen
    }
    var showDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(if (result?.detected == true) color.copy(alpha = 0.06f) else Color.Transparent)
            .clickable { showDialog = true }
            .padding(horizontal = 12.dp, vertical = 12.dp)
    ) {
        // 第一行：状态点 + 名称 + id
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(12.dp))
            Text(
                check.name,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = if (result != null) TextPrimary else TextTertiary,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            Text(check.id, style = MaterialTheme.typography.labelSmall, color = TextTertiary)
        }

        // actual/evidence 行
        if (result != null) {
            val hasActualOrExpected = result.actual != null || check.expected != null
            val hasEvidence = result.evidence != null
            
            if (hasActualOrExpected) {
                if (check.expected != null) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "${stringResource(R.string.label_expected)}: ${check.expected.replace("\n", " ")}",
                        style = MaterialTheme.typography.bodySmall,
                        color = SafeGreen.copy(alpha = 0.8f),
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        modifier = Modifier.padding(start = 20.dp)
                    )
                }
                if (result.actual != null) {
                    Spacer(Modifier.height(4.dp))
                    val actColor = if (result.detected) DangerRed.copy(alpha = 0.8f) else color.copy(alpha = 0.8f)
                    Text(
                        "${stringResource(R.string.label_actual)}: ${result.actual.replace("\n", " ")}",
                        style = MaterialTheme.typography.bodySmall,
                        color = actColor,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        modifier = Modifier.padding(start = 20.dp)
                    )
                }
            }
            if (hasEvidence) {
                Spacer(Modifier.height(4.dp))
                Text(
                    result.evidence!!.replace("\n", " "),
                    style = MaterialTheme.typography.bodySmall,
                    color = color.copy(alpha = 0.7f),
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    modifier = Modifier.padding(start = 20.dp)
                )
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            when {
                                result == null -> Icons.Default.HourglassEmpty
                                result.detected -> Icons.Default.Warning
                                else -> Icons.Default.CheckCircle
                            },
                            contentDescription = null, tint = color, modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(check.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            Text(check.id, style = MaterialTheme.typography.labelSmall, color = TextTertiary)
                        }
                    }
                    if (check.tags.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        @OptIn(ExperimentalLayoutApi::class)
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            check.tags.forEach { tag ->
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = DarkSurfaceVariant
                                ) {
                                    Text(
                                        tag,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextSecondary,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            },
            text = {
                Column {
                    Text(check.description, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                    Spacer(Modifier.height(12.dp))
                    if (result != null) {
                        Text(
                            if (result.detected) stringResource(R.string.check_status_detected) else stringResource(R.string.check_status_passed),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold, color = color
                        )
                        // expected / actual
                        if (check.expected != null || result.actual != null) {
                            Spacer(Modifier.height(12.dp))
                            Column(modifier = Modifier.fillMaxWidth()) {
                                if (check.expected != null) {
                                    Text(stringResource(R.string.label_expected),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextSecondary)
                                    Spacer(Modifier.height(4.dp))
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = DarkBackground,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(check.expected,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = SafeGreen.copy(alpha = 0.8f),
                                            modifier = Modifier.padding(8.dp))
                                    }
                                }
                                if (result.actual != null) {
                                    if (check.expected != null) Spacer(Modifier.height(8.dp))
                                    Text(stringResource(R.string.label_actual),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextSecondary)
                                    Spacer(Modifier.height(4.dp))
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = DarkBackground,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(result.actual,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = if (result.detected) DangerRed.copy(alpha = 0.8f) else TextPrimary,
                                            modifier = Modifier.padding(8.dp))
                                    }
                                }
                            }
                        }
                        // evidence
                        if (result.evidence != null) {
                            Spacer(Modifier.height(8.dp))
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = DarkBackground,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    result.evidence,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextPrimary,
                                    modifier = Modifier.padding(8.dp)
                                )
                            }
                        }
                    } else {
                        Text(stringResource(R.string.check_status_waiting), style = MaterialTheme.typography.bodyMedium, color = TextTertiary)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showDialog = false }) { Text("关闭") } },
            containerColor = DarkCard,
            titleContentColor = TextPrimary,
            textContentColor = TextPrimary
        )
    }
}
