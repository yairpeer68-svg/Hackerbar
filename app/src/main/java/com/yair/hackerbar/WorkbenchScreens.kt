package com.yair.hackerbar

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun HistoryScreen(exchanges: List<HttpExchange>, onOpen: (HttpExchange) -> Unit, onClear: () -> Unit) {
    var query by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Request History", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = onClear, enabled = exchanges.isNotEmpty()) { Text("Clear") }
        }
        OutlinedTextField(query, { query = it }, label = { Text("Search URL, method, status") }, modifier = Modifier.fillMaxWidth())
        exchanges.filter { query.isBlank() || "${it.method} ${it.url} ${it.status}".contains(query, true) }.take(100).forEach { item ->
            Card(onClick = { onOpen(item) }) { Column(Modifier.fillMaxWidth().padding(10.dp)) {
                Text("${item.method}  ${item.status}", fontWeight = FontWeight.Bold)
                Text(item.url, style = MaterialTheme.typography.bodySmall)
                Text("${item.durationMs} ms · ${item.responseBytes} bytes · ${item.project}", style = MaterialTheme.typography.labelSmall)
            } }
        }
    }
}
@Composable
fun AnalysisScreen(exchange: HttpExchange?) {
    if (exchange == null) {
        Text("Send or open a request first to analyze its response.")
        return
    }
    val findings = remember(exchange.id) { PassiveAnalyzer.analyze(exchange) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Passive Security Analysis", style = MaterialTheme.typography.titleLarge)
        Text("${exchange.method} ${exchange.url}", style = MaterialTheme.typography.bodySmall)
        Text("HTTP ${exchange.status} · ${exchange.durationMs} ms · ${exchange.responseBytes} bytes")
        if (findings.isEmpty()) Text("No passive header or cookie observations detected.")
        findings.forEach { f -> Card { Column(Modifier.padding(10.dp)) {
            Text("${f.severity} · ${f.title}", fontWeight = FontWeight.Bold)
            Text(f.evidence, style = MaterialTheme.typography.bodySmall)
            Text(f.recommendation, style = MaterialTheme.typography.bodySmall)
        } }
        }
        Text("Response headers", fontWeight = FontWeight.Bold)
        SelectionText(redactSecrets(exchange.responseHeaders))
    }
}
@Composable
fun ProjectsScreen(projects: List<String>, current: String, onSelect: (String) -> Unit, onAdd: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Projects", style = MaterialTheme.typography.titleLarge)
        Text("Current project: $current")
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(name, { name = it }, label = { Text("New project") }, modifier = Modifier.weight(1f), singleLine = true)
            Button(onClick = { if (name.isNotBlank()) { onAdd(name); name = "" } }) { Text("Add") }
        }
        projects.forEach { p ->
            OutlinedButton(onClick = { onSelect(p) }, modifier = Modifier.fillMaxWidth()) {
                Text(if (p == current) "✓ $p" else p)
            }
        }
        Text("Projects separate request history context. Stored locally on this device.", style = MaterialTheme.typography.bodySmall)
    }
}
