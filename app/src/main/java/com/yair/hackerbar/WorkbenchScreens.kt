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
fun HistoryScreen(exchanges: List<HttpExchange>, onOpen: (HttpExchange) -> Unit, onPin: (HttpExchange) -> Unit, onClear: () -> Unit) {
    var query by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Request History", style = MaterialTheme.typography.titleLarge)
            TextButton(onClick = onClear, enabled = exchanges.isNotEmpty()) { Text("Clear") }
        }
        OutlinedTextField(query, { query = it }, label = { Text("Search URL, method, status") }, modifier = Modifier.fillMaxWidth())
        exchanges.filter { query.isBlank() || "${it.method} ${it.url} ${it.status}".contains(query, true) }
            .sortedWith(compareByDescending<HttpExchange> { it.pinned }.thenByDescending { it.timestamp }).take(100).forEach { item ->
            Card(onClick = { onOpen(item) }) { Column(Modifier.fillMaxWidth().padding(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("${if (item.pinned) "★ " else ""}${item.method}  ${item.status}", fontWeight = FontWeight.Bold)
                    TextButton(onClick = { onPin(item) }) { Text(if (item.pinned) "Unpin" else "Pin") }
                }
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
        if (exchange.tlsVersion.isNotBlank()) Text("TLS ${exchange.tlsVersion} · ${exchange.cipherSuite}")
        if (exchange.responseMime.isNotBlank()) Text("${exchange.responseMime}${exchange.responseCharset.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""}${exchange.contentEncoding.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""}")
        if (exchange.redirectLocation.isNotBlank()) Text("Redirect → ${exchange.redirectLocation}")
        if (exchange.certificateSubject.isNotBlank()) {
            Text("Certificate", fontWeight = FontWeight.Bold)
            SelectionText("Subject: ${exchange.certificateSubject}\nIssuer: ${exchange.certificateIssuer}\nExpires: ${if (exchange.certificateNotAfter > 0) java.util.Date(exchange.certificateNotAfter) else "unknown"}")
        }
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

@Composable
fun IntelligenceScreen(exchanges: List<HttpExchange>) {
    var mode by remember { mutableStateOf("Endpoints") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Project Intelligence", style = MaterialTheme.typography.titleLarge)
        Text("Passive inventory generated only from requests already captured in this project.", style = MaterialTheme.typography.bodySmall)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            AssistChip(onClick = { mode = "Endpoints" }, label = { Text(if (mode == "Endpoints") "[Endpoints]" else "Endpoints") })
            AssistChip(onClick = { mode = "Parameters" }, label = { Text(if (mode == "Parameters") "[Parameters]" else "Parameters") })
        }
        val text = if (mode == "Endpoints") endpointMap(exchanges) else parameterInventory(exchanges)
        SelectionText(text)
    }
}
