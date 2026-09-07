package com.yair.hackerbar

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import java.net.URI
import java.net.URLEncoder
import java.util.Base64
import java.util.concurrent.TimeUnit

object Engine {
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).callTimeout(20, TimeUnit.SECONDS).build()
    fun allowed(url: String, scope: String): Boolean {
        val uri = URI(url)
        val host = uri.host?.lowercase() ?: return false
        return uri.scheme == "https" && uri.userInfo == null && uri.port in -1..65535 && scope.lines().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.any { host == it } && uri.port != 0
    }
    fun send(url: String, scope: String, method: String, headers: String, body: String): String {
        require(allowed(url, scope)) { "HTTPS host is outside the exact allowlist" }
        val builder = Request.Builder().url(url)
        headers.lines().filter { it.isNotBlank() }.forEach { line ->
            val i = line.indexOf(':'); require(i > 0) { "Invalid header: $line" }
            val name = line.substring(0, i).trim()
            require(!name.equals("Host", true)) { "Host override is not supported" }
            builder.addHeader(name, line.substring(i + 1).trim())
        }
        val payload = if (method == "GET" || method == "HEAD") null else body.toRequestBody("text/plain; charset=utf-8".toMediaType())
        builder.method(method, payload)
        client.newCall(builder.build()).execute().use { response ->
            val text = response.body?.string()?.take(200000) ?: ""
            return "HTTP ${response.code} ${response.message}\n" + response.headers.toString() + "\n" + text
        }
    }
}

data class Payload(val category: String, val name: String, val value: String, val note: String)
val payloads = listOf(
    Payload("XSS", "HTML reflection canary", "HB_CANARY_2026", "Check reflection and output encoding before any active proof."),
    Payload("XSS", "Attribute context", "\"HB_CANARY_2026\"", "Inspect whether quotes are encoded in attribute context."),
    Payload("SQLi", "Quote handling", "'", "Compare errors and response changes against a baseline."),
    Payload("SQLi", "Boolean comparison", "1 AND 1=1", "Use only on an authorized test parameter."),
    Payload("Traversal", "Relative path", "../HB_CANARY_2026", "Check path normalization without requesting sensitive files."),
    Payload("SSTI", "Template arithmetic", "{{7*7}}", "Check whether the template engine evaluates the expression."),
    Payload("SSRF", "Controlled callback", "https://example.com/HB_CANARY_2026", "Replace with an endpoint you own; never target internal services."),
    Payload("WAF", "URL encoding", "%48%42%5F%43%41%4E%41%52%59", "Compare canonical and encoded canaries."),
    Payload("WAF", "Double URL encoding", "%2548%2542%255F%2543%2541%254E%2541%2552%2559", "Observe decoding differences without automated evasion."),
    Payload("WAF", "HTML entities", "&#72;&#66;&#95;CANARY", "Check context-dependent normalization."),
    Payload("WAF", "Case variation", "hb_CaNaRy_2026", "Compare normalization and application behavior.")
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); setContent { MaterialTheme(colorScheme = darkColorScheme()) { App() } } }
}
@Composable fun App() {
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Repeater", "Payloads", "WAF Lab", "Decoder", "Diff")
    var scope by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("https://example.com/") }
    var method by remember { mutableStateOf("GET") }
    var headers by remember { mutableStateOf("") }
    var body by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var baseline by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var lastSend by remember { mutableLongStateOf(0L) }
    val coroutine = rememberCoroutineScope()
    val sendRequest = {
        if (!busy) {
            busy = true
            coroutine.launch {
                result = try {
                    require(System.currentTimeMillis() - lastSend >= 1000) { "Wait at least one second between requests" }
                    lastSend = System.currentTimeMillis()
                    withContext(Dispatchers.IO) { Engine.send(url, scope, method, headers, body) }
                } catch (e: Exception) { "Error: ${e.message}" }
                busy = false
            }
        }
    }
    Column(Modifier.fillMaxSize().padding(12.dp)) {
        Text("HackerBar Mobile", style = MaterialTheme.typography.headlineSmall)
        Text("Authorized testing · Local-first prototype", style = MaterialTheme.typography.bodySmall)
        ScrollableTabRow(selectedTabIndex = tab) { tabs.forEachIndexed { i, name -> Tab(selected = tab == i, onClick = { tab = i }, text = { Text(name) }) } }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            when (tab) {
                0 -> {
                    Text("Scope Guard", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(scope, { scope = it }, label = { Text("Allowed HTTPS hosts, one per line") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                    Text("Exact hosts only. No wildcards, redirects, or automatic cross-host requests.")
                    OutlinedTextField(url, { url = it }, label = { Text("URL") }, modifier = Modifier.fillMaxWidth())
                    Row { listOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD").forEach { m -> TextButton(onClick = { method = m }) { Text(if (method == m) "[$m]" else m) } } }
                    OutlinedTextField(headers, { headers = it }, label = { Text("Headers: one per line") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                    OutlinedTextField(body, { body = it }, label = { Text("Request body") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
                    Button(onClick = sendRequest, enabled = !busy && runCatching { Engine.allowed(url, scope) }.getOrDefault(false)) { Text(if (busy) "Sending…" else "Send request") }
                    OutlinedButton(onClick = { baseline = result }) { Text("Save response as baseline") }
                    Text("Response", style = MaterialTheme.typography.titleMedium)
                    SelectionText(result)
                }
                1 -> {
                    Text("Payload library", style = MaterialTheme.typography.titleLarge)
                    Text("Curated starter checks. Review and adapt each payload before use.")
                    payloads.forEach { p -> Card { Column(Modifier.padding(12.dp)) { Text("${p.category} · ${p.name}", style = MaterialTheme.typography.titleMedium); SelectionText(p.value); Text(p.note); TextButton(onClick = { body = p.value; tab = 0 }) { Text("Use in Repeater body") } } } }
                }
                2 -> {
                    Text("WAF Lab", style = MaterialTheme.typography.titleLarge)
                    Text("Manual normalization experiments; no automatic bypass or attack loop.")
                    var input by remember { mutableStateOf("HB_CANARY_2026") }
                    OutlinedTextField(input, { input = it }, label = { Text("Test canary") }, modifier = Modifier.fillMaxWidth())
                    val variants = listOf("Original" to input, "URL encoded" to URLEncoder.encode(input, "UTF-8"), "Double encoded" to URLEncoder.encode(URLEncoder.encode(input, "UTF-8"), "UTF-8"), "Uppercase" to input.uppercase(), "Lowercase" to input.lowercase())
                    variants.forEach { (name, value) -> Card { Column(Modifier.padding(12.dp)) { Text(name); SelectionText(value); TextButton(onClick = { body = value; tab = 0 }) { Text("Use in Repeater") } } } }
                    Text("Compare a baseline with each manual request. A different status alone does not prove a bypass.")
                }
                3 -> Decoder()
                else -> {
                    Text("Response Diff", style = MaterialTheme.typography.titleLarge)
                    Text("Save a baseline in Repeater, then send another request.")
                    Text("Baseline: ${baseline.length} characters · Current: ${result.length} characters")
                    Text(if (baseline == result) "Responses are identical" else "Responses differ")
                    SelectionText("BASELINE\n$baseline\n\nCURRENT\n$result")
                }
            }
        }
    }
}
@Composable fun SelectionText(value: String) { androidx.compose.foundation.text.selection.SelectionContainer { Text(value, style = MaterialTheme.typography.bodySmall) } }
@Composable fun Decoder() {
    var input by remember { mutableStateOf("") }
    var output by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Encoder / Decoder", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(input, { input = it }, label = { Text("Input") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
        val operations = listOf("Base64 encode", "Base64 decode", "URL encode", "URL decode", "Hex encode", "Hex decode")
        operations.forEach { op -> OutlinedButton(onClick = { output = try { when(op) {
            "Base64 encode" -> Base64.getEncoder().encodeToString(input.toByteArray())
            "Base64 decode" -> String(Base64.getDecoder().decode(input))
            "URL encode" -> URLEncoder.encode(input, "UTF-8")
            "URL decode" -> java.net.URLDecoder.decode(input, "UTF-8")
            "Hex encode" -> input.toByteArray().joinToString("") { "%02x".format(it) }
            else -> { require(input.length % 2 == 0 && input.matches(Regex("[0-9a-fA-F]*"))); String(input.chunked(2).map { it.toInt(16).toByte() }.toByteArray()) }
        } } catch (e: Exception) { "Invalid input: ${e.message}" } }) { Text(op) } }
        SelectionText(output)
    }
}
