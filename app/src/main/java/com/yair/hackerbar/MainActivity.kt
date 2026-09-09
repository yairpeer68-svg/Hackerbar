package com.yair.hackerbar

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import java.net.URI
import java.net.URLEncoder
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

private const val PRIVACY_UA_FOR_REPEATER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

private fun upsertHeaderText(text: String, name: String, value: String): String =
    (text.lineSequence().filter { it.isNotBlank() && !it.substringBefore(':').trim().equals(name, true) }.toList() + "$name: $value").joinToString("\n")

object Engine {
    private const val MAX_RESPONSE_BYTES = 262144L
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).callTimeout(20, TimeUnit.SECONDS).build()
    private val activeCall = AtomicReference<Call?>(null)
    fun cancelActive() { activeCall.getAndSet(null)?.cancel() }
    fun normalizeUrl(raw: String): String {
        val t = raw.trim()
        return if (t.contains("://")) t else "https://$t"
    }
    fun normalizeScopeEntry(raw: String): String {
        val t = raw.trim().lowercase()
        if (t.isBlank()) return ""
        return runCatching { URI(normalizeUrl(t)).host?.lowercase().orEmpty() }.getOrDefault(t.substringBefore('/').substringBefore(':'))
    }
    fun hostOf(raw: String): String = runCatching { URI(normalizeUrl(raw)).host?.lowercase().orEmpty() }.getOrDefault("")
    fun withTestParam(raw: String, value: String): String = normalizeUrl(raw).toHttpUrl().newBuilder().setQueryParameter("hb_test", value).build().toString()
    fun validationError(url: String, scope: String): String? {
        val normalized = normalizeUrl(url)
        val uri = runCatching { URI(normalized) }.getOrElse { return "Invalid URL" }
        val host = uri.host?.lowercase() ?: return "URL must contain a valid host"
        if (uri.scheme != "https") return "Only HTTPS requests are allowed"
        if (uri.userInfo != null) return "User-info in URLs is not allowed"
        if (uri.port == 0 || uri.port > 65535) return "Invalid port"
        return null
    }
    fun allowed(url: String, scope: String): Boolean = validationError(url, scope) == null
    fun sendDetailed(url: String, scope: String, method: String, headers: String, body: String, project: String = "Default"): HttpExchange {
        val normalizedUrl = normalizeUrl(url)
        require(allowed(normalizedUrl, scope)) { validationError(normalizedUrl, scope) ?: "Request is not allowed" }
        val builder = Request.Builder().url(normalizedUrl)
        var requestType: MediaType? = null
        headers.lines().filter { it.isNotBlank() }.forEach { line ->
            val i = line.indexOf(':'); require(i > 0) { "Invalid header: $line" }
            val name = line.substring(0, i).trim()
            val value = line.substring(i + 1).trim()
            require(!name.equals("Host", true)) { "Host override is not supported" }
            if (name.equals("Content-Length", true) || name.equals("Transfer-Encoding", true)) return@forEach
            if (name.equals("Content-Type", true)) requestType = value.toMediaType()
            builder.addHeader(name, value)
        }
        val payload = if (method == "GET" || method == "HEAD") null else body.toRequestBody(requestType ?: "text/plain; charset=utf-8".toMediaType())
        builder.method(method, payload)
        val started = System.nanoTime()
        val call = client.newCall(builder.build())
        activeCall.set(call)
        try {
            call.execute().use { response ->
                val responseBody = response.body
                val type = responseBody?.contentType()
                val source = responseBody?.source()
                val bytes = source?.readByteArray(MAX_RESPONSE_BYTES + 1) ?: ByteArray(0)
                val truncated = bytes.size > MAX_RESPONSE_BYTES
                val safeBytes = if (truncated) bytes.copyOf(MAX_RESPONSE_BYTES.toInt()) else bytes
                val mime = type?.type.orEmpty() + "/" + type?.subtype.orEmpty()
                val textual = type == null || type.type == "text" || type.subtype.contains("json", true) || type.subtype.contains("xml", true) || type.subtype.contains("javascript", true) || type.subtype.contains("html", true)
                val text = if (textual) safeBytes.toString(type?.charset(Charsets.UTF_8) ?: Charsets.UTF_8) + if (truncated) "\n[response truncated at 256 KiB]" else "" else "[binary response omitted: $mime, ${responseBody?.contentLength()?.takeIf { it >= 0 } ?: safeBytes.size.toLong()} bytes]"
                return HttpExchange(project = project, method = method, url = normalizedUrl, requestHeaders = headers, requestBody = body, status = response.code, responseHeaders = response.headers.toString(), responseBody = text, durationMs = (System.nanoTime() - started) / 1_000_000, responseBytes = responseBody?.contentLength()?.takeIf { it >= 0 } ?: safeBytes.size.toLong())
            }
        } finally { activeCall.compareAndSet(call, null) }
    }
    fun render(exchange: HttpExchange): String =
        "HTTP ${exchange.status}\n${exchange.responseHeaders}\n${exchange.responseBody}"

}

data class CapturedRequest(val url: String, val method: String, val headers: Map<String, String>, val body: String = "")
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
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); CrashReporter.install(this); setContent { MaterialTheme(colorScheme = darkColorScheme()) { App() } } }
}
@Composable fun App() {
    var tab by remember { mutableIntStateOf(0) }
    var browserUrl by remember { mutableStateOf("https://example.com/") }
    val tabs = listOf("Browser", "Repeater", "History", "Analyze", "Projects", "Payloads", "WAF Lab", "Decoder", "Diff", "Intel", "Findings")
    var scope by remember { mutableStateOf("example.com") }
    var url by remember { mutableStateOf("https://example.com/") }
    var method by remember { mutableStateOf("GET") }
    var headers by remember { mutableStateOf("") }
    var body by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var baseline by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var lastSend by remember { mutableLongStateOf(0L) }
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val store = remember(context.applicationContext) { WorkbenchStore(context.applicationContext) }
    var findings by remember { mutableStateOf(emptyList<String>()) }
    var exchanges by remember { mutableStateOf(emptyList<HttpExchange>()) }
    var projects by remember { mutableStateOf(listOf("Default")) }
    var currentProject by remember { mutableStateOf("Default") }
    var lastExchange by remember { mutableStateOf<HttpExchange?>(null) }
    var storageWarning by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        runCatching {
            val loaded = withContext(Dispatchers.IO) { Triple(store.loadFindings(), store.loadExchanges(), store.loadProjects().ifEmpty { listOf("Default") }) }
            findings = loaded.first
            exchanges = loaded.second
            projects = loaded.third
            currentProject = projects.first()
            lastExchange = exchanges.firstOrNull()
        }.onFailure { storageWarning = "Could not load local workbench data: ${it.javaClass.simpleName}" }
    }
    val coroutine = rememberCoroutineScope()
    val sendRequest = {
        if (!busy) {
            busy = true
            coroutine.launch {
                result = try {
                    require(System.currentTimeMillis() - lastSend >= 1000) { "Wait at least one second between requests" }
                    lastSend = System.currentTimeMillis()
                    url = Engine.normalizeUrl(url)
                    val exchange = withContext(Dispatchers.IO) { Engine.sendDetailed(url, scope, method, headers, body, currentProject) }
                    withContext(Dispatchers.IO) { store.saveExchange(exchange) }
                    exchanges = withContext(Dispatchers.IO) { store.loadExchanges() }
                    lastExchange = exchange
                    Engine.render(exchange)
                } catch (e: Exception) {
                    val detail = e.message?.takeIf { it.isNotBlank() } ?: e.cause?.message?.takeIf { it.isNotBlank() } ?: e.javaClass.simpleName
                    "Error: $detail"
                }
                busy = false
            }
        }
    }
    Column(Modifier.fillMaxSize().background(Color(0xFF0B0F12))) {
        storageWarning?.let { Text(it, color = Color(0xFFFFC857), modifier = Modifier.padding(6.dp)) }
        Row(Modifier.fillMaxWidth().background(Color(0xFF11181D)).padding(horizontal = 8.dp, vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.hackerbar_logo), "HackerBar logo", Modifier.size(30.dp).clip(RoundedCornerShape(15.dp)))
            Spacer(Modifier.width(7.dp))
            Column(Modifier.weight(1f)) {
                Text("DH HackerBar Mobile", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium)
                Text("Authorized Security Workbench", color = Color(0xFF72D6FF), style = MaterialTheme.typography.labelSmall)
            }
            AssistChip(onClick = { tab = 1 }, label = { Text("Scope") })
        }
        ScrollableTabRow(selectedTabIndex = tab, edgePadding = 0.dp, containerColor = Color(0xFF0F1519)) { tabs.forEachIndexed { i, name -> Tab(selected = tab == i, onClick = { tab = i }, text = { Text(name) }) } }
        Column(Modifier.fillMaxSize().padding(6.dp).then(if (tab == 0) Modifier else Modifier.verticalScroll(rememberScrollState())), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            when (tab) {
                0 -> BrowserWorkspace(browserUrl, { browserUrl = it }, { req ->
                    url = Engine.normalizeUrl(req.url)
                    Engine.hostOf(req.url).takeIf { it.isNotBlank() }?.let { scope = it }
                    method = req.method.uppercase().takeIf { it in listOf("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS") } ?: "GET"
                    headers = req.headers.entries
                        .filterNot { (k, _) -> k.equals("Host", true) || k.equals("Content-Length", true) || k.startsWith("sec-ch-ua", true) || k.equals("X-Requested-With", true) || k.equals("User-Agent", true) }
                        .joinToString("\n") { (k, v) -> "$k: $v" }
                    headers = listOf(headers, "User-Agent: $PRIVACY_UA_FOR_REPEATER", "sec-ch-ua: \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"", "sec-ch-ua-mobile: ?0", "sec-ch-ua-platform: \"Windows\"").filter { it.isNotBlank() }.joinToString("\n")
                    body = req.body.take(128000)
                    result = "Captured from Browser: ${method} ${url}${if (body.isNotBlank()) " · body ${body.length} chars" else ""}"
                    tab = 1
                }, { tool, req ->
                    url = Engine.normalizeUrl(req.url)
                    Engine.hostOf(req.url).takeIf { it.isNotBlank() }?.let { scope = it }
                    method = req.method.uppercase().takeIf { it in listOf("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS") } ?: "GET"
                    headers = req.headers.entries
                        .filterNot { (k, _) -> k.equals("Host", true) || k.equals("Content-Length", true) || k.startsWith("sec-ch-ua", true) || k.equals("X-Requested-With", true) || k.equals("User-Agent", true) }
                        .joinToString("\n") { (k, v) -> "$k: $v" }
                    headers = listOf(headers, "User-Agent: $PRIVACY_UA_FOR_REPEATER", "sec-ch-ua: \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"", "sec-ch-ua-mobile: ?0", "sec-ch-ua-platform: \"Windows\"").filter { it.isNotBlank() }.joinToString("\n")
                    body = req.body.take(128000)
                    val testValue = when (tool) {
                        "SQLi" -> "'"
                        "XSS" -> "HB_CANARY_2026"
                        "LFI / Traversal" -> "../HB_CANARY_2026"
                        "SSTI" -> "{{7*7}}"
                        "SSRF" -> "https://example.com/HB_CANARY_2026"
                        else -> ""
                    }
                    if (testValue.isNotBlank()) {
                        if (method in listOf("GET", "HEAD")) { url = Engine.withTestParam(url, testValue); body = "" } else body = testValue
                    }
                    if (tool == "Authorization" && headers.lineSequence().none { it.startsWith("Authorization:", true) }) {
                        headers = listOf(headers, "Authorization: Bearer TEST_TOKEN").filter { it.isNotBlank() }.joinToString("\n")
                    }
                    result = "Prepared $tool from Browser: ${method} ${url}"
                    tab = if (tool == "WAF Lab") 6 else 1
                })
                1 -> {
                    Text("Target", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(scope, { scope = it }, label = { Text("Current host (auto-updated)") }, modifier = Modifier.fillMaxWidth(), minLines = 1)
                    Text("Scope is informational only; requests are not blocked by this field. HTTPS URL validation remains enabled.")
                    OutlinedTextField(url, { value ->
                        url = value
                        Engine.hostOf(value).takeIf { it.isNotBlank() }?.let { scope = it }
                    }, label = { Text("URL (https:// optional)") }, modifier = Modifier.fillMaxWidth())
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) { listOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS").forEach { m -> TextButton(onClick = { method = m }) { Text(if (method == m) "[$m]" else m) } } }
                    OutlinedTextField(headers, { headers = it }, label = { Text("Headers: one per line") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        AssistChip(onClick = { headers = upsertHeaderText(headers, "Content-Type", "application/json; charset=utf-8") }, label = { Text("JSON") })
                        AssistChip(onClick = { headers = upsertHeaderText(headers, "Content-Type", "application/x-www-form-urlencoded") }, label = { Text("Form") })
                        AssistChip(onClick = { headers = upsertHeaderText(headers, "Content-Type", "application/xml; charset=utf-8") }, label = { Text("XML") })
                        AssistChip(onClick = { headers = upsertHeaderText(headers, "Content-Type", "text/plain; charset=utf-8") }, label = { Text("Text") })
                    }
                    OutlinedTextField(body, { body = it }, label = { Text("Request body") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
                    val validation = Engine.validationError(url, scope)
                    if (validation != null) Text(validation, color = Color(0xFFFFC857), style = MaterialTheme.typography.bodySmall)
                    when {
                        busy -> Text("Sending request…", color = Color(0xFF72D6FF), fontWeight = FontWeight.SemiBold)
                        result.startsWith("HTTP ") -> Text(result.lineSequence().first(), color = Color(0xFF72E6A6), fontWeight = FontWeight.Bold)
                        result.startsWith("Error:") -> Text(result.lineSequence().first(), color = Color(0xFFFF7A7A), fontWeight = FontWeight.Bold)
                        result.startsWith("Captured from Browser:") -> Text(result, color = Color(0xFF72D6FF), style = MaterialTheme.typography.bodySmall)
                    }
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = sendRequest, enabled = !busy) { Text(if (busy) "Sending…" else "Execute") }
                        if (busy) OutlinedButton(onClick = { Engine.cancelActive() }) { Text("Cancel") }
                        OutlinedButton(onClick = { baseline = result }, enabled = result.isNotBlank()) { Text("Baseline") }
                        OutlinedButton(onClick = { if (result.isNotBlank()) { store.saveFinding("${method} ${url}\n${redactSecrets(result.take(10000))}"); findings = store.loadFindings() } }, enabled = result.isNotBlank()) { Text("Save finding") }
                        OutlinedButton(onClick = { tab = 3 }, enabled = lastExchange != null) { Text("Analyze") }
                        OutlinedButton(onClick = { clipboard.setText(AnnotatedString(requestAsCurl(method, url, headers, body))) }) { Text("Copy cURL") }
                        OutlinedButton(onClick = { clipboard.setText(AnnotatedString(requestAsRawHttp(method, url, headers, body))) }) { Text("Copy Raw") }
                        TextButton(onClick = { headers = ""; body = ""; result = "" }) { Text("Clear") }
                    }
                    Text("Response", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        AssistChip(onClick = { lastExchange?.let { result = Engine.render(it.copy(responseBody = prettyJsonOrOriginal(it.responseBody))) } }, label = { Text("Pretty JSON") })
                        AssistChip(onClick = { clipboard.setText(AnnotatedString(result)) }, label = { Text("Copy Response") })
                    }
                    SelectionText(result)
                }
                2 -> HistoryScreen(exchanges.filter { it.project == currentProject }, { item ->
                    lastExchange = item; url = item.url; method = item.method; headers = item.requestHeaders; body = item.requestBody; result = Engine.render(item); tab = 1
                }, { coroutine.launch { withContext(Dispatchers.IO) { store.clearExchanges(currentProject) }; exchanges = withContext(Dispatchers.IO) { store.loadExchanges() }; lastExchange = null } })
                3 -> AnalysisScreen(lastExchange)
                4 -> ProjectsScreen(projects, currentProject, { currentProject = it }, { name -> store.addProject(name); projects = store.loadProjects(); currentProject = name.trim().take(40) })
                5 -> {
                    Text("Payload Intelligence", style = MaterialTheme.typography.titleLarge)
                    Text("Curated manual checks with context and expected interpretation.")
                    var q by remember { mutableStateOf("") }
                    OutlinedTextField(q, { q = it }, label = { Text("Search category, name or note") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    payloads.filter { q.isBlank() || (it.category + it.name + it.note).contains(q, true) }.forEach { p ->
                        Card { Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("${p.category} · ${p.name}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            SelectionText(p.value); Text(p.note, style = MaterialTheme.typography.bodySmall)
                            TextButton(onClick = { if (method in listOf("GET", "HEAD")) { url = Engine.withTestParam(url, p.value); body = "" } else body = p.value; tab = 1 }) { Text("Send to Repeater") }
                        } }
                    }
                }
                6 -> {
                    Text("WAF Lab", style = MaterialTheme.typography.titleLarge)
                    Text("Manual normalization experiments; no automatic bypass or attack loop.")
                    var input by remember { mutableStateOf("HB_CANARY_2026") }
                    OutlinedTextField(input, { input = it }, label = { Text("Test canary") }, modifier = Modifier.fillMaxWidth())
                    val variants = listOf("Original" to input, "URL encoded" to URLEncoder.encode(input, "UTF-8"), "Double encoded" to URLEncoder.encode(URLEncoder.encode(input, "UTF-8"), "UTF-8"), "Uppercase" to input.uppercase(), "Lowercase" to input.lowercase())
                    variants.forEach { (name, value) -> Card { Column(Modifier.padding(12.dp)) { Text(name); SelectionText(value); TextButton(onClick = { if (method in listOf("GET", "HEAD")) { url = Engine.withTestParam(url, value); body = "" } else body = value; tab = 1 }) { Text("Use in Repeater") } } } }
                    Text("Compare a baseline with each manual request. A different status alone does not prove a bypass.")
                }
                7 -> Decoder()
                8 -> {
                    Text("Response Diff", style = MaterialTheme.typography.titleLarge)
                    Text("Save a baseline in Repeater, then send another request.")
                    val delta = result.length - baseline.length
                    Text("Baseline ${baseline.length} chars · Current ${result.length} chars · Δ ${if (delta >= 0) "+" else ""}$delta")
                    Text(if (baseline == result) "IDENTICAL" else "CHANGED", color = if (baseline == result) Color(0xFF72E6A6) else Color(0xFFFFC857), fontWeight = FontWeight.Bold)
                    SelectionText("BASELINE\n$baseline\n\nCURRENT\n$result")
                }
                9 -> IntelligenceScreen(exchanges.filter { it.project == currentProject })
                else -> {
                    Text("Evidence Vault", style = MaterialTheme.typography.titleLarge)
                    Text("Local findings captured from Repeater. Nothing is uploaded automatically.")
                    if (findings.isEmpty()) Text("No findings saved yet.")
                    findings.forEachIndexed { i, item -> Card { Column(Modifier.padding(12.dp)) { Text("Finding #${i + 1}", fontWeight = FontWeight.Bold); SelectionText(item); TextButton(onClick = { store.removeFinding(i); findings = store.loadFindings() }) { Text("Remove") } } } }
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
        val operations = listOf("Base64 encode", "Base64 decode", "URL encode", "URL decode", "Hex encode", "Hex decode", "JSON pretty", "JWT decode")
        operations.forEach { op -> OutlinedButton(onClick = { output = try { when(op) {
            "Base64 encode" -> Base64.getEncoder().encodeToString(input.toByteArray())
            "Base64 decode" -> String(Base64.getDecoder().decode(input))
            "URL encode" -> URLEncoder.encode(input, "UTF-8")
            "URL decode" -> java.net.URLDecoder.decode(input, "UTF-8")
            "Hex encode" -> input.toByteArray().joinToString("") { "%02x".format(it) }
            "Hex decode" -> { require(input.length % 2 == 0 && input.matches(Regex("[0-9a-fA-F]*"))); String(input.chunked(2).map { it.toInt(16).toByte() }.toByteArray()) }
            "JSON pretty" -> prettyJsonOrOriginal(input)
            else -> decodeJwtForDisplay(input)
        } } catch (e: Exception) { "Invalid input: ${e.message}" } }) { Text(op) } }
        SelectionText(output)
    }
}
