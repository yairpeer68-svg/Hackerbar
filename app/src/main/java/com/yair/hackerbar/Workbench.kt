package com.yair.hackerbar

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class HttpExchange(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val project: String = "Default",
    val method: String,
    val url: String,
    val requestHeaders: String = "",
    val requestBody: String = "",
    val status: Int = 0,
    val responseHeaders: String = "",
    val responseBody: String = "",
    val durationMs: Long = 0,
    val responseBytes: Long = 0
)

data class PassiveFinding(
    val title: String,
    val severity: String,
    val evidence: String,
    val recommendation: String
)
class WorkbenchStore(context: Context) {
    internal val prefs = context.getSharedPreferences("dh_hackbar_workbench_v2", Context.MODE_PRIVATE)

    fun loadExchanges(): List<HttpExchange> = runCatching {
        val arr = JSONArray(prefs.getString("exchanges", "[]") ?: "[]")
        List(arr.length()) { i -> arr.getJSONObject(i).toExchange() }
    }.getOrDefault(emptyList())

    fun saveExchange(exchange: HttpExchange) {
        val safe = exchange.copy(
            requestHeaders = redactSecrets(exchange.requestHeaders.take(16000)),
            requestBody = redactSensitiveBody(exchange.requestBody.take(64000)),
            responseHeaders = redactSecrets(exchange.responseHeaders.take(32000)),
            responseBody = redactSensitiveBody(exchange.responseBody.take(64000))
        )
        val all = (listOf(safe) + loadExchanges()).distinctBy { it.id }.take(50)
        val arr = JSONArray()
        all.forEach { arr.put(it.toJson()) }
        prefs.edit().putString("exchanges", arr.toString()).apply()
    }

    fun clearExchanges(project: String? = null) {
        if (project == null) { prefs.edit().remove("exchanges").apply(); return }
        val keep = loadExchanges().filterNot { it.project == project }
        val arr = JSONArray(); keep.forEach { arr.put(it.toJson()) }
        prefs.edit().putString("exchanges", arr.toString()).apply()
    }

    fun loadProjects(): List<String> = runCatching {
        val arr = JSONArray(prefs.getString("projects", "[\"Default\"]") ?: "[\"Default\"]")
        List(arr.length()) { i -> arr.getString(i) }
    }.getOrDefault(listOf("Default"))
    fun addProject(name: String) {
        val clean = name.trim().take(40)
        if (clean.isBlank()) return
        val projects = (loadProjects() + clean).distinct().take(20)
        val arr = JSONArray(); projects.forEach { arr.put(it) }
        prefs.edit().putString("projects", arr.toString()).apply()
    }

    private fun HttpExchange.toJson() = JSONObject().apply {
        put("id", id); put("timestamp", timestamp); put("project", project)
        put("method", method); put("url", url); put("requestHeaders", requestHeaders)
        put("requestBody", requestBody); put("status", status)
        put("responseHeaders", responseHeaders); put("responseBody", responseBody)
        put("durationMs", durationMs); put("responseBytes", responseBytes)
    }

    private fun JSONObject.toExchange() = HttpExchange(
        id = optString("id"), timestamp = optLong("timestamp"), project = optString("project", "Default"),
        method = optString("method"), url = optString("url"), requestHeaders = optString("requestHeaders"),
        requestBody = optString("requestBody"), status = optInt("status"), responseHeaders = optString("responseHeaders"),
        responseBody = optString("responseBody"), durationMs = optLong("durationMs"), responseBytes = optLong("responseBytes")
    )
}
object PassiveAnalyzer {
    fun analyze(exchange: HttpExchange): List<PassiveFinding> {
        val h = exchange.responseHeaders.lowercase()
        val findings = mutableListOf<PassiveFinding>()
        fun missing(header: String, title: String, severity: String, recommendation: String) {
            if (!h.contains("${header.lowercase()}:") ) findings += PassiveFinding(title, severity, "Header not present", recommendation)
        }
        if (exchange.url.startsWith("https://")) {
            missing("Strict-Transport-Security", "HSTS missing", "Medium", "Consider enabling HSTS after validating HTTPS coverage.")
        }
        missing("Content-Security-Policy", "CSP missing", "Info", "Consider a restrictive Content-Security-Policy appropriate for the application.")
        missing("X-Content-Type-Options", "MIME sniffing protection missing", "Low", "Set X-Content-Type-Options: nosniff where appropriate.")
        missing("Referrer-Policy", "Referrer-Policy missing", "Info", "Set an explicit Referrer-Policy matching privacy requirements.")
        if (h.contains("access-control-allow-origin: *") && h.contains("access-control-allow-credentials: true")) {
            findings += PassiveFinding("Risky CORS combination", "High", "Wildcard origin appears with credentials", "Review CORS policy and use explicit trusted origins.")
        }
        return findings + cookieFindings(exchange.responseHeaders)
    }
    private fun cookieFindings(headers: String): List<PassiveFinding> {
        val out = mutableListOf<PassiveFinding>()
        headers.lineSequence().filter { it.startsWith("Set-Cookie:", true) }.forEach { line ->
            val lower = line.lowercase()
            if (!lower.contains("; secure")) out += PassiveFinding("Cookie missing Secure", "Medium", line.take(180), "Mark session cookies Secure when served over HTTPS.")
            if (!lower.contains("; httponly")) out += PassiveFinding("Cookie missing HttpOnly", "Low", line.take(180), "Use HttpOnly for cookies that do not require JavaScript access.")
            if (!lower.contains("samesite=")) out += PassiveFinding("Cookie missing SameSite", "Info", line.take(180), "Set an explicit SameSite policy appropriate for the flow.")
        }
        return out
    }
}

fun redactSecrets(text: String): String = text.lineSequence().joinToString("\n") { line ->
    val name = line.substringBefore(':', "").trim().lowercase()
    if (name in setOf("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key")) {
        "${line.substringBefore(':')}: [REDACTED]"
    } else line
}

fun redactSensitiveBody(text: String): String {
    var out = text
    val jsonKeys = "password|passwd|token|access_token|refresh_token|api_key|apikey|secret|client_secret"
    out = Regex("""(?i)("(?:$jsonKeys)"\s*:\s*")[^"]*""").replace(out) { it.groupValues[1] + "[REDACTED]" }
    out = Regex("""(?i)((?:^|[&;])(?:password|passwd|token|access_token|refresh_token|api_key|apikey|secret|client_secret)=)[^&;\r\n]*""").replace(out) { it.groupValues[1] + "[REDACTED]" }
    return out
}

fun WorkbenchStore.loadFindings(): List<String> = runCatching {
    val arr = JSONArray(prefs.getString("findings", "[]") ?: "[]")
    List(arr.length()) { i -> arr.getString(i) }
}.getOrDefault(emptyList())

fun WorkbenchStore.saveFinding(value: String) {
    val all = (loadFindings() + value.take(12000)).takeLast(100)
    val arr = JSONArray(); all.forEach { arr.put(it) }
    prefs.edit().putString("findings", arr.toString()).apply()
}

fun WorkbenchStore.removeFinding(index: Int) {
    val all = loadFindings().filterIndexed { i, _ -> i != index }
    val arr = JSONArray(); all.forEach { arr.put(it) }
    prefs.edit().putString("findings", arr.toString()).apply()
}
