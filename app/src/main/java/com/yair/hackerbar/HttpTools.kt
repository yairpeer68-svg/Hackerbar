package com.yair.hackerbar

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.util.Base64

fun requestAsCurl(method: String, url: String, headers: String, body: String): String {
    val parts = mutableListOf("curl", "-i", "-X", shellQuote(method.uppercase()), shellQuote(Engine.normalizeUrl(url)))
    headers.lineSequence().map { it.trim() }.filter { it.isNotBlank() }.forEach {
        parts += listOf("-H", shellQuote(it))
    }
    if (method.uppercase() !in setOf("GET", "HEAD") && body.isNotEmpty()) parts += listOf("--data-raw", shellQuote(body))
    return parts.joinToString(" ")
}

fun requestAsRawHttp(method: String, url: String, headers: String, body: String): String {
    val uri = URI(Engine.normalizeUrl(url))
    val path = (uri.rawPath?.ifBlank { "/" } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
    val host = uri.host ?: ""
    val lines = mutableListOf("${method.uppercase()} $path HTTP/1.1", "Host: $host")
    lines += headers.lineSequence().map { it.trim() }.filter { it.isNotBlank() && !it.startsWith("Host:", true) }
    return (lines + listOf("", body)).joinToString("\r\n")
}

private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
fun prettyJsonOrOriginal(value: String): String = runCatching {
    val t = value.trim()
    when {
        t.startsWith("{") -> JSONObject(t).toString(2)
        t.startsWith("[") -> JSONArray(t).toString(2)
        else -> value
    }
}.getOrDefault(value)

fun decodeJwtForDisplay(token: String): String {
    val parts = token.trim().split('.')
    if (parts.size < 2) return "JWT must contain at least header.payload"
    fun decodePart(part: String): String {
        val padded = part + "=".repeat((4 - part.length % 4) % 4)
        val raw = String(Base64.getUrlDecoder().decode(padded), Charsets.UTF_8)
        return prettyJsonOrOriginal(raw)
    }
    return runCatching { "HEADER\n${decodePart(parts[0])}\n\nPAYLOAD\n${decodePart(parts[1])}\n\nSignature is not verified." }
        .getOrElse { "Invalid JWT: ${it.message ?: it.javaClass.simpleName}" }
}

fun endpointMap(exchanges: List<HttpExchange>): String {
    if (exchanges.isEmpty()) return "No requests in this project yet."
    return exchanges.groupingBy {
        val u = runCatching { URI(it.url) }.getOrNull()
        "${it.method.uppercase()} ${u?.host.orEmpty()}${u?.path?.ifBlank { "/" } ?: "/"}"
    }.eachCount().entries.sortedByDescending { it.value }.joinToString("\n") { "${it.value}×  ${it.key}" }
}
fun parameterInventory(exchanges: List<HttpExchange>): String {
    val counts = linkedMapOf<String, Int>()
    fun add(name: String) {
        val clean = name.trim()
        if (clean.isNotBlank()) counts[clean] = (counts[clean] ?: 0) + 1
    }
    exchanges.forEach { ex ->
        runCatching { URI(ex.url).rawQuery }.getOrNull()?.split('&')?.forEach { pair ->
            add(URLDecoder.decode(pair.substringBefore('='), "UTF-8"))
        }
        val body = ex.requestBody.trim()
        if (body.startsWith("{")) runCatching {
            val obj = JSONObject(body); obj.keys().forEachRemaining(::add)
        }
        if (body.contains('=') && !body.startsWith("{")) body.split('&').forEach { add(URLDecoder.decode(it.substringBefore('='), "UTF-8")) }
        ex.requestHeaders.lineSequence().forEach { line ->
            val name = line.substringBefore(':', "").trim()
            if (name.isNotBlank()) add("header:$name")
        }
    }
    if (counts.isEmpty()) return "No parameters discovered yet."
    return counts.entries.sortedByDescending { it.value }.joinToString("\n") { "${it.value}×  ${it.key}" }
}
