package com.yair.hackerbar

import android.annotation.SuppressLint
import android.webkit.*
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import androidx.webkit.UserAgentMetadata
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import java.util.concurrent.atomic.AtomicReference

private const val PRIVACY_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

private fun applyPrivacyIdentity(web: WebView) {
    web.settings.userAgentString = PRIVACY_UA
    if (WebViewFeature.isFeatureSupported(WebViewFeature.USER_AGENT_METADATA)) {
        val chrome = UserAgentMetadata.BrandVersion.Builder()
            .setBrand("Google Chrome").setMajorVersion("151").setFullVersion("151.0.0.0").build()
        val chromium = UserAgentMetadata.BrandVersion.Builder()
            .setBrand("Chromium").setMajorVersion("151").setFullVersion("151.0.0.0").build()
        val metadata = UserAgentMetadata.Builder()
            .setBrandVersionList(listOf(chrome, chromium))
            .setFullVersion("151.0.0.0")
            .setPlatform("Windows")
            .setPlatformVersion("10.0.0")
            .setArchitecture("x86")
            .setBitness(64)
            .setModel("Desktop")
            .setMobile(false)
            .setWow64(false)
            .build()
        WebSettingsCompat.setUserAgentMetadata(web.settings, metadata)
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable fun BrowserWorkspace(initialUrl: String, onUrl: (String)->Unit, toRepeater: (CapturedRequest)->Unit, toTool: (String, CapturedRequest)->Unit) {
    val context = LocalContext.current
    var address by remember { mutableStateOf(initialUrl) }
    var current by remember { mutableStateOf(initialUrl) }
    var source by remember { mutableStateOf("") }
    var panel by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var noRedirect by remember { mutableStateOf(false) }
    var jsEnabled by remember { mutableStateOf(true) }
    var desktop by remember { mutableStateOf(true) }
    var progress by remember { mutableIntStateOf(0) }
    val web = remember { WebView(context) }
    val history = remember { mutableStateListOf<String>() }
    val capturedMainRequest = remember { AtomicReference<CapturedRequest?>(null) }
    val defaultAgent = remember { PRIVACY_UA }
    fun navigate(raw: String) {
        val target = if (raw.contains("://")) raw else "https://$raw"
        val uri = runCatching { Uri.parse(target) }.getOrNull()
        if (uri?.scheme !in listOf("https", "http") || uri?.host.isNullOrBlank()) { panel = "Invalid HTTP(S) URL"; return }
        address = target; web.loadUrl(target)
    }
    fun inspect(script: String, name: String) {
        web.evaluateJavascript(script) { result ->
            panel = name
            source = runCatching { JSONObject("{\"v\":$result}").getString("v") }.getOrDefault(result)
        }
    }
    fun currentRequest(): CapturedRequest {
        val page = current.ifBlank { address }
        val fallbackHeaders = linkedMapOf<String, String>()
        web.settings.userAgentString?.takeIf { it.isNotBlank() }?.let { fallbackHeaders["User-Agent"] = it }
        CookieManager.getInstance().getCookie(page)?.takeIf { it.isNotBlank() }?.let { fallbackHeaders["Cookie"] = it }
        return capturedMainRequest.get()?.copy(url = page) ?: CapturedRequest(page, "GET", fallbackHeaders)
    }
    BackHandler(web.canGoBack() == true && panel.isEmpty()) { web.goBack() }
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            OutlinedTextField(address, { address = it }, Modifier.weight(1f), singleLine = true, label = { Text("URL") })
            Button(onClick = { navigate(address) }, modifier = Modifier.padding(top = 8.dp)) { Text("Go") }
        }
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            OutlinedButton(onClick = { web.goBack() }, enabled = web.canGoBack() == true, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp)) { Text("<") }
            OutlinedButton(onClick = { web.goForward() }, enabled = web.canGoForward() == true, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp)) { Text(">") }
            OutlinedButton(onClick = { address = "" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Clear") }
            Button(onClick = { navigate(address) }, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp)) { Text("Execute") }
            OutlinedButton(onClick = { web.reload() }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Reload") }
            OutlinedButton(onClick = { web.stopLoading() }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Stop") }
            OutlinedButton(onClick = { toRepeater(currentRequest()) }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Repeater") }
        }
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            listOf("SQL" to "SQLi", "XSS" to "XSS", "LFI" to "LFI / Traversal", "SSTI" to "SSTI", "SSRF" to "SSRF", "Auth" to "Authorization", "WAF" to "WAF Lab").forEach { (label, target) ->
                OutlinedButton(onClick = { toTool(target, currentRequest()) }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text(label) }
            }
        }
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            OutlinedButton(onClick = { inspect("document.documentElement.outerHTML", "View Source") }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("View Source") }
            OutlinedButton(onClick = { inspect("JSON.stringify(Array.from(document.querySelectorAll('a[href]')).map(a=>a.href))", "Extract Links") }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Extract Links") }
            OutlinedButton(onClick = { panel = "Find in Page" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Find") }
            OutlinedButton(onClick = { panel = "History" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("History") }
            OutlinedButton(onClick = { panel = "Headers" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Headers") }
            OutlinedButton(onClick = { panel = "Cookies" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("Cookies") }
            OutlinedButton(onClick = { panel = "User Agent" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("User Agent") }
            OutlinedButton(onClick = { panel = if (panel == "Menu") "" else "Menu" }, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)) { Text("More") }
        }
        if (loading) LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
        if (panel == "Menu") Column(Modifier.verticalScroll(rememberScrollState())) {
            Row { TextButton(onClick = { inspect("document.documentElement.outerHTML", "View Source") }) { Text("View Source") }; TextButton(onClick = { inspect("JSON.stringify(Array.from(document.querySelectorAll('a[href]')).map(a=>a.href))", "Extract Links") }) { Text("Extract Links") } }
            Row { TextButton(onClick = { panel = "Find in Page" }) { Text("Find in Page") }; TextButton(onClick = { panel = "History" }) { Text("History") }; TextButton(onClick = { panel = "Tamper Data" }) { Text("Tamper Data") } }
            Row { TextButton(onClick = { panel = "Custom Query" }) { Text("Custom Query") }; TextButton(onClick = { panel = "Admin Finder" }) { Text("Admin Finder") }; TextButton(onClick = { panel = "Web Tools" }) { Text("Web Tools") } }
            Row { TextButton(onClick = { web.clearCache(true); web.reload(); panel = "" }) { Text("Restart") }; TextButton(onClick = { panel = "About" }) { Text("About") } }
            Row { Checkbox(jsEnabled, { jsEnabled = it; web.settings?.javaScriptEnabled = it }); Text("JavaScript") }
            Row { Checkbox(noRedirect, { noRedirect = it }); Text("No Redirection") }
            Row { Checkbox(desktop, { desktop = it; if (it) applyPrivacyIdentity(web) else web.settings.userAgentString = WebSettings.getDefaultUserAgent(context); web.reload() }); Text("Privacy Desktop Identity") }
        }
        if (panel.isNotEmpty() && panel != "Menu") {
            Text(panel, style = MaterialTheme.typography.titleMedium)
            when (panel) {
                "Find in Page" -> { var query by remember { mutableStateOf("") }; OutlinedTextField(query, { query = it; web.findAllAsync(it) }, label = { Text("Find") }); Row { TextButton(onClick = { web.findNext(false) }) { Text("Previous") }; TextButton(onClick = { web.findNext(true) }) { Text("Next") } } }
                "History" -> history.asReversed().take(30).forEach { h -> TextButton(onClick = { navigate(h); panel = "" }) { Text(h) } }
                "Tamper Data" -> { Text("Edit the current request in Repeater."); Button(onClick = { toRepeater(currentRequest()) }) { Text("Open Repeater") } }
                "Headers" -> SelectionText("Browser request-header editing is intentionally separated from WebView. Use Repeater for exact request control. Current page: $current")
                "Cookies" -> SelectionText(CookieManager.getInstance().getCookie(current) ?: "No cookies for current page")
                "User Agent" -> SelectionText(web.settings.userAgentString ?: defaultAgent)
                "SQLi" -> SelectionText("Manual SQL checks: quote handling ( ' ), boolean comparison (1 AND 1=1), baseline/error comparison. Use Repeater on an authorized parameter.")
                "XSS" -> SelectionText("Manual XSS checks: HB_CANARY_2026, quoted canary, reflected-context inspection. Confirm encoding/context before any active proof.")
                "LFI / Traversal" -> SelectionText("Manual path-normalization checks: ../HB_CANARY_2026 and encoded variants. Do not request sensitive local files.")
                "SSTI" -> SelectionText("Manual template check: {{7*7}}. Compare the rendered response against a baseline on an authorized target.")
                "SSRF" -> SelectionText("Use only a callback endpoint you control, e.g. https://example.com/HB_CANARY_2026. Do not probe internal metadata/services.")
                "Authorization" -> SelectionText("Authorization workspace: compare the same authorized request across your own test roles/sessions. Use Repeater for exact headers/cookies.")
                "WAF Lab" -> SelectionText("WAF experiments are available in the WAF Lab tab: original, URL encoded, double encoded and normalization variants.")
                "Custom Query" -> { Text("Open the current request in Repeater for custom method, headers, body and query-string editing."); Button(onClick = { toRepeater(currentRequest()) }) { Text("Open Repeater") } }
                "Admin Finder" -> Text("Automatic admin-path scanning is not enabled. Use authorized discovery lists manually and within scope.")
                "Web Tools" -> SelectionText("Quick tools: View Source · Extract Links · Find · History · Cookies · User Agent · Repeater · WAF Lab")
                "About" -> Text("DH HackerBar Mobile · modern compatibility prototype inspired by the original DH HackBar UI.")
                else -> SelectionText(source)
            }
            TextButton(onClick = { panel = ""; web.clearMatches() }) { Text("Close") }
        }
        AndroidView(factory = { ctx -> web.apply {
            settings.javaScriptEnabled = jsEnabled
            settings.domStorageEnabled = true
            settings.setGeolocationEnabled(false)
            settings.saveFormData = false
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.setSupportMultipleWindows(false)
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
            applyPrivacyIdentity(this)
            webChromeClient = object : WebChromeClient() {
                override fun onProgressChanged(view: WebView?, newProgress: Int) { progress = newProgress }
                override fun onPermissionRequest(request: PermissionRequest?) { request?.deny() }
                override fun onGeolocationPermissionsShowPrompt(origin: String?, callback: GeolocationPermissions.Callback?) { callback?.invoke(origin, false, false) }
            }
            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? {
                    if (request.isForMainFrame) {
                        val h = linkedMapOf<String, String>()
                        h.putAll(request.requestHeaders)
                        val page = request.url.toString()
                        // shouldInterceptRequest runs on a Chromium worker thread. Never touch WebView here.
                        // request.requestHeaders already contains the main-frame headers exposed by WebView.
                        capturedMainRequest.set(CapturedRequest(page, request.method ?: "GET", h))
                    }
                    return super.shouldInterceptRequest(view, request)
                }
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean {
                    val u = request.url
                    if (u.scheme !in listOf("http", "https")) return true
                    if (noRedirect && request.isRedirect) { panel = "Redirect blocked"; source = u.toString(); return true }
                    return false
                }
                override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) { loading = true; url?.let { current = it; address = it; onUrl(it) } }
                override fun onPageFinished(view: WebView?, url: String?) { loading = false; url?.let { if (history.lastOrNull() != it) history.add(it) } }
                override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) { if (request?.isForMainFrame == true) { panel = "Page error"; source = error?.description?.toString().orEmpty() } }
            }
            loadUrl(initialUrl); 
        } }, modifier = Modifier.fillMaxWidth().weight(1f))
    }
    DisposableEffect(web) { onDispose { web.stopLoading(); web.destroy() } }
}
