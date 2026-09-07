package com.yair.hackerbar

import android.annotation.SuppressLint
import android.webkit.*
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.json.JSONObject

@SuppressLint("SetJavaScriptEnabled")
@Composable fun BrowserWorkspace(initialUrl: String, onUrl: (String)->Unit, toRepeater: (String)->Unit) {
    val context = LocalContext.current
    var address by remember { mutableStateOf(initialUrl) }
    var current by remember { mutableStateOf(initialUrl) }
    var source by remember { mutableStateOf("") }
    var panel by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var noRedirect by remember { mutableStateOf(false) }
    var jsEnabled by remember { mutableStateOf(true) }
    var desktop by remember { mutableStateOf(false) }
    var progress by remember { mutableIntStateOf(0) }
    val web = remember { WebView(context) }
    val history = remember { mutableStateListOf<String>() }
    val defaultAgent = remember { WebSettings.getDefaultUserAgent(context) }
    fun navigate(raw: String) {
        val target = if (raw.contains("://")) raw else "https://$raw"
        val uri = runCatching { Uri.parse(target) }.getOrNull()
        if (uri?.scheme !in listOf("https", "http") || uri.host.isNullOrBlank()) { panel = "Invalid HTTP(S) URL"; return }
        address = target; web.loadUrl(target)
    }
    fun inspect(script: String, name: String) {
        web.evaluateJavascript(script) { result ->
            panel = name
            source = runCatching { JSONObject("{\"v\":$result}").getString("v") }.getOrDefault(result)
        }
    }
    BackHandler(web.canGoBack() == true && panel.isEmpty()) { web.goBack() }
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            OutlinedTextField(address, { address = it }, Modifier.weight(1f), singleLine = true, label = { Text("URL") })
            Button(onClick = { navigate(address) }, modifier = Modifier.padding(top = 8.dp)) { Text("Go") }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            TextButton(onClick = { web.goBack() }, enabled = web.canGoBack() == true) { Text("◀") }
            TextButton(onClick = { web.goForward() }, enabled = web.canGoForward() == true) { Text("▶") }
            TextButton(onClick = { web.reload() }) { Text("↻") }
            TextButton(onClick = { web.stopLoading() }) { Text("Stop") }
            TextButton(onClick = { toRepeater(current) }) { Text("HackBar") }
            TextButton(onClick = { panel = if (panel == "Menu") "" else "Menu" }) { Text("Menu") }
        }
        if (loading) LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
        if (panel == "Menu") Column(Modifier.verticalScroll(rememberScrollState())) {
            Row { TextButton(onClick = { inspect("document.documentElement.outerHTML", "View Source") }) { Text("View Source") }; TextButton(onClick = { inspect("JSON.stringify(Array.from(document.querySelectorAll('a[href]')).map(a=>a.href))", "Extract Links") }) { Text("Extract Links") } }
            Row { TextButton(onClick = { panel = "Find in Page" }) { Text("Find in Page") }; TextButton(onClick = { panel = "History" }) { Text("History") }; TextButton(onClick = { panel = "Tamper Data" }) { Text("Tamper Data") } }
            Row { TextButton(onClick = { panel = "Custom Query" }) { Text("Custom Query") }; TextButton(onClick = { panel = "Admin Finder" }) { Text("Admin Finder") }; TextButton(onClick = { panel = "Web Tools" }) { Text("Web Tools") } }
            Row { TextButton(onClick = { web.clearCache(true); web.reload(); panel = "" }) { Text("Restart") }; TextButton(onClick = { panel = "About" }) { Text("About") } }
            Row { Checkbox(jsEnabled, { jsEnabled = it; web.settings?.javaScriptEnabled = it }); Text("JavaScript") }
            Row { Checkbox(noRedirect, { noRedirect = it }); Text("No Redirection") }
            Row { Checkbox(desktop, { desktop = it; web.settings?.userAgentString = if (it) "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" else defaultAgent; web.reload() }); Text("Desktop User Agent") }
        }
        if (panel.isNotEmpty() && panel != "Menu") {
            Text(panel, style = MaterialTheme.typography.titleMedium)
            when (panel) {
                "Find in Page" -> { var query by remember { mutableStateOf("") }; OutlinedTextField(query, { query = it; web.findAllAsync(it) }, label = { Text("Find") }); Row { TextButton(onClick = { web.findNext(false) }) { Text("Previous") }; TextButton(onClick = { web.findNext(true) }) { Text("Next") } } }
                "History" -> history.asReversed().take(30).forEach { h -> TextButton(onClick = { navigate(h); panel = "" }) { Text(h) } }
                "Tamper Data" -> Text("Request editing is available in Repeater. Browser-wide interception is not implemented yet.")
                "Custom Query", "Admin Finder", "Web Tools" -> Text("This original tool is not implemented yet. No scanner is running.")
                "About" -> Text("HackerBar Mobile · compatibility prototype. Original DH HackBar is developed by Team Darknet Haxor.")
                else -> SelectionText(source)
            }
            TextButton(onClick = { panel = ""; web.clearMatches() }) { Text("Close") }
        }
        AndroidView(factory = { ctx -> web.apply {
            settings.javaScriptEnabled = jsEnabled
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.setSupportMultipleWindows(false)
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            webChromeClient = object : WebChromeClient() { override fun onProgressChanged(view: WebView?, newProgress: Int) { progress = newProgress } }
            webViewClient = object : WebViewClient() {
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
