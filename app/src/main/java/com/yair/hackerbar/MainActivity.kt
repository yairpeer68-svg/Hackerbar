package com.yair.hackerbar
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
class MainActivity: ComponentActivity(){ override fun onCreate(savedInstanceState: Bundle?){ super.onCreate(savedInstanceState); setContent { MaterialTheme(colorScheme=darkColorScheme()){ Surface(Modifier.fillMaxSize()){ Home() } } } } }
@Composable fun Home(){ var tab by remember{ mutableIntStateOf(0) }; val tabs=listOf("Repeater","Decoder","Diff","Findings"); Column(Modifier.fillMaxSize()){ Text("HackerBar Mobile", style=MaterialTheme.typography.headlineSmall, modifier=Modifier.padding(16.dp)); TabRow(selectedTabIndex=tab){ tabs.forEachIndexed{i,t->Tab(selected=tab==i,onClick={tab=i},text={Text(t)})} }; Box(Modifier.padding(16.dp)){ when(tab){0->Repeater();1->Decoder();2->Text("Response diff module");else->Text("Evidence vault")}} } }
@Composable fun Repeater(){ var url by remember{mutableStateOf("https://example.com/")}; var body by remember{mutableStateOf("")}; Column(verticalArrangement=Arrangement.spacedBy(10.dp)){ Text("Authorized HTTP Repeater", style=MaterialTheme.typography.titleLarge); OutlinedTextField(url,{url=it},label={Text("URL")},modifier=Modifier.fillMaxWidth()); OutlinedTextField(body,{body=it},label={Text("Body")},modifier=Modifier.fillMaxWidth()); Button(onClick={}){Text("Send")}; Text("Scope Guard will be required before active requests are enabled.") } }
@Composable fun Decoder(){ var input by remember{mutableStateOf("")}; var output by remember{mutableStateOf("")}; Column(verticalArrangement=Arrangement.spacedBy(10.dp)){ OutlinedTextField(input,{input=it},label={Text("Input")},modifier=Modifier.fillMaxWidth()); Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){ Button(onClick={output=android.util.Base64.encodeToString(input.toByteArray(),android.util.Base64.NO_WRAP)}){Text("Base64")}; Button(onClick={output=java.net.URLEncoder.encode(input,"UTF-8")}){Text("URL Encode")} }; Text(output) } }
