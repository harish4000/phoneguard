package com.harish.phoneguard

import android.Manifest
import android.app.Activity
import android.app.role.RoleManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import rikka.shizuku.Shizuku
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Selected tab and text shared into the app from another app. */
private val tabState = mutableIntStateOf(0)
private val sharedText = mutableStateOf("")
private const val TAB_SCAMS = 2

class MainActivity : ComponentActivity() {
    private val onGrant = Shizuku.OnRequestPermissionResultListener { _, result ->
        if (result == PackageManager.PERMISSION_GRANTED) Thread {
            Shell.bootstrap(this)
            Store.log("Shizuku access granted")
        }.start()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Store.init(this)
        Shizuku.addRequestPermissionResultListener(onGrant)
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        MonitorService.start(this)
        takeShared(intent)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) { App() }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeShared(intent)
    }

    private fun takeShared(i: Intent?) {
        val t = when (i?.action) {
            Intent.ACTION_SEND -> i.getStringExtra(Intent.EXTRA_TEXT)
            Intent.ACTION_PROCESS_TEXT -> i.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }
        if (!t.isNullOrBlank()) {
            sharedText.value = t
            tabState.intValue = TAB_SCAMS
        }
    }

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(onGrant)
        super.onDestroy()
    }
}

private fun appInfo(c: android.content.Context, pkg: String) {
    try {
        c.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (e: Exception) { }
}

private fun gb(b: Long): String = "%.1f GB".format(b / 1e9)

private fun ago(t: Long): String =
    if (t == 0L) "never" else SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(t))

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun Small(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun Toggle(label: String, key: String, default: Boolean) {
    var v by remember { mutableStateOf(Store.bool(key, default)) }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Switch(checked = v, onCheckedChange = { v = it; Store.putBool(key, it) })
        Text(label, Modifier.weight(1f))
    }
}

@Composable
private fun App() {
    var tab by tabState
    val tabs = listOf("Home", "Protect", "Scams", "Clean", "Apps")
    Scaffold(bottomBar = {
        NavigationBar {
            tabs.forEachIndexed { i, t ->
                NavigationBarItem(selected = tab == i, onClick = { tab = i }, icon = { Text(t.take(1)) }, label = { Text(t) })
            }
        }
    }) { pad ->
        Column(
            Modifier.padding(pad).imePadding().padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            when (tab) {
                0 -> Home()
                1 -> Protect()
                2 -> Scams()
                3 -> Clean()
                else -> Apps()
            }
        }
    }
}

@Composable
private fun Home() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(3000); tick++ } }
    val alive = remember(tick) { Shell.alive() }
    val ready = remember(tick) { Ctl.can(c) }
    val control = remember(tick) { Ctl.label(c) }
    val b = remember(tick) { Device.battery(c) }
    val th = remember(tick) { Device.thermal(c) }
    val st = remember(tick) { Device.storage() }
    val cur = remember(tick) { Profiles.current() }
    val learned by produceState<List<Smart.Learned>>(emptyList(), tick / 10) { value = withContext(Dispatchers.IO) { Smart.learned(c) } }
    val log = remember(tick) { Store.str("log").lines().take(40).joinToString("\n") }
    val score by produceState<Score.Result?>(null, tick / 10) { value = withContext(Dispatchers.IO) { Score.compute(c) } }

    val stalled = remember { System.currentTimeMillis() - Store.long("beat") > 5 * 60_000 && Store.long("beat") > 0 }
    if (stalled) Section("Protection was paused") {
        Text("Android stopped PhoneGuard in the background. It is running again now.")
        Small("To stop this happening: Protect tab, Security check, allow PhoneGuard to run in the background.")
    }
    if (!ready) Section("Control is off") {
        Text(
            if (alive) "Shizuku is running. Grant access once and this phone keeps performance control for good, even when Shizuku is not running."
            else "Protection is working. Performance control needs a one-time setup: two minutes on a cable with the family PC. Ask whoever gave you this app."
        )
        if (alive) Button(onClick = { Shell.request() }) { Text("Grant access") }
    }
    score?.let { r ->
        Section("Protection score: ${r.score} of 100") {
            if (r.todo.isEmpty()) Small("Everything is in place.")
            r.todo.forEach { Small("- $it") }
        }
    }
    Section("Now") {
        Text("Battery ${b.pct}%${if (b.charging) " (charging)" else ""}, ${"%.1f".format(b.tempC)} C")
        Text("Thermal state: ${Device.thermalLabel(th)}")
        Text("Storage free: ${gb(st.first)} of ${gb(st.second)} (${st.first * 100 / st.second}%)")
        Text("Running for ${"%.1f".format(Device.uptimeDays())} days since restart")
        Text("Performance control: $control")
    }
    Section("Profile: ${cur.label}") {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Profile.entries.filter { it != Profile.COOLDOWN }.forEach { p ->
                FilterChip(selected = cur == p, enabled = ready, label = { Text(p.label) }, onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            Store.put("base", p.name)
                            Profiles.apply(c, p, "manual")
                        }
                        tick++
                    }
                })
            }
        }
        Small(cur.desc)
        Toggle("Smart mode: adapt settings to what you are doing", "auto", true)
        Small("Switches profile for games and video, holds apps that heat this phone at 60 Hz, saves battery under 20%, and frees memory and storage before they cause lag.")
        if (learned.isNotEmpty()) {
            Small("Learned so far (share of time the phone ran warm with each app on screen):")
            learned.forEach { Small("${it.hotShare}%   ${it.label}") }
        }
        OutlinedButton(enabled = ready, onClick = {
            scope.launch { withContext(Dispatchers.IO) { Profiles.restore(c) }; tick++ }
        }) { Text("Restore original settings") }
    }
    Section("Action log") { Small(log.ifBlank { "Nothing yet." }) }
}

@Composable
private fun Protect() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    var hits by remember { mutableStateOf<List<Scanner.Hit>?>(null) }
    var fileHits by remember { mutableStateOf(FileScan.lastHits()) }
    var procHits by remember { mutableStateOf<List<ProcScan.Hit>?>(null) }
    var procRan by remember { mutableStateOf(false) }
    var armed by remember { mutableStateOf("") }
    var aiApp by remember { mutableStateOf(mapOf<String, String>()) }
    var vt by remember { mutableStateOf(Store.str("vtKey")) }
    val filesOk = remember(refresh) { FileScan.allowed() }
    var upd by remember { mutableStateOf("") }
    val ready = remember(refresh) { Ctl.can(c) }
    val dns = remember(refresh) { Web.dnsName(c) }
    val findings by produceState<List<Security.Finding>?>(null, refresh) { value = withContext(Dispatchers.IO) { Security.scan(c) } }

    Section("Antivirus scan") {
        Text("Definitions: ${Defs.version()}")
        Small("${Scam.aiRuleCount(c)} scam patterns written by the home AI are active")
        Small(if (Cloud.on()) "Cloud check: on, ${Cloud.usedToday()} lookups today. ${Cloud.status()}" else "Cloud check: off (add a VirusTotal key below)")
        Text("Last scan: ${ago(Store.long("lastScan"))}")
        Small("${Store.long("lastScanN")} apps, ${Store.long("lastFileN")} files, ${Store.long("lastProcN")} running processes checked")
        if (!filesOk) {
            Button(onClick = {
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { FileScan.grant(c) }
                    if (!ok) try {
                        c.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + c.packageName)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    } catch (e: Exception) { }
                    delay(800)
                    refresh++
                }
            }) { Text("Allow file scanning") }
            Small("Needed to scan every file in storage, and to check downloads the moment they arrive.")
        }
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                status = "Updating definitions..."
                val d = withContext(Dispatchers.IO) { Defs.update(c, force = true) }
                status = "Scanning apps, including preinstalled ones..."
                hits = withContext(Dispatchers.IO) { Scanner.scan(c) }
                status = "Scanning files..."
                fileHits = withContext(Dispatchers.IO) { FileScan.scan(c) }
                status = "Scanning running processes..."
                procHits = withContext(Dispatchers.IO) { ProcScan.scan(c) }
                procRan = true
                status = d
                busy = false
                refresh++
            }
        }) { Text(if (busy) "Scanning..." else "Update and scan everything") }
        if (status.isNotEmpty()) Small(status)
        hits?.let { h ->
            if (h.isEmpty() && fileHits.isEmpty() && procHits.isNullOrEmpty()) Text("No threats found.")
            h.forEach { x ->
                Text((if (x.level == 2) "MALWARE APP: " else "REVIEW APP: ") + x.label,
                    color = if (x.level == 2) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                Small(x.why)
                if (x.pkg.isNotEmpty()) TextButton(onClick = {
                    try {
                        c.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + x.pkg)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    } catch (e: Exception) { }
                }) { Text("Open app info to uninstall") }
                if (x.pkg.isNotEmpty() && Scam.aiOn()) {
                    TextButton(onClick = {
                        aiApp = aiApp + (x.pkg to "Asking the home AI...")
                        scope.launch {
                            val v = withContext(Dispatchers.IO) { Scam.aiApp(c, x.pkg) }
                            aiApp = aiApp + (x.pkg to v)
                        }
                    }) { Text("Ask the home AI about this app") }
                    aiApp[x.pkg]?.let { Small(it) }
                }
            }
        }
        fileHits.forEach { x ->
            Text((if (x.level == 2) "MALWARE FILE: " else "REVIEW FILE: ") + x.path.substringAfterLast('/'),
                color = if (x.level == 2) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            Small(x.why)
            Small(x.path.removePrefix("/storage/emulated/0/"))
            TextButton(onClick = {
                if (armed != x.path) armed = x.path
                else scope.launch {
                    val gone = withContext(Dispatchers.IO) { try { java.io.File(x.path).delete() } catch (e: Exception) { false } }
                    if (gone) {
                        Store.log("Deleted flagged file ${x.path.substringAfterLast('/')}")
                        FileScan.forget(x.path)
                        fileHits = fileHits.filter { it.path != x.path }
                    } else status = "Could not delete it. Remove it in the Files app."
                    armed = ""
                }
            }) { Text(if (armed == x.path) "Tap again to delete permanently" else "Delete file") }
        }
        procHits?.forEach { x ->
            Text((if (x.level == 2) "MALWARE RUNNING: " else "REVIEW PROCESS: ") + x.name,
                color = if (x.level == 2) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            Small(x.why)
        }
        if (procRan && procHits == null) Small("Process scan skipped: it needs the one-time setup or Shizuku.")
        Small("Checks every installed and preinstalled app, every file in shared storage that can carry code, and every running process. Apps and files are also checked as they arrive. Android does not let any app read other apps' private data or memory, so nothing on Android can scan those.")
    }
    Section("Cloud check (VirusTotal)") {
        OutlinedTextField(value = vt, onValueChange = { vt = it; Store.put("vtKey", it.trim()) }, modifier = Modifier.fillMaxWidth(),
            singleLine = true, visualTransformation = PasswordVisualTransformation(), label = { Text("VirusTotal API key") })
        Toggle("Check apps and installers against VirusTotal", "vtOn", true)
        OutlinedButton(onClick = {
            try {
                GmsBarcodeScanning.getClient(c).startScan().addOnSuccessListener { code ->
                    val u = try { Uri.parse(code.rawValue.orEmpty()) } catch (e: Exception) { null }
                    if (u != null && u.scheme == "phoneguard" && u.host == "setup") {
                        u.getQueryParameter("vt")?.let { vt = it; Store.put("vtKey", it.trim()) }
                        u.getQueryParameter("ai")?.let { Store.put("glmUrl", it.trim()) }
                        if (u.getQueryParameter("early") == "1") Store.putBool("earlyUpdates", true)
                        status = "Setup code applied."
                        refresh++
                    } else status = "That is not a PhoneGuard setup code."
                }
            } catch (e: Exception) { status = "QR scanner is not available on this phone." }
        }) { Text("Scan a setup code") }
        Small("VirusTotal combines about seventy antivirus engines and is updated continuously, so it knows malware that is hours old. Only a file's fingerprint is sent, never the file. Lookups run in the background, four a minute, and results are remembered.")
    }
    Section("Web protection") {
        val on = dns != null && dns != "automatic"
        Text(if (on) "On: $dns" else "Off")
        if (!on) {
            Button(enabled = ready, onClick = {
                scope.launch { withContext(Dispatchers.IO) { Web.enable(c) }; delay(1500); refresh++ }
            }) { Text("Turn on") }
            if (!ready) Small("By hand: Settings, Network and internet, Private DNS, then enter ${Web.DNS}")
        }
        Small("Uses a filtering DNS (Quad9) so known malicious and phishing sites fail to load, in every app and browser.")
        Toggle("Warn when joining Wi-Fi with no password", "wifiWarn", true)
    }
    Section("Security check") {
        val f = findings
        if (f == null) Small("Checking...")
        f?.forEach { x ->
            val tag = when (x.level) { 2 -> "RISK"; 1 -> "REVIEW"; else -> "OK" }
            Text("$tag: ${x.title}", color = if (x.level == 2) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            Small(x.detail)
            if (x.action != null && x.level > 0) TextButton(onClick = {
                try { c.startActivity(Intent(x.action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (e: Exception) { }
            }) { Text("Open setting") }
        }
        OutlinedButton(onClick = { refresh++ }) { Text("Check again") }
    }
    Section("App updates") {
        Text("Installed: v${BuildConfig.VERSION_NAME}")
        Button(onClick = {
            upd = "Checking..."
            scope.launch {
                upd = withContext(Dispatchers.IO) { Updater.check(c) }
                if (Updater.pending(c)) {
                    upd = "Installing version ${Store.str("updName")}. The app will close and reopen."
                    withContext(Dispatchers.IO) { Updater.install(c, manual = true) }
                }
            }
        }) { Text("Check for update") }
        if (upd.isNotEmpty()) Small(upd)
        Toggle("Install updates automatically", "autoUpdate", true)
        Toggle("Get updates early (this is the test phone)", "earlyUpdates", false)
        Small("Checked daily and installed while the screen is off. An update installs only if its checksum matches and it is signed with the same key as this app. Phones wait two days after a release unless they are the test phone, so a faulty update can be replaced before it spreads.")
    }
}

@Composable
private fun Scams() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var text by sharedText
    var verdict by remember { mutableStateOf<Scam.Verdict?>(null) }
    var ai by remember { mutableStateOf("") }
    var glm by remember { mutableStateOf(Store.str("glmUrl")) }
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(2000); tick++ } }
    val role = remember(tick) { CallRules.hasRole(c) }
    val contacts = remember(tick) { CallRules.canReadContacts(c) }
    var myNumber by remember { mutableStateOf(Store.str("myNumber")) }
    var blockList by remember { mutableStateOf(Store.str("blockList")) }
    var email by remember { mutableStateOf("") }
    var pw by remember { mutableStateOf("") }
    var breach by remember { mutableStateOf("") }
    var watch by remember { mutableStateOf(Store.str("watchEmails")) }
    val auto = remember(tick) { ScamWatch.enabled(c) }

    Section("Scam checker") {
        OutlinedTextField(value = text, onValueChange = { text = it }, modifier = Modifier.fillMaxWidth(), minLines = 3,
            label = { Text("Paste a message or link") })
        Button(enabled = text.isNotBlank(), onClick = {
            val t = text
            ai = ""
            scope.launch {
                verdict = withContext(Dispatchers.IO) { Scam.rules(c, t) }
                if (Store.str("glmUrl").isNotBlank()) {
                    ai = "Asking the home AI..."
                    ai = withContext(Dispatchers.IO) { Scam.ai(t) }
                }
            }
        }) { Text("Check") }
        OutlinedButton(onClick = {
            try {
                GmsBarcodeScanning.getClient(c).startScan()
                    .addOnSuccessListener { code -> code.rawValue?.let { text = it; verdict = null; ai = "" } }
                    .addOnFailureListener { ai = "QR scanner is not available on this phone yet. Try again in a minute." }
            } catch (e: Exception) { ai = "QR scanner is not available on this phone." }
        }) { Text("Scan a QR code") }
        verdict?.let { v ->
            Text("${v.label} (risk ${v.score} of 100)",
                color = if (v.score >= 60) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            v.reasons.forEach { Small("- $it") }
            if (v.score < 30) Small("No red flags is not proof it is safe. If it asks for money, codes or a login, verify through a number you already know.")
        }
        if (ai.isNotEmpty()) { Text("Second opinion"); Small(ai) }
        Small("Tip: in any app, select text or tap Share, then pick Check for scam. A scanned QR code lands in the box above, so you can check it before opening it.")
    }
    Section("Automatic scam alerts") {
        Text(if (auto) "On" else "Off")
        if (!auto) {
            Button(onClick = {
                scope.launch {
                    val ok = withContext(Dispatchers.IO) { ScamWatch.enable(c) }
                    if (!ok) try {
                        c.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    } catch (e: Exception) { }
                }
            }) { Text("Turn on") }
            Small("If Android greys out the switch, open this app's App info, tap the three dots, and choose Allow restricted settings first.")
        }
        Toggle("Check incoming messages and warn me", "scamAuto", true)
        Small("Checks message notifications from texts and chat apps with the rules above, on the phone only. Nothing is stored or uploaded. You get an alert only when a message scores as a likely scam.")
    }
    Section("Voice and video fakes") {
        Small("AI can clone a voice from a few seconds of audio. Agree a family code word, and ask for it before acting on any urgent call about money, even when the voice is familiar. Then hang up and call back on the number you have saved.")
    }
    Section("Spam call blocking") {
        Text(if (role) "On" else "Off")
        if (!role) Button(onClick = {
            try {
                val i = c.getSystemService(RoleManager::class.java).createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
                (c as Activity).startActivityForResult(i, 5)
            } catch (e: Exception) { }
        }) { Text("Turn on call blocking") }
        if (role && !contacts) {
            Button(onClick = { (c as Activity).requestPermissions(arrayOf(Manifest.permission.READ_CONTACTS), 2) }) { Text("Allow contacts") }
            Small("Contacts stay on the phone. They are needed for the look-alike and unknown-caller rules, and so people you know are never blocked.")
        }
        Toggle("Block hidden numbers", "blkHidden", true)
        Toggle("Block callers whose ID fails carrier verification", "blkSpoof", true)
        Toggle("Block numbers on the shared spam list", "blkFeed", true)
        Toggle("Silence numbers that mimic your own", "blkNeighbour", true)
        Toggle("Silence everyone not in contacts", "silUnknown", false)
        OutlinedTextField(value = myNumber, onValueChange = { myNumber = it; Store.put("myNumber", it) }, modifier = Modifier.fillMaxWidth(),
            singleLine = true, label = { Text("Your mobile number") })
        OutlinedTextField(value = blockList, onValueChange = { blockList = it; Store.put("blockList", it) }, modifier = Modifier.fillMaxWidth(),
            minLines = 2, label = { Text("Your block list: numbers or prefixes, one per line") })
        Small("Blocked and silenced calls still appear in the call log, and each one is recorded in the action log on Home.")
    }
    Section("Breach check") {
        OutlinedTextField(value = email, onValueChange = { email = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
            label = { Text("Email address") })
        Button(enabled = email.contains('@'), onClick = {
            breach = "Checking..."
            scope.launch { breach = withContext(Dispatchers.IO) { Breach.email(email) } }
        }) { Text("Check email") }
        OutlinedTextField(value = pw, onValueChange = { pw = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
            visualTransformation = PasswordVisualTransformation(), label = { Text("Password to test") })
        Button(enabled = pw.isNotEmpty(), onClick = {
            breach = "Checking..."
            scope.launch { breach = withContext(Dispatchers.IO) { Breach.password(pw) } }
        }) { Text("Check password") }
        if (breach.isNotEmpty()) Small(breach)
        OutlinedTextField(value = watch, onValueChange = { watch = it; Store.put("watchEmails", it) }, modifier = Modifier.fillMaxWidth(),
            minLines = 2, label = { Text("Emails to monitor weekly, one per line") })
        OutlinedButton(enabled = watch.contains('@'), onClick = {
            breach = "Checking saved addresses..."
            scope.launch {
                withContext(Dispatchers.IO) { Breach.watch(c) }
                breach = "Saved. You will get a notification now for existing breaches, and later only for new ones."
            }
        }) { Text("Save and check now") }
        Small("The email goes to the XposedOrNot breach service. The password never leaves the phone: only the first five characters of its hash are sent.")
    }
    Section("Home AI for second opinions") {
        OutlinedTextField(value = glm, onValueChange = { glm = it; Store.put("glmUrl", it.trim()) }, modifier = Modifier.fillMaxWidth(),
            singleLine = true, label = { Text("Address, https://...ts.net") })
        Small("Optional. Sends the checked text to the family's own model over Tailscale, never to an outside AI. Leave empty to use on-phone rules only.")
        Toggle("Also ask the home AI about borderline incoming messages", "aiAuto", false)
        Small("Off by default. When on, an incoming message that looks suspicious but not certain is sent to the family PC for a verdict, so reworded scams are caught by meaning. Clear scams and ordinary messages never leave the phone.")
    }
}

@Composable
private fun Clean() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var msg by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var refresh by remember { mutableIntStateOf(0) }
    val st = remember(refresh) { Device.storage() }
    val files by produceState<List<Pair<Long, String>>?>(null, refresh) {
        value = withContext(Dispatchers.IO) { Actions.largeFiles() }
    }

    Section("Storage") {
        val pct = st.first * 100 / st.second
        Text("${gb(st.first)} free of ${gb(st.second)} ($pct%)")
        if (pct < 15) Text("Below 15% free the phone slows down sharply. Clear space.", color = MaterialTheme.colorScheme.error)
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                msg = withContext(Dispatchers.IO) { Actions.trimCaches(c) }
                busy = false
                refresh++
            }
        }) { Text(if (busy) "Cleaning..." else "Clear all app caches") }
        Small("Clears temporary files for every app, browsers included. Logins, tabs and saved data stay.")
        if (msg.isNotEmpty()) Text(msg)
        Toggle("Clean weekly while the screen is off", "autoclean", true)
    }
    Section("Largest files") {
        val f = files
        when {
            f == null -> Small("Allow file scanning on the Protect tab to list large files.")
            f.isEmpty() -> Small("No files over 50 MB.")
            else -> f.forEach { (size, path) -> Small("${size / 1_000_000} MB   ${path.removePrefix("/sdcard/").removePrefix("/storage/emulated/0/")}") }
        }
        Small("Listed only. Delete them yourself in the Files app.")
    }
}

@Composable
private fun Apps() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    val ready = remember(refresh) { Shell.granted() }
    val rogue by produceState<List<Rogue.Row>>(emptyList(), refresh) { value = withContext(Dispatchers.IO) { Rogue.flagged(c) } }
    val bloat by produceState<List<Bloat.Row>?>(emptyList(), refresh) { value = withContext(Dispatchers.IO) { Bloat.candidates(c) } }
    val off = remember(refresh) { Bloat.disabled().toList().sorted() }
    val act: (() -> Unit) -> Unit = { block -> scope.launch { withContext(Dispatchers.IO) { block() }; refresh++ } }

    Section("Background hogs") {
        if (rogue.isEmpty()) Small("None flagged. The monitor samples background CPU every 5 minutes and needs about half an hour of data.")
        rogue.forEach { r ->
            Text(r.label)
            Small("Average ${"%.1f".format(r.avg)}% CPU while off screen, ${r.samples} samples")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (ready) {
                    TextButton(onClick = { act { Actions.forceStop(r.pkg) } }) { Text("Stop now") }
                    TextButton(onClick = { act { Actions.restrictBackground(r.pkg, true) } }) { Text("Block background") }
                    TextButton(onClick = { act { Actions.restrictBackground(r.pkg, false) } }) { Text("Unblock") }
                } else {
                    TextButton(onClick = { act { Actions.softStop(c, r.pkg) } }) { Text("End background work") }
                    TextButton(onClick = { appInfo(c, r.pkg) }) { Text("Open app settings") }
                }
            }
        }
        Small("Stopping or blocking an app can delay its notifications, so these stay manual.")
    }
    Section("Unused preinstalled apps") {
        val bl = bloat
        when {
            bl == null -> {
                Small("PhoneGuard needs usage access to know which apps you never open.")
                TextButton(onClick = {
                    try { c.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (e: Exception) { }
                }) { Text("Allow usage access") }
            }
            bl.isEmpty() -> Small("Nothing to suggest.")
            else -> {
                Small("Preinstalled apps you have not opened in 30 days, limited to ones the community debloat list rates safe to remove. Disabling is reversible below.")
                bl.forEach { r ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(r.label, Modifier.weight(1f))
                        if (ready) TextButton(onClick = { act { Bloat.disable(r.pkg) } }) { Text("Disable") }
                        else TextButton(onClick = { appInfo(c, r.pkg) }) { Text("Open to disable") }
                    }
                    if (r.note.isNotEmpty()) Small(r.note)
                }
            }
        }
    }
    if (off.isNotEmpty()) Section("Disabled by PhoneGuard") {
        off.forEach { pkg ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(pkg, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                TextButton(enabled = ready, onClick = { act { Bloat.enable(pkg) } }) { Text("Re-enable") }
            }
        }
    }
}
