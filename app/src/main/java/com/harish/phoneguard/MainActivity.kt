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
    val ready = remember(tick) { Shell.granted() }
    val b = remember(tick) { Device.battery(c) }
    val th = remember(tick) { Device.thermal(c) }
    val st = remember(tick) { Device.storage() }
    val cur = remember(tick) { Profiles.current() }
    val learned by produceState<List<Smart.Learned>>(emptyList(), tick / 10) { value = withContext(Dispatchers.IO) { Smart.learned(c) } }
    val log = remember(tick) { Store.str("log").lines().take(40).joinToString("\n") }

    if (!ready) Section("Control is off") {
        Text(
            if (alive) "Shizuku is running. Grant access to enable profiles, cleanup and app control."
            else "Protection is working. Performance control needs Shizuku: open the Shizuku app and start it. This is needed again after every restart."
        )
        if (alive) Button(onClick = { Shell.request() }) { Text("Grant access") }
    }
    Section("Now") {
        Text("Battery ${b.pct}%${if (b.charging) " (charging)" else ""}, ${"%.1f".format(b.tempC)} C")
        Text("Thermal state: ${Device.thermalLabel(th)}")
        Text("Storage free: ${gb(st.first)} of ${gb(st.second)} (${st.first * 100 / st.second}%)")
        Text("Running for ${"%.1f".format(Device.uptimeDays())} days since restart")
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
            scope.launch { withContext(Dispatchers.IO) { Profiles.restore() }; tick++ }
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
    var upd by remember { mutableStateOf("") }
    val ready = remember(refresh) { Shell.granted() }
    val dns = remember(refresh) { Web.dnsName(c) }
    val findings by produceState<List<Security.Finding>?>(null, refresh) { value = withContext(Dispatchers.IO) { Security.scan(c) } }

    Section("Malware scan") {
        Text("Definitions: ${Defs.version()}")
        Text("Last scan: ${ago(Store.long("lastScan"))}, ${Store.long("lastScanN")} apps checked")
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                status = withContext(Dispatchers.IO) { Defs.update(c, force = true) }
                hits = withContext(Dispatchers.IO) { Scanner.scan(c) + Scanner.downloads(c) }
                busy = false
                refresh++
            }
        }) { Text(if (busy) "Scanning..." else "Update and scan now") }
        if (status.isNotEmpty()) Small(status)
        hits?.let { h ->
            if (h.isEmpty()) Text("No threats found.")
            h.forEach { x ->
                Text((if (x.level == 2) "MALWARE: " else "REVIEW: ") + x.label,
                    color = if (x.level == 2) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                Small(x.why)
                if (x.pkg.isNotEmpty()) TextButton(onClick = {
                    try {
                        c.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + x.pkg)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    } catch (e: Exception) { }
                }) { Text("Open app info to uninstall") }
            }
        }
        Small("Runs daily and whenever an app is installed. It matches apps against known malware and flags risky sideloaded apps. Play Protect stays on as the first layer.")
    }
    Section("Web protection") {
        val on = dns != null && dns != "automatic"
        Text(if (on) "On: $dns" else "Off")
        if (!on) {
            Button(enabled = ready, onClick = {
                scope.launch { withContext(Dispatchers.IO) { Web.enable() }; delay(1500); refresh++ }
            }) { Text("Turn on") }
            if (!ready) Small("Without Shizuku: Settings, Network and internet, Private DNS, then enter ${Web.DNS}")
        }
        Small("Uses a filtering DNS (Quad9) so known malicious and phishing sites fail to load, in every app and browser.")
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
            scope.launch { upd = withContext(Dispatchers.IO) { Updater.check(c) } }
        }) { Text("Check for update") }
        if (upd.isNotEmpty()) Small(upd)
        Small("Checked daily. An update installs only if its checksum matches and it is signed with the same key as this app.")
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
        verdict?.let { v ->
            Text("${v.label} (risk ${v.score} of 100)",
                color = if (v.score >= 60) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            v.reasons.forEach { Small("- $it") }
            if (v.score < 30) Small("No red flags is not proof it is safe. If it asks for money, codes or a login, verify through a number you already know.")
        }
        if (ai.isNotEmpty()) { Text("Second opinion"); Small(ai) }
        Small("Tip: in any app, select text or tap Share, then pick Check for scam. For a QR code, scan it with the camera and share the link here before opening it.")
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
        Small("The email goes to the XposedOrNot breach service. The password never leaves the phone: only the first five characters of its hash are sent.")
    }
    Section("Home AI for second opinions") {
        OutlinedTextField(value = glm, onValueChange = { glm = it; Store.put("glmUrl", it.trim()) }, modifier = Modifier.fillMaxWidth(),
            singleLine = true, label = { Text("Address, https://...ts.net") })
        Small("Optional. Sends the checked text to the family's own model over Tailscale, never to an outside AI. Leave empty to use on-phone rules only.")
    }
}

@Composable
private fun Clean() {
    val scope = rememberCoroutineScope()
    var msg by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var refresh by remember { mutableIntStateOf(0) }
    val st = remember(refresh) { Device.storage() }
    val files by produceState<List<Pair<Long, String>>?>(null, refresh) {
        value = withContext(Dispatchers.IO) { if (Shell.granted()) Actions.largeFiles() else null }
    }

    Section("Storage") {
        val pct = st.first * 100 / st.second
        Text("${gb(st.first)} free of ${gb(st.second)} ($pct%)")
        if (pct < 15) Text("Below 15% free the phone slows down sharply. Clear space.", color = MaterialTheme.colorScheme.error)
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                msg = withContext(Dispatchers.IO) { Actions.trimCaches() }
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
            f == null -> Small("Start Shizuku to list large files.")
            f.isEmpty() -> Small("No files over 50 MB.")
            else -> f.forEach { (size, path) -> Small("${size / 1_000_000} MB   ${path.removePrefix("/sdcard/")}") }
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
                TextButton(enabled = ready, onClick = { act { Actions.forceStop(r.pkg) } }) { Text("Stop now") }
                TextButton(enabled = ready, onClick = { act { Actions.restrictBackground(r.pkg, true) } }) { Text("Block background") }
                TextButton(enabled = ready, onClick = { act { Actions.restrictBackground(r.pkg, false) } }) { Text("Unblock") }
            }
        }
        Small("Stopping or blocking an app can delay its notifications, so these stay manual.")
    }
    Section("Unused preinstalled apps") {
        val bl = bloat
        when {
            bl == null -> Small("Start Shizuku once so the app can read usage history.")
            bl.isEmpty() -> Small("Nothing to suggest.")
            else -> {
                Small("Preinstalled apps not opened in 30 days. On a new phone, wait a few weeks before trusting this list. Disabling is reversible below.")
                bl.forEach { r ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(r.label, Modifier.weight(1f))
                        TextButton(enabled = ready, onClick = { act { Bloat.disable(r.pkg) } }) { Text("Disable") }
                    }
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
