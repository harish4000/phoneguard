package com.harish.phoneguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku

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
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) { App() }
        }
    }

    override fun onDestroy() {
        Shizuku.removeRequestPermissionResultListener(onGrant)
        super.onDestroy()
    }
}

private fun gb(b: Long): String = "%.1f GB".format(b / 1e9)

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
private fun App() {
    var tab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Home", "Clean", "Apps", "Security", "Log")
    Scaffold(bottomBar = {
        NavigationBar {
            tabs.forEachIndexed { i, t ->
                NavigationBarItem(selected = tab == i, onClick = { tab = i }, icon = { Text(t.take(1)) }, label = { Text(t) })
            }
        }
    }) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            when (tab) {
                0 -> Home()
                1 -> Clean()
                2 -> Apps()
                3 -> SecurityTab()
                else -> Section("Action log") { Small(Store.str("log").ifBlank { "Nothing yet." }) }
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
    var auto by remember { mutableStateOf(Store.bool("auto", true)) }

    if (!ready) Section("Control is off") {
        Text(
            if (alive) "Shizuku is running. Grant access to enable profiles, cleanup and app control."
            else "Open the Shizuku app and start it. This is needed again after every restart. Monitoring and alerts work without it."
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
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Switch(checked = auto, onCheckedChange = { auto = it; Store.putBool("auto", it) })
            Text("Switch automatically for games and video")
        }
        OutlinedButton(enabled = ready, onClick = {
            scope.launch { withContext(Dispatchers.IO) { Profiles.restore() }; tick++ }
        }) { Text("Restore original settings") }
    }
}
@Composable
private fun Clean() {
    val scope = rememberCoroutineScope()
    var msg by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var refresh by remember { mutableIntStateOf(0) }
    var weekly by remember { mutableStateOf(Store.bool("autoclean", true)) }
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
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Switch(checked = weekly, onCheckedChange = { weekly = it; Store.putBool("autoclean", it) })
            Text("Clean weekly while the screen is off")
        }
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

@Composable
private fun SecurityTab() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    var upd by remember { mutableStateOf("") }
    val findings by produceState<List<Security.Finding>?>(null, refresh) { value = withContext(Dispatchers.IO) { Security.scan(c) } }

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
        Small("Play Protect remains the virus scanner. This check confirms the phone's defences are on and shows which apps hold risky powers.")
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