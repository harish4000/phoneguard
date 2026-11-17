package com.harish.phoneguard

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.provider.Settings
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors

/** SHA-256, SHA-1 and MD5 of a file in one pass. Threat feeds publish any of the three. */
object Hashes {
    fun of(f: File): List<String> = try {
        val mds = listOf("SHA-256", "SHA-1", "MD5").map { MessageDigest.getInstance(it) }
        f.inputStream().use { i ->
            val buf = ByteArray(65536)
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                mds.forEach { it.update(buf, 0, n) }
            }
        }
        mds.map { md -> md.digest().joinToString("") { "%02x".format(it) } }
    } catch (e: Exception) { listOf("", "", "") }

    fun ofBytes(b: ByteArray): List<String> =
        listOf("SHA-1", "SHA-256").map { a -> MessageDigest.getInstance(a).digest(b).joinToString("") { "%02x".format(it) } }
}

/**
 * Cloud check against VirusTotal, which aggregates the verdicts of about seventy antivirus engines and is updated
 * continuously. Only a file's hash is sent, never the file. Needs an API key entered once on the phone.
 * The free key allows four lookups a minute, so results arrive in the background and are remembered.
 */
object Cloud {
    data class Verdict(val malicious: Int, val total: Int, val at: Long)
    data class Item(val sha: String, val label: String, val pkg: String, val path: String, val recheckSoon: Boolean)

    private const val DAILY_CAP = 120
    private const val BAD = 3
    private val worker = Executors.newSingleThreadExecutor()
    private val queued = HashSet<String>()

    fun key(): String = Store.str("vtKey").trim()
    fun on(): Boolean = key().length >= 32 && Store.bool("vtOn", true)
    fun status(): String = Store.str("vtStatus")

    fun usedToday(): Int {
        val day = System.currentTimeMillis() / 86_400_000
        return if (Store.long("vtDay") == day) Store.long("vtUsed").toInt() else 0
    }

    private fun spend() {
        val day = System.currentTimeMillis() / 86_400_000
        if (Store.long("vtDay") != day) { Store.putLong("vtDay", day); Store.putLong("vtUsed", 0) }
        Store.inc("vtUsed")
    }

    @Synchronized
    private fun load(): HashMap<String, Verdict> {
        val m = HashMap<String, Verdict>()
        Store.str("vt").split(';').forEach {
            val p = it.split('|')
            if (p.size == 4) m[p[0]] = Verdict(p[1].toIntOrNull() ?: 0, p[2].toIntOrNull() ?: 0, p[3].toLongOrNull() ?: 0)
        }
        return m
    }

    @Synchronized
    private fun save(sha: String, v: Verdict) {
        val m = load()
        m[sha] = v
        Store.put("vt", m.entries.sortedByDescending { it.value.at }.take(3000)
            .joinToString(";") { "${it.key}|${it.value.malicious}|${it.value.total}|${it.value.at}" })
    }

    fun verdict(sha: String): Verdict? = if (sha.length == 64) load()[sha] else null

    /** Text for a scan result, or null when the engines did not flag it. */
    fun describe(v: Verdict?): Pair<Int, String>? = when {
        v == null || v.malicious <= 0 -> null
        v.malicious >= BAD -> 2 to "Flagged as malicious by ${v.malicious} of ${v.total} antivirus engines on VirusTotal. Uninstall or delete it."
        else -> 1 to "Flagged by ${v.malicious} of ${v.total} antivirus engines on VirusTotal. One or two flags are often a false alarm, but check where it came from."
    }

    fun enqueue(c: Context, items: List<Item>) {
        if (!on()) return
        val known = load()
        val now = System.currentTimeMillis()
        val todo = items.filter { it.sha.length == 64 }.filter {
            val v = known[it.sha]
            v == null || now - v.at > (if (it.recheckSoon) 7L else 30L) * 86_400_000
        }
        synchronized(queued) {
            todo.filter { queued.add(it.sha) }.forEach { item -> worker.execute { lookup(c.applicationContext, item) } }
        }
    }

    private fun lookup(c: Context, item: Item) {
        try {
            if (!on() || usedToday() >= DAILY_CAP || Store.long("vtPauseUntil") > System.currentTimeMillis()) return
            spend()
            val conn = (URL("https://www.virustotal.com/api/v3/files/${item.sha}").openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 30_000
                setRequestProperty("x-apikey", key())
                setRequestProperty("accept", "application/json")
            }
            val now = System.currentTimeMillis()
            when (conn.responseCode) {
                200 -> {
                    val stats = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
                        .getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats")
                    val bad = stats.optInt("malicious")
                    val total = bad + stats.optInt("suspicious") + stats.optInt("harmless") + stats.optInt("undetected")
                    val v = Verdict(bad, total, now)
                    save(item.sha, v)
                    Store.put("vtStatus", "Working")
                    if (bad >= BAD) {
                        Store.inc("wkMalware")
                        Store.log("Cloud check: ${item.label} flagged by $bad of $total engines")
                        if (item.path.isNotEmpty()) FileScan.remember(FileScan.Hit(item.path, 2, describe(v)!!.second))
                        else {
                            Store.putLong("lastBad", Store.long("lastBad") + 1)
                            Store.put("badPkgs", (Store.str("badPkgs").split(',').filter { it.isNotBlank() } + item.pkg).distinct().joinToString(","))
                        }
                        Notify.alert(c, 32, "Malware found by cloud check", "${item.label}: flagged by $bad of $total antivirus engines. Open PhoneGuard, Protect.")
                    }
                }
                404 -> save(item.sha, Verdict(0, 0, now))  // never seen by VirusTotal
                401, 403 -> { Store.put("vtStatus", "The key was rejected. Check it."); Store.putLong("vtPauseUntil", now + 6 * 3_600_000) }
                429 -> { Store.put("vtStatus", "Daily or per-minute limit reached. Resumes later."); Store.putLong("vtPauseUntil", now + 3_600_000) }
                else -> Store.put("vtStatus", "VirusTotal answered ${conn.responseCode}")
            }
            Thread.sleep(16_000)  // four lookups a minute on the free key
        } catch (e: Throwable) {
        } finally {
            synchronized(queued) { queued.remove(item.sha) }
        }
    }
}

/**
 * Behaviour-based spyware check. Stalkerware and banking spyware share a shape: installed from outside the store,
 * hidden from the launcher, often named like a system component, and holding the permissions needed to watch someone.
 */
object Spy {
    class Powers(val acc: Set<String>, val ntf: Set<String>, val adm: Set<String>)

    private val watching = mapOf(
        "RECORD_AUDIO" to "microphone", "CAMERA" to "camera", "ACCESS_FINE_LOCATION" to "location",
        "ACCESS_BACKGROUND_LOCATION" to "background location", "READ_SMS" to "texts", "READ_CALL_LOG" to "call log",
        "READ_CONTACTS" to "contacts", "READ_MEDIA_IMAGES" to "photos", "READ_EXTERNAL_STORAGE" to "files",
        "READ_PHONE_STATE" to "phone state"
    )
    private val disguise = Regex("(?i)\\b(system|service|services|update|sync|wi-?fi|settings|android|security|battery|carrier|device health|google)\\b")

    private fun pkgs(c: Context, key: String): Set<String> =
        Settings.Secure.getString(c.contentResolver, key).orEmpty().split(':').filter { it.isNotBlank() }.map { it.substringBefore('/') }.toSet()

    fun powers(c: Context) = Powers(
        pkgs(c, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES), pkgs(c, "enabled_notification_listeners"),
        c.getSystemService(DevicePolicyManager::class.java).activeAdmins.orEmpty().map { it.packageName }.toSet()
    )

    fun judge(pm: PackageManager, ai: ApplicationInfo, pi: PackageInfo, label: String, installer: String?, p: Powers): Scanner.Hit? {
        val pkg = ai.packageName
        val req = pi.requestedPermissions.orEmpty()
        val flags = pi.requestedPermissionsFlags ?: IntArray(0)
        val uses = req.indices.filter { flags.getOrElse(it) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
            .mapNotNull { watching[req[it].substringAfterLast('.')] }.distinct()
        val held = ArrayList<String>()
        if (pkg in p.acc) held.add("controls the screen")
        if (pkg in p.ntf) held.add("reads notifications")
        if (pkg in p.adm) held.add("is a device admin")
        val hidden = pm.getLaunchIntentForPackage(pkg) == null
        val sideloaded = installer != "com.android.vending"
        val fake = sideloaded && disguise.containsMatchIn(label)

        val facts = ArrayList<String>()
        if (hidden) facts.add("has no app icon")
        if (sideloaded) facts.add("was installed from outside the Play Store")
        if (fake) facts.add("is named like a system component")
        facts.addAll(held)
        if (uses.isNotEmpty()) facts.add("can access " + uses.joinToString(", "))

        if (hidden && sideloaded && (held.isNotEmpty() || uses.size >= 3))
            return Scanner.Hit(pkg, label, 2, "Behaves like spyware: it " + facts.joinToString(", ") + ". If you did not install it yourself, uninstall it.")
        val score = (if (hidden) 3 else 0) + (if (sideloaded) 2 else 0) + (if (fake) 2 else 0) + held.size * 2 +
            (if (uses.size >= 5) 3 else if (uses.size >= 3) 2 else 0)
        if (score >= 6) return Scanner.Hit(pkg, label, 1, "Has the reach of a monitoring app: it " + facts.joinToString(", ") + ". Fine if you chose it for that, otherwise remove it.")
        return null
    }
}
