package com.harish.phoneguard

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.provider.Settings
import java.io.File
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/** Daily threat definitions, published by the repo's definitions workflow. Files are sorted, one entry per line. */
object Defs {
    private val base: String get() = BuildConfig.UPDATE_URL.replace("latest/download/update.json", "download/defs/")
    private val names = listOf("hosts.txt", "hashes.txt", "calls.txt", "certs.txt", "pkgs.txt", "bloat.txt")

    private fun dir(c: Context): File = File(c.filesDir, "defs").apply { mkdirs() }
    fun file(c: Context, name: String): File = File(dir(c), name)
    fun version(): String = Store.str("defsVer", "not downloaded yet")

    private fun open(u: String): HttpURLConnection =
        (URL(u).openConnection() as HttpURLConnection).apply { connectTimeout = 15_000; readTimeout = 60_000 }

    @Synchronized
    fun update(c: Context, force: Boolean = false): String {
        if (!base.startsWith("https://")) return "Definitions channel not set."
        if (!force && c.getSystemService(ConnectivityManager::class.java).isActiveNetworkMetered) return "Waiting for Wi-Fi to update definitions."
        return try {
            val ver = open(base + "version.txt").inputStream.bufferedReader().use { it.readText() }.trim()
            Store.putLong("defsDay", System.currentTimeMillis() / 86_400_000)
            if (ver == Store.str("defsVer") && names.all { file(c, it).exists() }) return "Definitions are current ($ver)."
            var failed = 0
            for (n in names) {
                // One missing file must not block the rest: keep the previous copy of that file and carry on.
                try {
                    val tmp = File(dir(c), "$n.tmp")
                    GZIPInputStream(open("$base$n.gz").inputStream).use { i -> tmp.outputStream().use { o -> i.copyTo(o) } }
                    if (!tmp.renameTo(file(c, n))) { tmp.copyTo(file(c, n), overwrite = true); tmp.delete() }
                } catch (e: Exception) { failed++ }
            }
            if (failed == names.size) return "Definitions update failed: no files could be downloaded."
            Store.put("defsVer", ver)
            Store.log("Definitions updated: $ver")
            "Definitions updated ($ver)."
        } catch (e: Exception) {
            "Definitions update failed: ${e.message}"
        }
    }

    /** Binary search for an exact line in a sorted text file, without loading it into memory. */
    fun contains(f: File, key: String): Boolean {
        if (key.isEmpty() || !f.exists() || f.length() == 0L) return false
        return try {
            RandomAccessFile(f, "r").use { r ->
                var lo = 0L
                var hi = r.length()
                var found = false
                while (lo < hi && !found) {
                    val mid = (lo + hi) / 2
                    if (mid > 0) { r.seek(mid - 1); r.readLine() } else r.seek(0)
                    val start = r.filePointer
                    val line = if (start >= hi) null else r.readLine()
                    if (line == null) hi = mid
                    else {
                        val cmp = line.trim().compareTo(key)
                        if (cmp == 0) found = true else if (cmp < 0) lo = r.filePointer else hi = mid
                    }
                }
                found
            }
        } catch (e: Exception) { false }
    }

    /** True when the host or any parent domain is on the malicious host list. */
    fun hostListed(c: Context, host: String): Boolean {
        val f = file(c, "hosts.txt")
        var h = host.lowercase().trim('.')
        while (h.contains('.')) {
            if (contains(f, h)) return true
            h = h.substringAfter('.')
        }
        return false
    }

    /** Community-rated preinstalled apps that are safe to disable: package name to a one-line description. */
    fun bloat(c: Context): Map<String, String> = try {
        file(c, "bloat.txt").readLines().mapNotNull {
            val i = it.indexOf('\t')
            if (i > 0) it.substring(0, i) to it.substring(i + 1) else null
        }.toMap()
    } catch (e: Exception) { emptyMap() }

    fun callPrefixes(c: Context): List<String> = try {
        file(c, "calls.txt").readLines().map { it.filter { ch -> ch.isDigit() } }.filter { it.length >= 3 }
    } catch (e: Exception) { emptyList() }
}

/** Checks installed apps against known malware hashes, plus a behaviour check on apps from outside the Play Store. */
object Scanner {
    data class Hit(val pkg: String, val label: String, val level: Int, val why: String)

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { i ->
            val buf = ByteArray(65536)
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun scan(c: Context): List<Hit> {
        val pm = c.packageManager
        val hashes = Defs.file(c, "hashes.txt")
        val certs = Defs.file(c, "certs.txt")
        val pkgs = Defs.file(c, "pkgs.txt")
        val cache = HashMap<String, String>()
        Store.str("hc").split(';').forEach {
            val p = it.split('|')
            if (p.size == 3) cache[p[0] + "|" + p[1]] = p[2]
        }
        val keep = ArrayList<String>()
        val acc = Settings.Secure.getString(c.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
        val out = ArrayList<Hit>()
        var count = 0
        for (ai in pm.getInstalledApplications(0)) {
            // Preinstalled apps are checked against hashes and certificates too. The behaviour checks below are for apps you added.
            val system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
            if (ai.packageName == c.packageName) continue
            val pi = try {
                pm.getPackageInfo(ai.packageName, PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (e: Exception) { continue }
            count++
            val label = pm.getApplicationLabel(ai).toString()
            val key = ai.packageName + "|" + pi.lastUpdateTime
            val sha = cache[key] ?: try { sha256(File(ai.sourceDir)) } catch (e: Exception) { "" }
            if (sha.isNotEmpty()) keep.add("$key|$sha")
            if (Defs.contains(hashes, sha)) {
                out.add(Hit(ai.packageName, label, 2, "Matches a known malware sample. Uninstall it."))
                continue
            }
            val signers = pi.signingInfo?.apkContentsSigners.orEmpty().map { s ->
                MessageDigest.getInstance("SHA-1").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
            }
            if (signers.any { Defs.contains(certs, it) }) {
                out.add(Hit(ai.packageName, label, 2, "Signed with a certificate used by known stalkerware, which lets someone else read this phone. Uninstall it."))
                continue
            }
            if (system) continue
            if (Defs.contains(pkgs, ai.packageName)) {
                out.add(Hit(ai.packageName, label, 1, "Its package name matches known stalkerware. If you did not install it yourself, uninstall it."))
                continue
            }
            val src = try { pm.getInstallSourceInfo(ai.packageName).installingPackageName } catch (e: Exception) { null }
            if (src == "com.android.vending" || ai.packageName == "moe.shizuku.privileged.api") continue
            val req = pi.requestedPermissions?.toSet().orEmpty()
            val powers = ArrayList<String>()
            if ("android.permission.READ_SMS" in req || "android.permission.RECEIVE_SMS" in req) powers.add("reads your texts")
            if ("android.permission.SYSTEM_ALERT_WINDOW" in req) powers.add("draws over other apps")
            if ("android.permission.REQUEST_INSTALL_PACKAGES" in req) powers.add("installs other apps")
            if ("android.permission.READ_CALL_LOG" in req) powers.add("reads your call log")
            if (acc.contains(ai.packageName + "/")) powers.add("controls the screen")
            if (powers.size >= 2) out.add(Hit(ai.packageName, label, 1, "Installed outside the Play Store and it " + powers.joinToString(", ") + "."))
        }
        Store.put("hc", keep.joinToString(";"))
        Store.putLong("lastScan", System.currentTimeMillis())
        Store.putLong("lastScanN", count.toLong())
        Store.putLong("lastBad", out.count { it.level == 2 }.toLong())
        Store.put("badPkgs", out.filter { it.level == 2 }.joinToString(",") { it.pkg })
        return out.sortedByDescending { it.level }
    }

    /** APK files sitting in Downloads. Needs Shizuku to read the folder. */
    fun downloads(c: Context): List<Hit> {
        if (!Shell.granted()) return emptyList()
        val hashes = Defs.file(c, "hashes.txt")
        return Shell.run("find /sdcard/Download -maxdepth 2 -iname '*.apk' -exec sha256sum {} + 2>/dev/null").out.lines().mapNotNull {
            val sha = it.substringBefore(' ').trim()
            val path = it.substringAfter(' ').trim()
            if (sha.length == 64 && Defs.contains(hashes, sha)) Hit("", path.substringAfterLast('/'), 2, "Downloaded file matches known malware. Delete it in the Files app.") else null
        }
    }
}
