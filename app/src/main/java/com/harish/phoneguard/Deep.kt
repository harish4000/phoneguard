package com.harish.phoneguard

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import android.os.FileObserver
import android.provider.Settings
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * File scan. Walks all of shared storage and checks every file that can carry Android code:
 * app installers (whatever their file name says), DEX code and native binaries.
 * Other apps' private data is off limits to every app on Android, this one included.
 */
object FileScan {
    data class Hit(val path: String, val level: Int, val why: String)

    private const val NONE = 0
    private const val APK = 1
    private const val DEX = 2
    private const val ELF = 3
    private const val MAX_HASH_BYTES = 300L * 1024 * 1024
    private val apkExt = setOf("apk", "apks", "xapk", "apkm")

    fun allowed(): Boolean = Environment.isExternalStorageManager()

    /** Grants all-files access through Shizuku. Returns false when Shizuku is not ready. */
    fun grant(c: Context): Boolean {
        if (!Shell.granted()) return false
        Shell.run("appops set ${c.packageName} MANAGE_EXTERNAL_STORAGE allow")
        Store.log("File scanning allowed")
        return true
    }

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

    /** Decides by content, not by file name, so a renamed installer is still caught. */
    private fun kind(f: File): Int {
        val head = ByteArray(4)
        val n = try { f.inputStream().use { it.read(head) } } catch (e: Exception) { return NONE }
        if (n < 4) return NONE
        if (head[0] == 0x7f.toByte() && head[1] == 'E'.code.toByte() && head[2] == 'L'.code.toByte() && head[3] == 'F'.code.toByte()) return ELF
        if (head[0] == 'd'.code.toByte() && head[1] == 'e'.code.toByte() && head[2] == 'x'.code.toByte() && head[3] == '\n'.code.toByte()) return DEX
        if (head[0] == 'P'.code.toByte() && head[1] == 'K'.code.toByte() && head[2] == 3.toByte() && head[3] == 4.toByte()) {
            if (f.extension.lowercase() in apkExt) return APK
            return try {
                ZipFile(f).use { z -> if (z.getEntry("AndroidManifest.xml") != null && z.getEntry("classes.dex") != null) APK else NONE }
            } catch (e: Exception) { NONE }
        }
        return NONE
    }

    /** Checks one file. Null means clean or not a file type that can carry Android code. */
    @Synchronized
    fun check(c: Context, f: File): Hit? {
        if (!f.isFile || f.length() < 8) return null
        val k = kind(f)
        if (k == NONE) return null
        val key = f.path + "|" + f.length() + "|" + f.lastModified()
        if (clean.contains(key)) return null
        if (f.length() <= MAX_HASH_BYTES) {
            val sha = try { sha256(f) } catch (e: Exception) { "" }
            if (Defs.contains(Defs.file(c, "hashes.txt"), sha)) return Hit(f.path, 2, "Matches a known malware sample.")
        }
        val ext = f.extension.lowercase()
        if (k == APK) {
            val pi = try { c.packageManager.getPackageArchiveInfo(f.path, PackageManager.GET_SIGNING_CERTIFICATES) } catch (e: Exception) { null }
            val signers = pi?.signingInfo?.apkContentsSigners.orEmpty().map { s ->
                MessageDigest.getInstance("SHA-1").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
            }
            if (signers.any { Defs.contains(Defs.file(c, "certs.txt"), it) })
                return Hit(f.path, 2, "App installer signed with a certificate used by known stalkerware.")
            if (pi != null && Defs.contains(Defs.file(c, "pkgs.txt"), pi.packageName))
                return Hit(f.path, 1, "App installer whose package name matches known stalkerware.")
            if (ext !in apkExt && ext != "zip" && ext != "jar")
                return Hit(f.path, 1, "App installer disguised as a .$ext file. Do not open it unless you know where it came from.")
        } else if (!f.path.contains("/Android/")) {
            return Hit(f.path, 1, (if (k == DEX) "App code" else "A program") + " stored in shared storage. Ordinary apps do not keep code here.")
        }
        clean.add(key)
        return null
    }

    private val clean: MutableSet<String> by lazy {
        HashSet(Store.str("fc").split('\n').filter { it.isNotBlank() })
    }

    private fun saveClean() {
        Store.put("fc", clean.filter { File(it.substringBefore('|')).exists() }.take(4000).joinToString("\n"))
    }

    fun lastHits(): List<Hit> = Store.str("fileHits").split('\n').mapNotNull {
        val p = it.split('\t')
        val lvl = p.getOrNull(1)?.toIntOrNull()
        if (p.size == 3 && lvl != null && File(p[0]).exists()) Hit(p[0], lvl, p[2]) else null
    }

    private fun saveHits(h: List<Hit>) {
        Store.put("fileHits", h.joinToString("\n") { "${it.path}\t${it.level}\t${it.why}" })
        Store.putLong("lastBadFiles", h.count { it.level == 2 }.toLong())
    }

    fun forget(path: String) = saveHits(lastHits().filter { it.path != path })

    /** Records a hit found by the real-time watcher. */
    fun remember(h: Hit) = saveHits((lastHits().filter { it.path != h.path } + h))

    /**
     * Walks shared storage. With since > 0 only files changed after that time are checked.
     * Android blocks Android/data and Android/obb for apps, so those are covered through Shizuku when it is running.
     */
    @Synchronized
    fun scan(c: Context, since: Long = 0): List<Hit> {
        val started = System.currentTimeMillis()
        val found = ArrayList<Hit>()
        var files = 0L
        if (allowed()) {
            val root = Environment.getExternalStorageDirectory()
            val stack = ArrayDeque<File>()
            stack.add(root)
            while (stack.isNotEmpty() && files < 400_000) {
                val dir = stack.removeLast()
                val kids = try { dir.listFiles() } catch (e: Exception) { null } ?: continue
                for (f in kids) {
                    if (f.isDirectory) {
                        val rel = f.path.removePrefix(root.path)
                        if (rel == "/Android/data" || rel == "/Android/obb") continue
                        if (f.canonicalPath == f.absolutePath) stack.add(f)
                    } else {
                        files++
                        if (since > 0 && f.lastModified() < since) continue
                        try { check(c, f)?.let { found.add(it) } } catch (e: Throwable) { }
                    }
                }
            }
        }
        if (Shell.granted()) {
            val hashes = Defs.file(c, "hashes.txt")
            val newer = if (since > 0) "-mmin -${(started - since) / 60_000 + 2} " else ""
            val dirs = if (allowed()) "/sdcard/Android/data /sdcard/Android/obb" else "/sdcard"
            Shell.run("find $dirs -type f $newer\\( -iname '*.apk' -o -iname '*.dex' -o -iname '*.jar' -o -iname '*.xapk' \\) -size -300M -exec sha256sum {} + 2>/dev/null")
                .out.lines().forEach {
                    val sha = it.substringBefore(' ').trim()
                    val path = it.substringAfter(' ').trim()
                    if (sha.length == 64) {
                        files++
                        if (Defs.contains(hashes, sha)) found.add(Hit(path, 2, "Matches a known malware sample."))
                    }
                }
        }
        saveClean()
        val all = (lastHits().filter { old -> found.none { it.path == old.path } } + found)
        saveHits(all)
        if (since == 0L) Store.putLong("lastFileN", files)
        Store.putLong("lastFileScan", started)
        return all.sortedByDescending { it.level }
    }

    /** Folders where downloads and received files land. Watched so a bad file is flagged the moment it arrives. */
    fun watchDirs(): List<File> {
        val root = Environment.getExternalStorageDirectory()
        return listOf(
            "Download", "Documents", "Bluetooth", "Download/Telegram", "Telegram/Telegram Documents",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents", "Download/Nearby Share", "Download/Quick Share"
        ).map { File(root, it) }.filter { it.isDirectory }
    }

    fun observer(onFile: (File) -> Unit): FileObserver? {
        val dirs = watchDirs()
        if (!allowed() || dirs.isEmpty()) return null
        return object : FileObserver(dirs, CLOSE_WRITE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null) return
                dirs.map { File(it, path) }.firstOrNull { it.isFile }?.let(onFile)
            }
        }
    }
}

/** Process scan. Needs Shizuku, because Android hides other apps' processes from ordinary apps. */
object ProcScan {
    data class Hit(val name: String, val level: Int, val why: String)

    private val badNames = Regex("(?i)(^|/)(xmrig|minerd|cpuminer|ccminer|ethminer)(\\s|$)")
    private val rootNames = Regex("(?i)(^|/)(magiskd|ksud|frida-server|frida-helper|daemonsu)(\\s|$)")
    private val badDirs = listOf("/data/local/tmp/", "/sdcard/", "/storage/", "/mnt/")

    /** App processes from Android's activity report, for phones without Shizuku. Native programs are not visible this way. */
    private fun fromReport(): List<String> =
        Regex("ProcessRecord\\{[0-9a-f]+ \\d+:([^/\\s}]+)/").findAll(Ctl.dumpsys("activity processes"))
            .map { "app " + it.groupValues[1] }.distinct().toList()

    /** Null when neither Shizuku nor the one-time setup is available. */
    fun scan(c: Context): List<Hit>? {
        if (!Shell.granted() && !Ctl.dump(c)) return null
        val pm = c.packageManager
        val bad = Store.str("badPkgs").split(',').filter { it.isNotBlank() }.toSet()
        val out = ArrayList<Hit>()
        val seen = HashSet<String>()
        var count = 0
        // CMDLINE shows the full command. Some builds lack it, so fall back to the plain process name.
        var rows = if (Shell.granted()) Shell.run("ps -A -o USER,CMDLINE").out.lines().drop(1) else fromReport()
        if (Shell.granted() && rows.count { it.trim().contains(' ') } < 20) rows = Shell.run("ps -A -o USER,NAME").out.lines().drop(1)
        if (rows.size < 5) return null
        rows.forEach { line ->
            val t = line.trim().split(Regex("\\s+"), 2)
            val cmd = t.getOrNull(1)?.trim().orEmpty()
            if (cmd.isEmpty() || cmd.startsWith("[")) return@forEach
            count++
            val exe = cmd.substringBefore(' ')
            if (exe.contains("shizuku") || !seen.add(exe)) return@forEach
            when {
                badNames.containsMatchIn(cmd) -> out.add(Hit(exe, 2, "A crypto-mining program is running."))
                rootNames.containsMatchIn(cmd) -> out.add(Hit(exe, 1, "A root or instrumentation tool is running. On a phone you did not root yourself, that is a warning sign."))
                badDirs.any { exe.startsWith(it) } -> out.add(Hit(exe, 1, "A program is running from a temporary or shared folder, which ordinary apps never do."))
                else -> {
                    val pkg = exe.substringBefore(':')
                    if (!pkg.contains('.') || pkg.startsWith("/") || pkg == c.packageName) return@forEach
                    val ai = try { pm.getApplicationInfo(pkg, 0) } catch (e: Exception) { return@forEach }
                    val label = pm.getApplicationLabel(ai).toString()
                    if (pkg in bad) out.add(Hit(label, 2, "An app flagged as malware is running right now. Uninstall it."))
                    else if (ai.flags and ApplicationInfo.FLAG_SYSTEM == 0 && pm.getLaunchIntentForPackage(pkg) == null) {
                        val src = try { pm.getInstallSourceInfo(pkg).installingPackageName } catch (e: Exception) { null }
                        if (src != "com.android.vending") out.add(Hit(label, 1, "Running in the background with no app icon, and not from the Play Store ($pkg). Check that you installed it."))
                    }
                }
            }
        }
        Store.putLong("lastProcN", count.toLong())
        Store.putLong("lastBadProcs", out.count { it.level == 2 }.toLong())
        return out.sortedByDescending { it.level }
    }
}

/** Alerts the moment any app gains one of the powers that spying and banking malware depend on. */
object Powers {
    private fun pkgs(c: Context, key: String): Set<String> =
        Settings.Secure.getString(c.contentResolver, key).orEmpty().split(':').filter { it.isNotBlank() }.map { it.substringBefore('/') }.toSet()

    fun check(c: Context) {
        val now = mapOf(
            "acc" to pkgs(c, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
            "ntf" to pkgs(c, "enabled_notification_listeners"),
            "adm" to c.getSystemService(DevicePolicyManager::class.java).activeAdmins.orEmpty().map { it.packageName }.toSet()
        )
        val what = mapOf(
            "acc" to "can now read and control the screen",
            "ntf" to "can now read your notifications, including one-time codes",
            "adm" to "is now a device admin, which makes it hard to remove"
        )
        val pm = c.packageManager
        var id = 70
        for ((kind, set) in now) {
            val first = !Store.has("pw_$kind")
            val old = Store.str("pw_$kind").split(',').filter { it.isNotBlank() }.toSet()
            Store.put("pw_$kind", set.joinToString(","))
            if (first) continue
            for (p in set - old) {
                if (p == c.packageName) continue
                val label = try { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() } catch (e: Exception) { p }
                Notify.alert(c, id++, "New app power: $label", "$label ${what[kind]}. If you did not turn this on yourself, open PhoneGuard, Protect, Security check.")
                Store.log("Power granted: $label ${what[kind]}")
            }
        }
    }
}
