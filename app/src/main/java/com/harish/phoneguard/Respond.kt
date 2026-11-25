package com.harish.phoneguard

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Environment
import android.os.storage.StorageManager
import android.provider.Settings
import java.io.File
import java.io.FileOutputStream

/**
 * Automatic response to confirmed malware (verdict level 3: a match in the threat definitions, or eight or more
 * antivirus engines agreeing in the cloud check). Every action here can be undone from the Protect tab:
 * files are quarantined, not deleted, and apps are cut off and disabled, not uninstalled.
 * Lower-confidence findings are never acted on automatically.
 */
object Respond {
    data class Item(val id: String, val orig: String, val size: Long, val at: Long, val why: String, val sha: String, val inPlace: Boolean)

    private const val KEEP_DAYS = 30
    private const val BIG = 300L * 1024 * 1024

    fun on(): Boolean = Store.bool("autoAct", true)

    // Things the user marked as safe: package names and file hashes. Never flagged again.
    fun trusted(): Set<String> = Store.str("trusted").split('\n').filter { it.isNotBlank() }.toSet()
    fun trust(key: String) { if (key.isNotBlank()) Store.put("trusted", (trusted() + key).joinToString("\n")) }

    private fun dir(c: Context): File = File(c.filesDir, "quarantine").apply { mkdirs() }

    @Synchronized
    fun list(): List<Item> = Store.str("quar").split('\n').mapNotNull {
        val p = it.split('\t')
        if (p.size == 7) Item(p[0], p[1], p[2].toLongOrNull() ?: 0, p[3].toLongOrNull() ?: 0, p[4], p[5], p[6] == "1") else null
    }

    @Synchronized
    private fun save(items: List<Item>) {
        Store.put("quar", items.joinToString("\n") { "${it.id}\t${it.orig}\t${it.size}\t${it.at}\t${it.why}\t${it.sha}\t${if (it.inPlace) 1 else 0}" })
    }

    private fun held(c: Context, i: Item): File = if (i.inPlace) File(i.orig + ".quarantined") else File(dir(c), i.id)

    /** Moves a file out of reach into the app's private storage. Very large files are renamed in place instead. */
    @Synchronized
    fun quarantine(c: Context, hit: FileScan.Hit): Boolean {
        val f = File(hit.path)
        if (!f.isFile || f.name.endsWith(".quarantined")) return false
        return try {
            val sha = Hashes.of(f)[0]
            val id = System.currentTimeMillis().toString(36) + sha.take(8)
            val size = f.length()
            val inPlace = size > BIG || c.filesDir.usableSpace < size + 200L * 1024 * 1024
            val ok = if (inPlace) f.renameTo(File(f.path + ".quarantined")) else {
                val dest = File(dir(c), id)
                f.inputStream().use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
                if (dest.length() == size) f.delete() else { dest.delete(); false }
            }
            if (!ok) return false
            save(list() + Item(id, f.path, size, System.currentTimeMillis(), hit.why.replace('\t', ' ').replace('\n', ' '), sha, inPlace))
            FileScan.forget(hit.path)
            MediaScannerConnection.scanFile(c, arrayOf(f.path), null, null)
            Store.log("Quarantined ${f.name} (${hit.why})")
            true
        } catch (e: Exception) { false }
    }

    /** Puts a quarantined file back and trusts it, so it is not taken again. */
    fun restore(c: Context, id: String): Boolean {
        val i = list().firstOrNull { it.id == id } ?: return false
        val from = held(c, i)
        var to = File(i.orig)
        if (to.exists()) to = File(to.parentFile, "restored-" + to.name)
        return try {
            trust(i.sha)
            to.parentFile?.mkdirs()
            val ok = from.renameTo(to) || run {
                from.inputStream().use { a -> to.outputStream().use { b -> a.copyTo(b) } }
                to.length() == from.length() && from.delete()
            }
            if (ok) { save(list().filter { it.id != id }); Store.log("Restored ${to.name} from quarantine and marked it trusted") }
            ok
        } catch (e: Exception) { false }
    }

    fun delete(c: Context, id: String) {
        val i = list().firstOrNull { it.id == id } ?: return
        try { held(c, i).delete() } catch (e: Exception) { }
        save(list().filter { it.id != id })
        Store.log("Deleted quarantined file ${File(i.orig).name}")
    }

    /** Quarantined files are deleted for good after thirty days. */
    fun purge(c: Context) {
        val cutoff = System.currentTimeMillis() - KEEP_DAYS * 86_400_000L
        list().filter { it.at < cutoff }.forEach { delete(c, it.id) }
    }

    /** Quarantines every confirmed-malware file in the list. Returns the names taken. */
    fun files(c: Context, hits: List<FileScan.Hit>): List<String> {
        if (!on()) return emptyList()
        return hits.filter { it.level >= 3 }.filter { quarantine(c, it) }.map { File(it.path).name }
    }

    fun contained(): Set<String> = Store.str("contained").split(',').filter { it.isNotBlank() }.toSet()

    private fun without(list: String?, pkg: String): String? {
        val items = list.orEmpty().split(':').filter { it.isNotBlank() }
        val kept = items.filter { !it.startsWith("$pkg/") }
        return if (kept.size == items.size) null else kept.joinToString(":")
    }

    /**
     * Contains a confirmed-malware app: removes its screen-control and notification access, stops it, and with
     * Shizuku disables it. Then asks for the one thing Android reserves for the owner: the uninstall.
     * Returns what was done, or null when nothing was (already handled, preinstalled, or switched off).
     */
    fun app(c: Context, hit: Scanner.Hit): String? {
        if (!on() || hit.level < 3 || hit.pkg.isEmpty() || hit.pkg == c.packageName) return null
        val pm = c.packageManager
        val ai = try { pm.getApplicationInfo(hit.pkg, 0) } catch (e: Exception) { return null }
        // A wrong match on a preinstalled app could break the phone, so those are reported, never touched.
        if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) return null
        val key = hit.pkg + "|" + (try { pm.getPackageInfo(hit.pkg, 0).lastUpdateTime } catch (e: Exception) { 0L })
        val acted = Store.str("acted").split('\n').filter { it.isNotBlank() }
        if (key in acted) return null
        Store.put("acted", (acted + key).takeLast(200).joinToString("\n"))

        val done = ArrayList<String>()
        if (Ctl.can(c)) {
            without(Ctl.get(c, "secure", Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES), hit.pkg)?.let {
                if (Ctl.put(c, "secure", Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, it.ifEmpty { null })) done.add("removed its control of the screen")
            }
            without(Ctl.get(c, "secure", "enabled_notification_listeners"), hit.pkg)?.let {
                if (Ctl.put(c, "secure", "enabled_notification_listeners", it.ifEmpty { null })) done.add("removed its access to notifications")
            }
        }
        if (Shell.granted()) {
            Shell.run("am force-stop ${hit.pkg}; pm disable-user --user 0 ${hit.pkg}")
            Store.put("contained", (contained() + hit.pkg).joinToString(","))
            done.add("disabled it")
        } else {
            try { c.getSystemService(ActivityManager::class.java).killBackgroundProcesses(hit.pkg) } catch (e: Exception) { }
            done.add("stopped its background work")
        }
        val summary = done.joinToString(", ")
        Store.log("Contained ${hit.label}: $summary")
        Notify.alert(c, 33, "Malware contained: ${hit.label}", "PhoneGuard $summary. Tap to uninstall it now.",
            Intent(Intent.ACTION_DELETE, Uri.parse("package:" + hit.pkg)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return summary
    }

    /** Undo for a disabled app, after the user decides it was a false alarm. Needs Shizuku. */
    fun release(pkg: String): Boolean {
        if (!Shell.granted()) return false
        Shell.run("pm enable $pkg")
        Store.put("contained", (contained() - pkg).joinToString(","))
        trust(pkg)
        Store.log("Re-enabled $pkg and marked it trusted")
        return true
    }
}

/** Memory card support: scanning it, measuring it, and moving old media onto it to keep internal storage free. */
object Card {
    data class Plan(val files: List<File>, val bytes: Long)
    data class Result(val moved: Int, val bytes: Long, val failed: Int, val note: String)

    /** Root folder of the first mounted removable card, or null. */
    fun root(c: Context): File? = try {
        c.getSystemService(StorageManager::class.java).storageVolumes
            .firstOrNull { it.isRemovable && it.state == Environment.MEDIA_MOUNTED }?.directory
    } catch (e: Exception) { null }

    /** Sequential write speed in MB per second, from a 24 MB test file that is deleted afterwards. Null if it cannot be measured. */
    fun speed(c: Context): Float? {
        val card = root(c) ?: return null
        val dir = c.getExternalFilesDirs(null).filterNotNull().firstOrNull { it.path.startsWith(card.path) } ?: return null
        val f = File(dir, "speedtest.tmp")
        return try {
            dir.mkdirs()
            val block = ByteArray(1024 * 1024) { (it * 31).toByte() }
            val t = System.nanoTime()
            FileOutputStream(f).use { o -> repeat(24) { o.write(block) }; o.fd.sync() }
            24f / ((System.nanoTime() - t) / 1e9f)
        } catch (e: Exception) { null } finally { f.delete() }
    }

    /** Camera photos, pictures and videos older than the given number of days, plus large downloads if asked. */
    fun plan(days: Int, downloads: Boolean): Plan {
        val root = Environment.getExternalStorageDirectory()
        val cutoff = System.currentTimeMillis() - days * 86_400_000L
        val out = ArrayList<File>()
        fun walk(dir: File, minSize: Long) {
            val kids = try { dir.listFiles() } catch (e: Exception) { null } ?: return
            for (f in kids) {
                if (f.name.startsWith(".")) continue
                if (f.isDirectory) walk(f, minSize)
                else if (f.lastModified() < cutoff && f.length() >= minSize) out.add(f)
            }
        }
        listOf("DCIM", "Pictures", "Movies", "Music").forEach { walk(File(root, it), 1) }
        if (downloads) walk(File(root, "Download"), 50_000_000)
        return Plan(out, out.sumOf { it.length() })
    }

    /**
     * Keep-on-card mode: once a day, everything in the media folders that is more than a day old goes to the card.
     * The one-day wait keeps it away from files that are still being written or edited.
     */
    fun keep(c: Context) {
        if (!Store.bool("cardKeep", false) || !FileScan.allowed() || root(c) == null) return
        val plan = plan(1, false)
        if (plan.files.isNotEmpty()) move(c, plan)
    }

    /** Copies each file to the same folder on the card, checks the copy, and only then removes the original. */
    @Synchronized
    fun move(c: Context, plan: Plan): Result {
        val card = root(c) ?: return Result(0, 0, 0, "No memory card found.")
        val root = Environment.getExternalStorageDirectory()
        var moved = 0
        var bytes = 0L
        var failed = 0
        var note = ""
        val touched = ArrayList<String>()
        for (f in plan.files) {
            if (card.usableSpace < f.length() + 200L * 1024 * 1024) { note = "The card is full. Stopped early."; break }
            try {
                var dest = File(card, f.path.removePrefix(root.path).trimStart('/'))
                if (dest.exists() && dest.length() != f.length()) dest = File(dest.parentFile, "copy-" + dest.name)
                dest.parentFile?.mkdirs()
                if (!dest.exists()) f.inputStream().use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
                if (dest.length() == f.length()) {
                    dest.setLastModified(f.lastModified())
                    val size = f.length()
                    if (f.delete()) { moved++; bytes += size; touched.add(dest.path); touched.add(f.path) } else failed++
                } else { dest.delete(); failed++ }
            } catch (e: Exception) { failed++ }
        }
        // Tell the gallery where the files went.
        touched.chunked(200).forEach { MediaScannerConnection.scanFile(c, it.toTypedArray(), null, null) }
        Store.log("Moved $moved files (${bytes / 1_000_000} MB) to the memory card" + (if (failed > 0) ", $failed could not be moved" else ""))
        return Result(moved, bytes, failed, note)
    }
}
