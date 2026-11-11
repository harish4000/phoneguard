package com.harish.phoneguard

import android.content.Context
import android.content.pm.ApplicationInfo

/** Cleanup and app control. */
object Actions {
    fun trimCaches(): String {
        if (!Shell.granted()) return "Start Shizuku to clean caches."
        val before = Device.storage().first
        Shell.run("pm trim-caches 999999999999")
        val freed = ((Device.storage().first - before) / 1_000_000).coerceAtLeast(0)
        Store.putLong("lastClean", System.currentTimeMillis())
        val msg = "Cleared app caches, freed $freed MB"
        Store.log(msg)
        return msg
    }

    fun forceStop(pkg: String) {
        Shell.run("am force-stop $pkg")
        Store.log("Stopped $pkg")
    }

    fun restrictBackground(pkg: String, on: Boolean) {
        Shell.run("cmd appops set $pkg RUN_ANY_IN_BACKGROUND ${if (on) "ignore" else "allow"}")
        Store.log((if (on) "Blocked background for " else "Allowed background for ") + pkg)
    }

    /** Largest files in shared storage as size to path. Listed only, never deleted by the app. */
    fun largeFiles(): List<Pair<Long, String>> =
        Shell.run("find /sdcard -type f -size +50M -exec stat -c '%s|%n' {} + 2>/dev/null | sort -t'|' -k1 -rn | head -25")
            .out.lines().mapNotNull {
                val i = it.indexOf('|')
                val size = if (i > 0) it.substring(0, i).toLongOrNull() else null
                if (size == null) null else size to it.substring(i + 1)
            }

    fun isUserApp(c: Context, pkg: String): Boolean = try {
        c.packageManager.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM == 0
    } catch (e: Exception) { false }
}

/** Finds apps that burn CPU while not on screen: the usual cause of lag and heat. */
object Rogue {
    data class Row(val pkg: String, val label: String, val avg: Float, val samples: Int)

    private fun load(): MutableMap<String, Pair<Float, Int>> {
        val m = HashMap<String, Pair<Float, Int>>()
        Store.str("rogue").split(';').forEach {
            val p = it.split('|')
            val s = p.getOrNull(1)?.toFloatOrNull()
            val n = p.getOrNull(2)?.toIntOrNull()
            if (p.size == 3 && s != null && n != null) m[p[0]] = s to n
        }
        return m
    }

    /** Current CPU use per process name as name to percent, highest first. */
    fun top(): List<Pair<String, Float>> =
        Shell.run("top -b -n 1 -m 25 -o %CPU,NAME").out.lines().mapNotNull {
            val t = it.trim().split(Regex("\\s+"))
            val cpu = t.getOrNull(0)?.toFloatOrNull()
            val name = t.getOrNull(1)?.substringBefore(':')
            if (cpu != null && name != null && name.contains('.')) name to cpu else null
        }.sortedByDescending { it.second }

    @Synchronized
    fun sample(c: Context, foreground: String?) {
        val m = load()
        val seen = HashMap<String, Float>()
        top().forEach { (p, v) ->
            if (p != foreground && p != c.packageName && Actions.isUserApp(c, p)) seen[p] = (seen[p] ?: 0f) + v
        }
        (m.keys + seen.keys).toSet().forEach { p ->
            val old = m[p] ?: (0f to 0)
            m[p] = (old.first + (seen[p] ?: 0f)) to (old.second + 1)
        }
        // Halve history about once a day so old behaviour fades out.
        if ((m.values.maxOfOrNull { it.second } ?: 0) > 288) m.keys.toList().forEach { k ->
            val v = m.getValue(k)
            m[k] = (v.first / 2) to (v.second / 2)
        }
        Store.put("rogue", m.entries.filter { it.value.first > 0.5f && it.value.second > 0 }
            .joinToString(";") { "${it.key}|${it.value.first}|${it.value.second}" })
    }

    fun flagged(c: Context): List<Row> {
        val pm = c.packageManager
        return load().mapNotNull { (p, v) ->
            val avg = v.first / v.second
            if (v.second < 6 || avg < 3f) return@mapNotNull null
            val label = try { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() } catch (e: Exception) { return@mapNotNull null }
            Row(p, label, avg, v.second)
        }.sortedByDescending { it.avg }
    }
}

/** Reversible disabling of preinstalled apps that have not been opened in 30 days. */
object Bloat {
    data class Row(val pkg: String, val label: String)

    private val keepPrefix = listOf(
        "com.android.", "com.google.android.gms", "com.google.android.gsf", "com.google.android.ext",
        "com.google.android.providers", "com.google.android.webview", "com.google.android.permissioncontroller",
        "com.google.android.packageinstaller", "com.google.android.setupwizard", "com.google.android.apps.messaging",
        "moe.shizuku", "com.harish.phoneguard"
    )
    private val keepWord = Regex("launcher|settings|dialer|phone|telecom|contacts|messag|camera|keyboard|inputmethod|systemui|setup|security|update")

    fun disabled(): Set<String> = Store.str("disabled").split(',').filter { it.isNotBlank() }.toSet()

    /** Null when usage access is missing, so the app never guesses. */
    fun candidates(c: Context): List<Row>? {
        val used = Usage.lastUsed(c)
        if (used.isEmpty()) return null
        val cutoff = System.currentTimeMillis() - 30L * 86_400_000
        val pm = c.packageManager
        return pm.getInstalledApplications(0).filter {
            it.flags and ApplicationInfo.FLAG_SYSTEM != 0 && it.enabled &&
                pm.getLaunchIntentForPackage(it.packageName) != null &&
                keepPrefix.none { k -> it.packageName.startsWith(k) } &&
                !keepWord.containsMatchIn(it.packageName) &&
                (used[it.packageName] ?: 0L) < cutoff
        }.map { Row(it.packageName, pm.getApplicationLabel(it).toString()) }.sortedBy { it.label }
    }

    fun disable(pkg: String) {
        Shell.run("pm disable-user --user 0 $pkg")
        Store.put("disabled", (disabled() + pkg).joinToString(","))
        Store.log("Disabled $pkg")
    }

    fun enable(pkg: String) {
        Shell.run("pm enable $pkg")
        Store.put("disabled", (disabled() - pkg).joinToString(","))
        Store.log("Re-enabled $pkg")
    }
}