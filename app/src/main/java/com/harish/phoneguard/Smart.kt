package com.harish.phoneguard

import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo

/**
 * Smart mode. Learns which apps make this phone run hot, then picks the profile for whatever is on screen
 * and relieves memory and storage pressure before they cause lag. Every action is logged with its reason.
 * It never force-stops or background-blocks apps by itself: those stay manual, because doing them silently
 * breaks notifications in messaging and location apps.
 */
object Smart {
    data class Learned(val pkg: String, val label: String, val samples: Int, val hotShare: Int)

    private const val MIN_SAMPLES = 20
    private var lastFg: String? = null
    private var lastTemp = 0f

    fun on(): Boolean = Store.bool("auto", true)

    private fun load(): HashMap<String, IntArray> {
        val m = HashMap<String, IntArray>()
        Store.str("heat").split(';').forEach {
            val p = it.split('|')
            val n = p.getOrNull(1)?.toIntOrNull()
            val h = p.getOrNull(2)?.toIntOrNull()
            if (p.size == 3 && n != null && h != null) m[p[0]] = intArrayOf(n, h)
        }
        return m
    }

    private fun save(m: Map<String, IntArray>) {
        Store.put("heat", m.entries.sortedByDescending { it.value[0] }.take(60)
            .joinToString(";") { "${it.key}|${it.value[0]}|${it.value[1]}" })
    }

    /** One sample every tick: was the phone warm, or warming, while this app was on screen? */
    private fun learn(fg: String, tempC: Float, charging: Boolean) {
        val m = load()
        val v = m.getOrPut(fg) { intArrayOf(0, 0) }
        val warming = fg == lastFg && tempC - lastTemp >= 0.3f
        // Charging heats the phone by itself, so only count clear heat while plugged in.
        val hot = if (charging) tempC >= 41f else tempC >= 38.5f || warming && tempC >= 36f
        v[0]++
        if (hot) v[1]++
        if (v[0] > 400) { v[0] /= 2; v[1] /= 2 }
        save(m)
        lastFg = fg
        lastTemp = tempC
    }

    private fun runsHot(pkg: String): Boolean {
        val v = load()[pkg] ?: return false
        return v[0] >= MIN_SAMPLES && v[1] * 100 / v[0] >= 30
    }

    fun learned(c: Context): List<Learned> {
        val pm = c.packageManager
        return load().mapNotNull { (p, v) ->
            if (v[0] < MIN_SAMPLES) return@mapNotNull null
            val label = try { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() } catch (e: Exception) { return@mapNotNull null }
            Learned(p, label, v[0], v[1] * 100 / v[0])
        }.sortedByDescending { it.hotShare }.take(8)
    }

    /** Called every 30 seconds by the monitor while the screen is on and the phone is not in cool-down. */
    fun tick(c: Context, b: Device.Batt) {
        val fg = Usage.foreground(c) ?: return
        if (fg == c.packageName) return
        learn(fg, b.tempC, b.charging)
        if (!on() || !Ctl.can(c)) return

        val cat = try { c.packageManager.getApplicationInfo(fg, 0).category } catch (e: Exception) { ApplicationInfo.CATEGORY_UNDEFINED }
        val hot = runsHot(fg)
        val (target, why) = when {
            b.pct <= 20 && !b.charging -> Profile.BATTERY to "battery at ${b.pct}%"
            cat == ApplicationInfo.CATEGORY_GAME && !hot -> Profile.GAMING to "game on screen"
            cat == ApplicationInfo.CATEGORY_GAME -> Profile.MEDIA to "game that runs hot on this phone, held at 60 Hz"
            cat == ApplicationInfo.CATEGORY_VIDEO -> Profile.MEDIA to "video app on screen"
            hot -> Profile.MEDIA to "app that runs hot on this phone, held at 60 Hz"
            else -> Profiles.base() to "back to your chosen profile"
        }
        if (target != Profiles.current()) {
            Profiles.apply(c, target, "smart: $why", if (cat == ApplicationInfo.CATEGORY_GAME) fg else null)
        }
        memoryRelief(c, fg)
    }

    /** Frees cached background processes when free memory runs low. Running apps and their notifications are untouched. */
    private fun memoryRelief(c: Context, fg: String) {
        val now = System.currentTimeMillis()
        if (now - Store.long("lastMemRelief") < 30 * 60_000) return
        val mi = ActivityManager.MemoryInfo()
        c.getSystemService(ActivityManager::class.java).getMemoryInfo(mi)
        val pct = mi.availMem * 100 / mi.totalMem.coerceAtLeast(1)
        if (pct >= 12 && !mi.lowMemory) return
        Store.putLong("lastMemRelief", now)
        Ctl.killCached(c, fg)
        Store.log("Smart: freed cached apps (memory at $pct% free)")
    }

    /** Called every ten minutes. Cleans caches when storage gets tight, at most once a day. */
    fun storageRelief(c: Context) {
        if (!on()) return
        val st = Device.storage()
        if (st.first * 100 / st.second >= 15) return
        if (System.currentTimeMillis() - Store.long("lastClean") < 86_400_000) return
        Store.log("Smart: storage under 15%, cleaning caches")
        Actions.trimCaches(c)
    }
}
