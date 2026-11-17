package com.harish.phoneguard

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.storage.StorageManager
import android.provider.Settings
import java.io.File
import java.io.FileOutputStream

/**
 * Control layer. Performance features run through whichever of these the phone has:
 *   2  Shizuku running: full control.
 *   1  One-time setup done: Android's developer permissions were granted to this app once, by Shizuku or by a PC
 *      over USB. They survive restarts and updates, so Shizuku is not needed again.
 *   0  Neither: monitoring and alerts only.
 */
object Ctl {
    private const val SECURE = "android.permission.WRITE_SECURE_SETTINGS"

    private fun has(c: Context, perm: String) = c.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED
    fun secure(c: Context): Boolean = has(c, SECURE)
    fun dump(c: Context): Boolean = has(c, Manifest.permission.DUMP)
    fun level(c: Context): Int = if (Shell.granted()) 2 else if (secure(c)) 1 else 0
    fun can(c: Context): Boolean = level(c) > 0

    fun label(c: Context): String = when (level(c)) {
        2 -> "Full (Shizuku running)"
        1 -> "On (one-time setup done)"
        else -> "Off"
    }

    /** While Shizuku is available, grant the permanent permissions so later restarts do not need it. */
    fun selfGrant(c: Context) {
        val p = c.packageName
        Shell.run(
            "pm grant $p $SECURE; pm grant $p android.permission.DUMP; pm grant $p android.permission.PACKAGE_USAGE_STATS; " +
                "pm grant $p android.permission.BATTERY_STATS; appops set $p WRITE_SETTINGS allow"
        )
    }

    /** Reading settings needs no permission. */
    fun get(c: Context, table: String, key: String): String? = try {
        when (table) {
            "global" -> Settings.Global.getString(c.contentResolver, key)
            "secure" -> Settings.Secure.getString(c.contentResolver, key)
            else -> Settings.System.getString(c.contentResolver, key)
        }
    } catch (e: Exception) { null }

    /** Writes a setting, or removes it when value is null. False when this phone refuses the change. */
    fun put(c: Context, table: String, key: String, value: String?): Boolean {
        if (Shell.granted()) {
            Shell.run(if (value == null) "settings delete $table $key" else "settings put $table $key $value")
            return true
        }
        if (!secure(c)) return false
        return try {
            when (table) {
                "global" -> Settings.Global.putString(c.contentResolver, key, value)
                "secure" -> Settings.Secure.putString(c.contentResolver, key, value)
                else -> Settings.System.canWrite(c) && Settings.System.putString(c.contentResolver, key, value)
            }
        } catch (e: Exception) {
            // Some phones only let the system itself change certain display settings.
            if (!Store.has("refused_$key")) { Store.put("refused_$key", "1"); Store.log("This phone refused a change to $key without Shizuku") }
            false
        }
    }

    fun saver(c: Context, on: Boolean) {
        if (Shell.granted()) Shell.run("cmd power set-mode ${if (on) 1 else 0}")
        else put(c, "global", "low_power", if (on) "1" else "0")
    }

    /** Dims the screen for cool-down. Returns the previous brightness and mode so they can be put back. */
    fun dim(c: Context): Pair<Int, Int> {
        val cr = c.contentResolver
        val level = try { Settings.System.getInt(cr, Settings.System.SCREEN_BRIGHTNESS) } catch (e: Exception) { -1 }
        val mode = try { Settings.System.getInt(cr, Settings.System.SCREEN_BRIGHTNESS_MODE) } catch (e: Exception) { -1 }
        if (Shell.granted()) Shell.run("cmd display set-brightness 0.35")
        else if (Settings.System.canWrite(c)) try {
            Settings.System.putInt(cr, Settings.System.SCREEN_BRIGHTNESS_MODE, Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL)
            if (level > 90) Settings.System.putInt(cr, Settings.System.SCREEN_BRIGHTNESS, 90)
        } catch (e: Exception) { }
        return level to mode
    }

    fun undim(c: Context, prev: Pair<Int, Int>) {
        val (level, mode) = prev
        if (Shell.granted()) {
            if (level >= 0) Shell.run("settings put system screen_brightness $level")
        } else if (Settings.System.canWrite(c)) try {
            if (level >= 0) Settings.System.putInt(c.contentResolver, Settings.System.SCREEN_BRIGHTNESS, level)
            if (mode >= 0) Settings.System.putInt(c.contentResolver, Settings.System.SCREEN_BRIGHTNESS_MODE, mode)
        } catch (e: Exception) { }
    }

    /** Output of a system report. Needs the DUMP permission from the one-time setup. Empty when unavailable. */
    fun dumpsys(args: String): String = try {
        val p = ProcessBuilder(listOf("sh", "-c", "dumpsys $args 2>/dev/null")).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().use { it.readText() }
        p.waitFor()
        out
    } catch (e: Exception) { "" }

    /**
     * Frees other apps' cached files without special rights: when an app asks Android to reserve storage,
     * Android deletes cached files to make room. The reserved file is removed straight away.
     */
    fun freeCaches(c: Context): Long {
        val before = Device.storage().first
        try {
            val sm = c.getSystemService(StorageManager::class.java)
            val uuid = sm.getUuidForPath(c.filesDir)
            val want = sm.getAllocatableBytes(uuid) - 500L * 1024 * 1024
            if (want - before < 20L * 1024 * 1024) return 0
            val tmp = File(c.cacheDir, "reserve.tmp")
            try {
                FileOutputStream(tmp).use { sm.allocateBytes(it.fd, want) }
            } finally { tmp.delete() }
        } catch (e: Exception) { }
        return (Device.storage().first - before).coerceAtLeast(0)
    }

    /** Asks Android to drop cached background processes of apps you installed. Running apps are untouched. */
    fun killCached(c: Context, except: String?) {
        if (Shell.granted()) { Shell.run("am kill-all"); return }
        val am = c.getSystemService(ActivityManager::class.java)
        c.packageManager.getInstalledApplications(0).forEach {
            if (it.flags and ApplicationInfo.FLAG_SYSTEM == 0 && it.packageName != except && it.packageName != c.packageName) {
                try { am.killBackgroundProcesses(it.packageName) } catch (e: Exception) { }
            }
        }
    }
}
