package com.harish.phoneguard

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.display.DisplayManager
import android.os.BatteryManager
import android.os.Environment
import android.os.PowerManager
import android.os.StatFs
import android.os.SystemClock
import android.view.Display

/** Read-only device state. Needs no special rights. */
object Device {
    data class Batt(val pct: Int, val tempC: Float, val charging: Boolean)

    fun battery(c: Context): Batt {
        val i = c.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = i?.getIntExtra(BatteryManager.EXTRA_LEVEL, 0) ?: 0
        val scale = (i?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100).coerceAtLeast(1)
        val temp = (i?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10f
        val plugged = (i?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0) != 0
        return Batt(level * 100 / scale, temp, plugged)
    }

    fun thermal(c: Context): Int = c.getSystemService(PowerManager::class.java).currentThermalStatus

    fun thermalLabel(s: Int): String = when (s) {
        PowerManager.THERMAL_STATUS_NONE -> "Normal"
        PowerManager.THERMAL_STATUS_LIGHT -> "Warm"
        PowerManager.THERMAL_STATUS_MODERATE -> "Hot"
        PowerManager.THERMAL_STATUS_SEVERE -> "Very hot"
        else -> "Critical"
    }

    /** Free and total bytes of internal storage. */
    fun storage(): Pair<Long, Long> {
        val s = StatFs(Environment.getDataDirectory().path)
        return s.availableBytes to s.totalBytes.coerceAtLeast(1L)
    }

    fun uptimeDays(): Double = SystemClock.elapsedRealtime() / 86_400_000.0

    fun maxHz(c: Context): Float {
        val d = c.getSystemService(DisplayManager::class.java).getDisplay(Display.DEFAULT_DISPLAY)
        return d?.supportedModes?.maxOfOrNull { it.refreshRate } ?: 60f
    }
}

/** App usage, read through usage access (self-granted through Shizuku in Shell.bootstrap). */
object Usage {
    private var last: String? = null

    fun foreground(c: Context): String? {
        try {
            val usm = c.getSystemService(UsageStatsManager::class.java)
            val now = System.currentTimeMillis()
            val ev = usm.queryEvents(now - 120_000, now)
            val e = UsageEvents.Event()
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e)
                if (e.eventType == UsageEvents.Event.ACTIVITY_RESUMED) last = e.packageName
            }
        } catch (e: Exception) { }
        return last
    }

    /** Package to last-used time over the past 30 days. Empty when usage access is missing. */
    fun lastUsed(c: Context): Map<String, Long> = try {
        val usm = c.getSystemService(UsageStatsManager::class.java)
        val now = System.currentTimeMillis()
        usm.queryAndAggregateUsageStats(now - 30L * 86_400_000, now).mapValues { it.value.lastTimeUsed }
    } catch (e: Exception) { emptyMap() }
}