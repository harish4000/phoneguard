package com.harish.phoneguard

import android.content.Context

enum class Hz { DEFAULT, MAX, LOW }

enum class Profile(
    val label: String, val desc: String,
    val saver: Boolean, val hz: Hz, val anim: String, val game: String
) {
    BALANCED("Balanced", "Everyday use. Your original display and power settings.", false, Hz.DEFAULT, "1.0", "standard"),
    GAMING("Gaming", "Highest refresh rate, performance game mode, battery saver off.", false, Hz.MAX, "0.5", "performance"),
    MEDIA("Media", "60 Hz for video and normal power. Runs cooler on long sessions.", false, Hz.LOW, "1.0", "standard"),
    BATTERY("Battery", "Battery saver on, 60 Hz, shorter animations.", true, Hz.LOW, "0.5", "battery"),
    COOLDOWN("Cool-down", "Applied automatically when the phone runs hot.", true, Hz.LOW, "0.5", "battery")
}

/** Applies profiles. The first change snapshots the original settings so they can always be restored. */
object Profiles {
    private val anims = listOf("animator_duration_scale", "transition_animation_scale", "window_animation_scale")
    private val keys = listOf("system peak_refresh_rate", "system min_refresh_rate") + anims.map { "global $it" }

    private fun read(k: String): Profile =
        try { Profile.valueOf(Store.str(k, "BALANCED")) } catch (e: Exception) { Profile.BALANCED }

    fun current(): Profile = read("profile")
    fun base(): Profile = read("base")

    private fun snapshot(c: Context) {
        if (Store.str("snap").isNotEmpty()) return
        Store.put("snap", keys.joinToString(";") { "$it=" + (Ctl.get(c, it.substringBefore(' '), it.substringAfter(' ')) ?: "null") })
    }

    private fun restoreAll(c: Context) {
        Store.str("snap").split(';').filter { it.contains('=') }.forEach {
            val k = it.substringBefore('=')
            val v = it.substringAfter('=')
            Ctl.put(c, k.substringBefore(' '), k.substringAfter(' '), if (v.isEmpty() || v == "null") null else v)
        }
        Ctl.saver(c, false)
    }

    fun restore(c: Context): Boolean {
        if (!Ctl.can(c)) return false
        if (Store.str("snap").isNotEmpty()) restoreAll(c)
        Store.put("profile", Profile.BALANCED.name)
        Store.put("base", Profile.BALANCED.name)
        Store.log("Restored original settings")
        return true
    }

    fun apply(c: Context, p: Profile, why: String, pkg: String? = null): Boolean {
        if (!Ctl.can(c)) return false
        snapshot(c)
        if (p == Profile.BALANCED) {
            restoreAll(c)
        } else {
            Ctl.saver(c, p.saver)
            when (p.hz) {
                Hz.MAX -> {
                    val m = Device.maxHz(c).toString()
                    Ctl.put(c, "system", "peak_refresh_rate", m)
                    Ctl.put(c, "system", "min_refresh_rate", m)
                }
                Hz.LOW -> {
                    Ctl.put(c, "system", "peak_refresh_rate", "60.0")
                    Ctl.put(c, "system", "min_refresh_rate", null)
                }
                Hz.DEFAULT -> { }
            }
            anims.forEach { Ctl.put(c, "global", it, p.anim) }
        }
        if (pkg != null && Shell.granted()) Shell.run("cmd game mode ${p.game} $pkg")
        Store.put("profile", p.name)
        Store.log("Profile ${p.label} ($why)")
        return true
    }
}
