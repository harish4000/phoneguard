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

    private fun snapshot() {
        if (Store.str("snap").isNotEmpty()) return
        Store.put("snap", keys.joinToString(";") { "$it=" + Shell.run("settings get $it").out.trim() })
    }

    private fun restoreCmds(): List<String> =
        Store.str("snap").split(';').filter { it.contains('=') }.map {
            val k = it.substringBefore('=')
            val v = it.substringAfter('=')
            if (v.isEmpty() || v == "null") "settings delete $k" else "settings put $k $v"
        } + "cmd power set-mode 0"

    fun restore(): Boolean {
        if (!Shell.granted()) return false
        if (Store.str("snap").isNotEmpty()) Shell.run(restoreCmds().joinToString("; "))
        Store.put("profile", Profile.BALANCED.name)
        Store.put("base", Profile.BALANCED.name)
        Store.log("Restored original settings")
        return true
    }

    fun apply(c: Context, p: Profile, why: String, pkg: String? = null): Boolean {
        if (!Shell.granted()) return false
        snapshot()
        val cmds = ArrayList<String>()
        if (p == Profile.BALANCED) {
            cmds.addAll(restoreCmds())
        } else {
            cmds.add("cmd power set-mode ${if (p.saver) 1 else 0}")
            when (p.hz) {
                Hz.MAX -> {
                    val m = Device.maxHz(c)
                    cmds.add("settings put system peak_refresh_rate $m")
                    cmds.add("settings put system min_refresh_rate $m")
                }
                Hz.LOW -> {
                    cmds.add("settings put system peak_refresh_rate 60.0")
                    cmds.add("settings delete system min_refresh_rate")
                }
                Hz.DEFAULT -> { }
            }
            anims.forEach { cmds.add("settings put global $it ${p.anim}") }
        }
        if (pkg != null) cmds.add("cmd game mode ${p.game} $pkg")
        Shell.run(cmds.joinToString("; "))
        Store.put("profile", p.name)
        Store.log("Profile ${p.label} ($why)")
        return true
    }
}