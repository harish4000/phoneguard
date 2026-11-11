package com.harish.phoneguard

import android.content.Context
import android.content.pm.PackageManager
import rikka.shizuku.Shizuku

/** Runs commands with ADB-level rights through Shizuku. Every privileged action in the app goes through here. */
object Shell {
    data class Result(val code: Int, val out: String)

    fun alive(): Boolean = try { Shizuku.pingBinder() } catch (e: Throwable) { false }

    fun granted(): Boolean = try {
        Shizuku.pingBinder() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (e: Throwable) { false }

    fun request() {
        try { if (Shizuku.pingBinder()) Shizuku.requestPermission(7) } catch (e: Throwable) { }
    }

    private val newProcess by lazy {
        Shizuku::class.java.getDeclaredMethod(
            "newProcess", Array<String>::class.java, Array<String>::class.java, String::class.java
        ).apply { isAccessible = true }
    }

    @Synchronized
    fun run(cmd: String): Result {
        if (!granted()) return Result(-1, "Shizuku not ready")
        return try {
            val p = newProcess.invoke(null, arrayOf("sh", "-c", "( $cmd ) 2>&1"), null, null) as Process
            val out = p.inputStream.bufferedReader().use { it.readText() }
            Result(p.waitFor(), out.trim())
        } catch (e: Throwable) {
            Result(-1, e.cause?.message ?: e.message ?: "error")
        }
    }

    /** Self setup once access is granted: usage access, notifications, exemption from battery optimisation. */
    fun bootstrap(c: Context) {
        val p = c.packageName
        run("appops set $p GET_USAGE_STATS allow; pm grant $p android.permission.POST_NOTIFICATIONS; dumpsys deviceidle whitelist +$p")
    }
}