package com.harish.phoneguard

import android.content.Context
import android.content.SharedPreferences
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Settings and the action log. Everything stays on the phone. */
object Store {
    private lateinit var p: SharedPreferences

    fun init(c: Context) {
        if (!::p.isInitialized) p = c.applicationContext.getSharedPreferences("pg", Context.MODE_PRIVATE)
    }

    fun str(k: String, d: String = ""): String = p.getString(k, d) ?: d
    fun put(k: String, v: String) = p.edit().putString(k, v).apply()
    fun long(k: String): Long = p.getLong(k, 0L)
    fun putLong(k: String, v: Long) = p.edit().putLong(k, v).apply()
    fun bool(k: String, d: Boolean): Boolean = p.getBoolean(k, d)
    fun putBool(k: String, v: Boolean) = p.edit().putBoolean(k, v).apply()

    @Synchronized
    fun log(msg: String) {
        val t = SimpleDateFormat("MM-dd HH:mm", Locale.US).format(Date())
        val lines = listOf("$t  $msg") + str("log").lines().filter { it.isNotBlank() }
        put("log", lines.take(150).joinToString("\n"))
    }
}