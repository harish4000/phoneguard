package com.harish.phoneguard

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.os.Build
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.util.concurrent.Executors

/**
 * Automatic scam alerts. Reads incoming message notifications and runs the same on-phone rules as the scam checker.
 * Message text is checked in memory and never stored or sent anywhere. Only a high score raises an alert.
 */
class ScamWatch : NotificationListenerService() {
    private val worker = Executors.newSingleThreadExecutor()
    private val seen = LinkedHashSet<Int>()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        try {
            Store.init(this)
            if (!Store.bool("scamAuto", true) || sbn.packageName == packageName || sbn.isOngoing) return
            val n = sbn.notification ?: return
            if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
            val isMessage = n.category == Notification.CATEGORY_MESSAGE || sbn.packageName in messengers
            if (!isMessage) return
            val text = textOf(n)
            if (text.length < 12) return
            synchronized(seen) {
                if (!seen.add(text.hashCode())) return
                if (seen.size > 200) seen.remove(seen.first())
            }
            val pkg = sbn.packageName
            worker.execute { check(pkg, text) }
        } catch (e: Throwable) { }
    }

    private fun check(pkg: String, text: String) {
        try {
            val v = Scam.rules(this, text)
            if (v.score < ALERT_AT) {
                // Optional: a borderline message goes to the family's own model, which reads meaning rather than wording.
                if (v.score < 30 || !Store.bool("aiAuto", false) || !Scam.aiOn() || !aiBudget()) return
                val opinion = Scam.ai(text)
                if (!aiSaysScam.containsMatchIn(opinion)) return
                val app = try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() } catch (e: Exception) { "a message" }
                val open = Intent(this, MainActivity::class.java).setAction(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
                Notify.alert(this, 5000 + (text.hashCode() and 0x3ff), "Possible scam in $app", "The home AI read it as a scam: " + opinion.take(220), open)
                Store.inc("wkScams")
                Store.log("Scam alert on a message in $app (home AI)")
                return
            }
            val app = try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() } catch (e: Exception) { "a message" }
            val open = Intent(this, MainActivity::class.java).setAction(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
            Notify.alert(this, 5000 + (text.hashCode() and 0x3ff), "Possible scam in $app",
                v.reasons.take(3).joinToString(". ") + ". Do not tap its links. Tap here to review.", open)
            Store.inc("wkScams")
            Store.log("Scam alert on a message in $app (risk ${v.score})")
        } catch (e: Throwable) { }
    }

    private fun textOf(n: Notification): String {
        val x = n.extras ?: return ""
        val last = try {
            @Suppress("DEPRECATION")
            x.getParcelableArray(Notification.EXTRA_MESSAGES)?.lastOrNull()?.let { (it as? android.os.Bundle)?.getCharSequence("text") }
        } catch (e: Exception) { null }
        val body = last ?: x.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: x.getCharSequence(Notification.EXTRA_TEXT)
        return body?.toString()?.trim().orEmpty()
    }

    private val aiCalls = ArrayList<Long>()

    private fun aiBudget(): Boolean = synchronized(aiCalls) {
        val now = System.currentTimeMillis()
        aiCalls.removeAll { now - it > 3_600_000 }
        if (aiCalls.size >= 12) false else aiCalls.add(now)
    }

    companion object {
        private val aiSaysScam = Regex("(?i)^\\W*(verdict\\W*)?(likely (a )?)?scam")
        const val ALERT_AT = 60
        private val messengers = setOf(
            "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms", "com.whatsapp",
            "com.whatsapp.w4b", "org.telegram.messenger", "org.thoughtcrime.securesms", "com.facebook.orca", "com.viber.voip"
        )

        fun enabled(c: Context): Boolean =
            Settings.Secure.getString(c.contentResolver, "enabled_notification_listeners").orEmpty().contains(c.packageName + "/")

        /** Grants notification access through Shizuku. Returns false when Shizuku is not ready. */
        fun enable(c: Context): Boolean {
            if (!Shell.granted()) return false
            Shell.run("cmd notification allow_listener " + ComponentName(c, ScamWatch::class.java).flattenToString())
            Store.log("Automatic scam alerts on")
            return true
        }
    }
}

/** One number for how well this phone is protected, with the fixes that would raise it. */
object Score {
    data class Result(val score: Int, val todo: List<String>)

    fun compute(c: Context): Result {
        var s = 100
        val todo = ArrayList<String>()
        fun lose(points: Int, fix: String) { s -= points; todo.add(fix) }

        if (Store.long("lastBad") + Store.long("lastBadFiles") + Store.long("lastBadProcs") > 0) lose(40, "Remove the malware found by the last scan (Protect tab)")
        if (!FileScan.allowed()) lose(5, "Allow file scanning (Protect tab)")
        if (!Cloud.on()) lose(5, "Add a VirusTotal key for cloud malware checks (Protect tab)")
        if (!c.getSystemService(android.os.PowerManager::class.java).isIgnoringBatteryOptimizations(c.packageName))
            lose(5, "Allow PhoneGuard to run in the background (Protect tab, Security check)")
        Security.scan(c).filter { it.level == 2 }.forEach { lose(20, it.title) }
        val dns = Web.dnsName(c)
        if (dns == null || dns == "automatic") lose(10, "Turn on web protection (Protect tab)")
        val today = System.currentTimeMillis() / 86_400_000
        if (today - Store.long("defsDay") > 3) lose(10, "Threat definitions are out of date. Connect to Wi-Fi.")
        if (System.currentTimeMillis() - Store.long("lastScan") > 3L * 86_400_000) lose(5, "Run a malware scan (Protect tab)")
        if (!CallRules.hasRole(c)) lose(5, "Turn on spam call blocking (Scams tab)")
        if (!ScamWatch.enabled(c) || !Store.bool("scamAuto", true)) lose(5, "Turn on automatic scam alerts (Scams tab)")
        if (Breach.watched().isEmpty()) lose(5, "Add your email for breach monitoring (Scams tab)")
        return Result(s.coerceIn(0, 100), todo)
    }
}

/** Weekly summary notification, plus the weekly breach recheck. */
object Digest {
    fun maybe(c: Context) {
        val now = System.currentTimeMillis()
        if (!Store.has("lastDigest")) { Store.putLong("lastDigest", now); return }
        if (now - Store.long("lastDigest") < 7L * 86_400_000) return
        Store.putLong("lastDigest", now)
        Breach.watch(c)
        val r = Score.compute(c)
        val parts = listOf(
            "${Store.long("wkCalls")} calls blocked or silenced",
            "${Store.long("wkScams")} scam messages flagged",
            "${Store.long("lastScanN")} apps and ${Store.long("lastFileN")} files scanned, ${Store.long("wkMalware")} threats"
        )
        val next = r.todo.firstOrNull()?.let { " Next step: $it." } ?: ""
        Notify.alert(c, 25, "Weekly protection report: ${r.score} of 100", parts.joinToString(", ") + "." + next)
        Store.log("Weekly report: score ${r.score}, " + parts.joinToString(", "))
        listOf("wkCalls", "wkScams", "wkMalware").forEach { Store.putLong(it, 0) }
    }
}

/** Warns once each time the phone joins a Wi-Fi network with no password or with broken WEP encryption. */
object WifiCheck {
    private var lastNet = 0L

    fun tick(c: Context) {
        if (Build.VERSION.SDK_INT < 31 || !Store.bool("wifiWarn", true)) return
        val cm = c.getSystemService(ConnectivityManager::class.java)
        val net = cm.activeNetwork
        val caps = if (net == null) null else cm.getNetworkCapabilities(net)
        if (net == null || caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) { lastNet = 0; return }
        if (net.networkHandle == lastNet) return
        lastNet = net.networkHandle
        val type = (caps.transportInfo as? WifiInfo)?.currentSecurityType ?: return
        val what = when (type) {
            WifiInfo.SECURITY_TYPE_OPEN -> "has no password"
            WifiInfo.SECURITY_TYPE_WEP -> "uses WEP, which is easily broken"
            else -> return
        }
        Notify.alert(c, 26, "Unsafe Wi-Fi", "This network $what, so others nearby can watch unencrypted traffic. Avoid banking and sign-ins here, or switch to mobile data.")
        Store.log("Joined an unsafe Wi-Fi network ($what)")
    }
}
