package com.harish.phoneguard

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.pm.PackageInstaller
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import java.time.LocalDate
import java.time.temporal.ChronoUnit

/**
 * Security audit. This is not a virus scanner: Google Play Protect stays the malware engine.
 * The audit checks that the phone's own defences are on and lists the apps holding powers that malware abuses.
 */
object Security {
    /** level: 0 fine, 1 review, 2 risk. action: a Settings intent action that fixes it. */
    data class Finding(val level: Int, val title: String, val detail: String, val action: String? = null)

    private fun label(pm: PackageManager, pkg: String): String =
        try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (e: Exception) { pkg }

    private fun secureList(c: Context, key: String): List<String> =
        Settings.Secure.getString(c.contentResolver, key).orEmpty().split(':').filter { it.isNotBlank() }
            .map { it.substringBefore('/') }.filter { it != c.packageName }.map { label(c.packageManager, it) }.distinct()

    fun scan(c: Context): List<Finding> {
        val out = ArrayList<Finding>()
        val pm = c.packageManager

        out.add(if (c.getSystemService(KeyguardManager::class.java).isDeviceSecure)
            Finding(0, "Screen lock", "A PIN, pattern or password is set.")
        else Finding(2, "No screen lock", "Anyone holding the phone can open everything on it.", Settings.ACTION_SECURITY_SETTINGS))

        val days = try {
            ChronoUnit.DAYS.between(LocalDate.parse(Build.VERSION.SECURITY_PATCH), LocalDate.now())
        } catch (e: Exception) { -1L }
        out.add(when {
            days < 0 -> Finding(1, "Security patch level unknown", Build.VERSION.SECURITY_PATCH)
            days > 120 -> Finding(2, "Security patches are $days days old", "Install the pending system update.", Settings.ACTION_SETTINGS)
            else -> Finding(0, "Security patches", "Patch level ${Build.VERSION.SECURITY_PATCH}.")
        })

        val verifier = Ctl.get(c, "global", "package_verifier_user_consent")
        if (verifier != null) out.add(
            if (verifier.trim() == "-1") Finding(2, "Play Protect is off", "Turn on app scanning in Play Store, Play Protect, Settings.")
            else Finding(0, "Play Protect", "App scanning is on."))

        if (!c.getSystemService(android.os.PowerManager::class.java).isIgnoringBatteryOptimizations(c.packageName))
            out.add(Finding(1, "Android may stop PhoneGuard in the background", "Allow it to run in the background so protection is not paused.", Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))

        val side = pm.getInstalledApplications(0).filter {
            it.flags and ApplicationInfo.FLAG_SYSTEM == 0 && it.packageName != c.packageName && it.packageName != "moe.shizuku.privileged.api"
        }.filter {
            val src = try { pm.getInstallSourceInfo(it.packageName).installingPackageName } catch (e: Exception) { null }
            src != "com.android.vending"
        }.map { pm.getApplicationLabel(it).toString() }
        out.add(if (side.isEmpty()) Finding(0, "App sources", "Every app you installed came from the Play Store.")
        else Finding(1, "${side.size} app(s) installed outside the Play Store", side.joinToString(", ")))

        val acc = secureList(c, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        out.add(if (acc.isEmpty()) Finding(0, "Accessibility access", "No app can read or control the screen.")
        else Finding(1, "Apps that can read and control the screen", acc.joinToString(", "), Settings.ACTION_ACCESSIBILITY_SETTINGS))

        val admins = c.getSystemService(DevicePolicyManager::class.java).activeAdmins.orEmpty()
            .map { label(pm, it.packageName) }.distinct()
        if (admins.isNotEmpty()) out.add(Finding(1, "Device admin apps", admins.joinToString(", "), Settings.ACTION_SECURITY_SETTINGS))

        val listeners = secureList(c, "enabled_notification_listeners")
        if (listeners.isNotEmpty()) out.add(Finding(1, "Apps that can read your notifications",
            listeners.joinToString(", ") + ". These can see one-time codes.", Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))

        if (Shell.granted()) {
            val inst = Shell.run("appops query-op REQUEST_INSTALL_PACKAGES allow").out.lines()
                .map { it.trim() }.filter { it.contains('.') && !it.contains(' ') && it != c.packageName }.map { label(pm, it) }
            if (inst.isNotEmpty()) out.add(Finding(1, "Apps allowed to install other apps", inst.joinToString(", "), Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES))
        }

        if (Settings.Global.getInt(c.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1)
            out.add(Finding(1, "USB or wireless debugging is on", "Shizuku needs this. Never approve a debugging or pairing prompt you did not start yourself."))

        return out.sortedByDescending { it.level }
    }
}

/**
 * Self-update. Reads update.json over https, then accepts the new APK only if its SHA-256 matches the manifest
 * and it is signed with the same key as the installed app. Android enforces the signature again at install time.
 */
object Updater {
    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun signers(pi: PackageInfo?): Set<String> =
        pi?.signingInfo?.apkContentsSigners?.map { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }?.toSet().orEmpty()

    private fun sameSigner(c: Context, f: File): Boolean {
        val pm = c.packageManager
        val mine = signers(pm.getPackageInfo(c.packageName, PackageManager.GET_SIGNING_CERTIFICATES))
        val theirs = signers(pm.getPackageArchiveInfo(f.path, PackageManager.GET_SIGNING_CERTIFICATES))
        // Some Android versions cannot read signers from a file. The installer still rejects a different key.
        return theirs.isEmpty() || theirs == mine
    }

    fun check(c: Context): String {
        val url = BuildConfig.UPDATE_URL
        if (!url.startsWith("https://")) return "Update channel not set yet."
        return try {
            val conn = URL(url).openConnection().apply { connectTimeout = 10_000; readTimeout = 10_000 }
            val j = JSONObject(conn.getInputStream().bufferedReader().use { it.readText() })
            if (j.getInt("versionCode") <= BuildConfig.VERSION_CODE) return "Up to date (v${BuildConfig.VERSION_NAME})."
            val apkUrl = j.getString("url")
            if (!apkUrl.startsWith("https://")) return "Update rejected: not https."
            val f = File(c.cacheDir, "update/phoneguard.apk").apply { parentFile?.mkdirs() }
            val md = MessageDigest.getInstance("SHA-256")
            URL(apkUrl).openStream().use { i ->
                f.outputStream().use { o ->
                    val buf = ByteArray(65536)
                    while (true) {
                        val r = i.read(buf)
                        if (r < 0) break
                        md.update(buf, 0, r)
                        o.write(buf, 0, r)
                    }
                }
            }
            if (!hex(md.digest()).equals(j.getString("sha256"), ignoreCase = true)) {
                f.delete(); Store.log("Update rejected: checksum mismatch"); return "Update rejected: checksum mismatch."
            }
            if (!sameSigner(c, f)) {
                f.delete(); Store.log("Update rejected: signature mismatch"); return "Update rejected: signature mismatch."
            }
            Store.putLong("updPending", j.getInt("versionCode").toLong())
            Store.putLong("updPublished", j.optLong("published", 0))
            Store.put("updName", j.optString("versionName"))
            Store.log("Update ${j.optString("versionName")} downloaded and verified")
            if (Store.bool("autoUpdate", true)) return "Update ${j.optString("versionName")} verified. " +
                (if (ripe()) "It installs by itself when the screen is off." else "It installs by itself two days after release, once it has proven itself on the test phone.")
            Notify.alert(c, 30, "PhoneGuard update ready", "Tap to install version ${j.optString("versionName")}.", viewIntent(c, f))
            "Update verified. Tap the notification to install."
        } catch (e: Exception) {
            "Update check failed: ${e.message}"
        }
    }

    private fun apk(c: Context): File = File(c.cacheDir, "update/phoneguard.apk")

    private fun viewIntent(c: Context, f: File): Intent {
        val uri = FileProvider.getUriForFile(c, c.packageName + ".files", f)
        return Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    fun pending(c: Context): Boolean = Store.long("updPending") > BuildConfig.VERSION_CODE && apk(c).exists()

    /**
     * Staged rollout. A phone with "Get updates early" on installs at once and acts as the test phone.
     * Every other phone waits two days, so a bad release can be replaced before it reaches the family.
     */
    fun ripe(): Boolean {
        val published = Store.long("updPublished")
        return Store.bool("earlyUpdates", false) || published == 0L || System.currentTimeMillis() / 1000 - published >= 48 * 3600
    }

    /**
     * Installs a verified, pending update without a tap. Android allows an app to update itself silently once
     * it holds the install permission. If Android still wants a confirmation, UpdateReceiver turns that into a notification.
     */
    fun install(c: Context, manual: Boolean = false): Boolean {
        if (!pending(c) || (!manual && !ripe())) return false
        val f = apk(c)
        if (!sameSigner(c, f)) { f.delete(); return false }
        return try {
            val installer = c.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            params.setAppPackageName(c.packageName)
            if (Build.VERSION.SDK_INT >= 31) params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            val id = installer.createSession(params)
            installer.openSession(id).use { s ->
                s.openWrite("base.apk", 0, f.length()).use { out ->
                    f.inputStream().use { it.copyTo(out) }
                    s.fsync(out)
                }
                val done = PendingIntent.getBroadcast(c, id, Intent(c, UpdateReceiver::class.java),
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                s.commit(done.intentSender)
            }
            Store.log("Installing update ${Store.str("updName")}")
            true
        } catch (e: Exception) {
            Store.log("Automatic install failed: ${e.message}")
            Notify.alert(c, 30, "PhoneGuard update ready", "Tap to install version ${Store.str("updName")}.", viewIntent(c, f))
            false
        }
    }
}

/** Receives the result of an automatic install. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        Store.init(c)
        when (i.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_SUCCESS -> Store.log("Update installed")
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                if (confirm != null) Notify.alert(c, 30, "PhoneGuard update ready",
                    "Android wants a one-time confirmation. Tap to install version ${Store.str("updName")}.", confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            else -> Store.log("Update not installed: " + i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE))
        }
    }
}
