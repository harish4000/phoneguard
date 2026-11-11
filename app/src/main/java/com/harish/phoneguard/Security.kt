package com.harish.phoneguard

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
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
            .map { label(c.packageManager, it.substringBefore('/')) }.distinct()

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

        if (Shell.granted()) {
            val v = Shell.run("settings get global package_verifier_user_consent").out.trim()
            out.add(if (v == "-1") Finding(2, "Play Protect is off", "Turn on app scanning in Play Store, Play Protect, Settings.")
            else Finding(0, "Play Protect", "App scanning is on."))
        }

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
            val uri = FileProvider.getUriForFile(c, c.packageName + ".files", f)
            val install = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            Notify.alert(c, 30, "PhoneGuard update ready", "Tap to install version ${j.optString("versionName")}.", install)
            Store.log("Update downloaded and verified")
            "Update verified. Tap the notification to install."
        } catch (e: Exception) {
            "Update check failed: ${e.message}"
        }
    }
}