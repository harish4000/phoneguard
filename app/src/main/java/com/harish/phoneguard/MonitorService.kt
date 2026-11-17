package com.harish.phoneguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import android.service.quicksettings.TileService

object Notify {
    private fun nm(c: Context) = c.getSystemService(NotificationManager::class.java)

    fun channels(c: Context) {
        nm(c).createNotificationChannel(NotificationChannel("status", "Monitor status", NotificationManager.IMPORTANCE_MIN))
        nm(c).createNotificationChannel(NotificationChannel("alerts", "Alerts", NotificationManager.IMPORTANCE_HIGH))
    }

    private fun open(c: Context): PendingIntent =
        PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)

    fun status(c: Context, text: String): Notification =
        Notification.Builder(c, "status").setSmallIcon(R.drawable.ic_shield).setContentTitle("PhoneGuard")
            .setContentText(text).setOngoing(true).setOnlyAlertOnce(true).setContentIntent(open(c)).build()

    fun update(c: Context, text: String) = nm(c).notify(1, status(c, text))

    fun alert(c: Context, id: Int, title: String, text: String, intent: Intent? = null) {
        channels(c)
        val pi = if (intent == null) open(c)
        else PendingIntent.getActivity(c, id, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        nm(c).notify(id, Notification.Builder(c, "alerts").setSmallIcon(R.drawable.ic_shield).setContentTitle(title)
            .setContentText(text).setStyle(Notification.BigTextStyle().bigText(text)).setAutoCancel(true)
            .setContentIntent(pi).build())
    }
}

/** Always-on monitor: thermal guard, charge guard, automatic profiles, rogue app sampling, daily checks. */
class MonitorService : Service() {
    private lateinit var thread: HandlerThread
    private lateinit var h: Handler
    private var n = 0L
    private var cooling = false
    private var stoppedHotApp = false
    private var prevBright = -1
    private var chargeAlerted = false
    private var hotChargeAlerted = false
    private var watch: android.os.FileObserver? = null

    /** Scans as soon as an app is installed or updated. Runs on the monitor thread. */
    private val installs = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            try { scanAndAlert() } catch (e: Throwable) { }
        }
    }

    private val loop = object : Runnable {
        override fun run() {
            try { tick() } catch (e: Throwable) { Store.log("Monitor error: ${e.message}") }
            h.postDelayed(this, 30_000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Store.init(this)
        Notify.channels(this)
        val note = Notify.status(this, "Monitoring")
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, note, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, note)
        thread = HandlerThread("phoneguard").apply { start() }
        h = Handler(thread.looper)
        h.post(loop)
        val f = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        registerReceiver(installs, f, null, h, Context.RECEIVER_NOT_EXPORTED)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDestroy() { try { unregisterReceiver(installs) } catch (e: Exception) { }; watch?.stopWatching(); thread.quitSafely(); super.onDestroy() }

    private fun tick() {
        n++
        val b = Device.battery(this)
        val th = Device.thermal(this)
        val ready = Shell.granted()
        Notify.update(this, "%.0f C, %s, %s%s".format(b.tempC, Device.thermalLabel(th), Profiles.current().label,
            if (ready) "" else ". Control off: start Shizuku"))
        thermalGuard(b, th)
        chargeGuard(b)
        val screenOn = getSystemService(PowerManager::class.java).isInteractive
        if (screenOn && !cooling) Smart.tick(this, b)
        WifiCheck.tick(this)
        if (ready && n % 10 == 0L) Rogue.sample(this, Usage.foreground(this))
        if (n % 20 == 1L) housekeeping(ready, screenOn)
    }

    private fun thermalGuard(b: Device.Batt, th: Int) {
        val hot = b.tempC >= 42f || th >= PowerManager.THERMAL_STATUS_MODERATE
        val cool = b.tempC <= 38f && th < PowerManager.THERMAL_STATUS_MODERATE
        if (hot && !cooling) {
            cooling = true
            prevBright = try { Settings.System.getInt(contentResolver, Settings.System.SCREEN_BRIGHTNESS) } catch (e: Exception) { -1 }
            val ok = Profiles.apply(this, Profile.COOLDOWN, "heat %.0f C".format(b.tempC))
            if (ok) Shell.run("cmd display set-brightness 0.35")
            Notify.alert(this, 10, "Phone is running hot",
                if (ok) "Cool-down applied: 60 Hz, dimmer screen, battery saver. It lifts by itself once the phone cools."
                else "Close heavy apps and unplug the charger. Start Shizuku for automatic cool-down.")
        }
        if (cooling && !stoppedHotApp && Shell.granted() && (b.tempC >= 46f || th >= PowerManager.THERMAL_STATUS_SEVERE)) {
            val fg = Usage.foreground(this)
            val worst = Rogue.top().firstOrNull { it.first != fg && it.first != packageName && Actions.isUserApp(this, it.first) }
            if (worst != null) {
                stoppedHotApp = true
                Actions.forceStop(worst.first)
                Notify.alert(this, 11, "Stopped a background app to cool down", worst.first)
            }
        }
        if (cooling && cool) {
            cooling = false
            stoppedHotApp = false
            if (Shell.granted()) {
                if (prevBright >= 0) Shell.run("settings put system screen_brightness $prevBright")
                Profiles.apply(this, Profiles.base(), "cooled down")
            }
        }
    }

    private fun chargeGuard(b: Device.Batt) {
        if (!b.charging) { chargeAlerted = false; hotChargeAlerted = false; return }
        if (b.pct >= 80 && !chargeAlerted) {
            chargeAlerted = true
            Notify.alert(this, 20, "Battery at ${b.pct}%", "Unplug now to slow battery wear.")
        }
        if (b.tempC >= 40f && !hotChargeAlerted) {
            hotChargeAlerted = true
            Notify.alert(this, 21, "Charging hot (%.0f C)".format(b.tempC), "Take the case off or unplug until it cools.")
        }
    }

    private fun housekeeping(ready: Boolean, screenOn: Boolean) {
        val now = System.currentTimeMillis()
        if (ready && !screenOn && Store.bool("autoclean", true) && now - Store.long("lastClean") > 7L * 86_400_000) {
            Actions.trimCaches()
        }
        Smart.storageRelief()
        ensureWatch()
        try { Powers.check(this) } catch (e: Throwable) { }
        val day = now / 86_400_000
        if (Store.long("defsDay") != day) {
            val before = Defs.version()
            Defs.update(this)
            if (Defs.version() != before) scanAndAlert()
        }
        if (Store.long("day") == day) return
        Store.putLong("day", day)
        scanAndAlert()
        deepScan()
        if (ready) Shell.bootstrap(this)
        val st = Device.storage()
        val pct = st.first * 100 / st.second
        if (pct < 15) Notify.alert(this, 22, "Storage almost full",
            "Only $pct% free. Phones slow down sharply below 15%. Open PhoneGuard, Clean.")
        if (Device.uptimeDays() >= 7) Notify.alert(this, 23, "Restart recommended",
            "The phone has been on for %.0f days. A restart clears stuck processes.".format(Device.uptimeDays()))
        Updater.check(this)
        Digest.maybe(this)
    }

    private fun scanAndAlert() {
        val bad = Scanner.scan(this).filter { it.level == 2 }
        if (bad.isNotEmpty()) {
            Store.log("Scan: malware match in " + bad.joinToString(", ") { it.label })
            Store.inc("wkMalware")
            Notify.alert(this, 24, "Malware found", bad.joinToString(", ") { it.label } + ". Open PhoneGuard, Protect.")
        }
    }

    /** Daily: files changed since the last scan, and everything running right now. */
    private fun deepScan() {
        val files = FileScan.scan(this, Store.long("lastFileScan")).filter { it.level == 2 }
        if (files.isNotEmpty()) {
            Store.inc("wkMalware")
            Notify.alert(this, 27, "Malware file found", files.joinToString(", ") { it.path.substringAfterLast('/') } + ". Open PhoneGuard, Protect, to delete it.")
        }
        val procs = ProcScan.scan(this).orEmpty().filter { it.level == 2 }
        if (procs.isNotEmpty()) {
            Store.inc("wkMalware")
            Notify.alert(this, 28, "Malware is running", procs.joinToString(", ") { it.name } + ". Open PhoneGuard, Protect.")
        }
    }

    /** Real-time check of files as they land in download and received-file folders. */
    private fun ensureWatch() {
        if (watch != null) return
        watch = FileScan.observer { f ->
            h.postDelayed({
                try {
                    val hit = FileScan.check(this, f) ?: return@postDelayed
                    FileScan.remember(hit)
                    Store.log("File flagged: ${f.name} (${hit.why})")
                    if (hit.level == 2) Store.inc("wkMalware")
                    Notify.alert(this, 29, if (hit.level == 2) "Malware file received" else "Suspicious file received", "${f.name}: ${hit.why} Open PhoneGuard, Protect.")
                } catch (e: Throwable) { }
            }, 2500)
        }
        watch?.startWatching()
    }

    companion object {
        fun start(c: Context) { c.startForegroundService(Intent(c, MonitorService::class.java)) }
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (i.action == Intent.ACTION_BOOT_COMPLETED) MonitorService.start(c)
    }
}

/** Quick Settings tile: one tap clears app caches. */
class CleanTile : TileService() {
    override fun onClick() {
        Store.init(this)
        Thread { Notify.alert(this, 40, "Quick clean", Actions.trimCaches()) }.start()
    }
}