package com.harish.phoneguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
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
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDestroy() { thread.quitSafely(); super.onDestroy() }

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
        if (ready && screenOn && !cooling && Store.bool("auto", true)) autoProfile()
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

    private fun autoProfile() {
        val fg = Usage.foreground(this) ?: return
        val cat = try { packageManager.getApplicationInfo(fg, 0).category } catch (e: Exception) { return }
        val target = when (cat) {
            ApplicationInfo.CATEGORY_GAME -> Profile.GAMING
            ApplicationInfo.CATEGORY_VIDEO -> Profile.MEDIA
            else -> Profiles.base()
        }
        if (target != Profiles.current()) {
            Profiles.apply(this, target, "auto: $fg", if (target == Profile.GAMING) fg else null)
        }
    }

    private fun housekeeping(ready: Boolean, screenOn: Boolean) {
        val now = System.currentTimeMillis()
        if (ready && !screenOn && Store.bool("autoclean", true) && now - Store.long("lastClean") > 7L * 86_400_000) {
            Actions.trimCaches()
        }
        val day = now / 86_400_000
        if (Store.long("day") == day) return
        Store.putLong("day", day)
        if (ready) Shell.bootstrap(this)
        val st = Device.storage()
        val pct = st.first * 100 / st.second
        if (pct < 15) Notify.alert(this, 22, "Storage almost full",
            "Only $pct% free. Phones slow down sharply below 15%. Open PhoneGuard, Clean.")
        if (Device.uptimeDays() >= 7) Notify.alert(this, 23, "Restart recommended",
            "The phone has been on for %.0f days. A restart clears stuck processes.".format(Device.uptimeDays()))
        Updater.check(this)
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