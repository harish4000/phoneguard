package com.harish.phoneguard

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import android.telecom.Call
import android.telecom.CallScreeningService
import android.telecom.Connection

/** Spam call rules. Decides before the phone rings. Nothing about calls leaves the phone. */
object CallRules {
    const val ALLOW = 0
    const val SILENCE = 1
    const val BLOCK = 2

    fun hasRole(c: Context): Boolean = c.getSystemService(RoleManager::class.java).isRoleHeld(RoleManager.ROLE_CALL_SCREENING)

    fun canReadContacts(c: Context): Boolean =
        c.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED

    private fun digits(s: String): String = s.filter { it.isDigit() }

    /** Last ten digits, so +1 365 555 0100 and 3655550100 compare equal. */
    private fun national(s: String): String = digits(s).takeLast(10)

    fun inContacts(c: Context, number: String): Boolean {
        if (!canReadContacts(c)) return false
        return try {
            val uri = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(number))
            c.contentResolver.query(uri, arrayOf(ContactsContract.PhoneLookup._ID), null, null, null)?.use { it.count > 0 } ?: false
        } catch (e: Exception) { false }
    }

    fun blockList(): List<String> = Store.str("blockList").split('\n', ',').map { digits(it) }.filter { it.length >= 3 }

    /** Returns the action and the reason for the log. */
    fun decide(c: Context, raw: String?, verificationFailed: Boolean): Pair<Int, String> {
        val number = raw?.trim().orEmpty()
        if (digits(number).isEmpty()) {
            return if (Store.bool("blkHidden", true)) BLOCK to "hidden number" else ALLOW to ""
        }
        val d = digits(number)
        val known = inContacts(c, number)
        if (known) return ALLOW to ""
        blockList().firstOrNull { d.startsWith(it) || national(number).startsWith(it) || d.endsWith(it) && it.length >= 7 }
            ?.let { return BLOCK to "on your block list" }
        if (Store.bool("blkFeed", true)) {
            Defs.callPrefixes(c).firstOrNull { d.startsWith(it) || d == it }?.let { return BLOCK to "on the shared spam list" }
        }
        if (verificationFailed && Store.bool("blkSpoof", true)) return BLOCK to "caller ID failed carrier verification"
        val mine = national(Store.str("myNumber"))
        if (Store.bool("blkNeighbour", true) && mine.length == 10 && canReadContacts(c)) {
            val n = national(number)
            if (n.length == 10 && n != mine && n.take(6) == mine.take(6)) return SILENCE to "look-alike of your own number"
        }
        if (Store.bool("silUnknown", false) && canReadContacts(c)) return SILENCE to "not in contacts"
        return ALLOW to ""
    }
}

class CallScreen : CallScreeningService() {
    override fun onScreenCall(details: Call.Details) {
        Store.init(this)
        val b = CallResponse.Builder()
        try {
            if (details.callDirection == Call.Details.DIRECTION_INCOMING && Store.bool("callsOn", true)) {
                val number = details.handle?.schemeSpecificPart
                val failed = details.callerNumberVerificationStatus == Connection.VERIFICATION_STATUS_FAILED
                val (action, why) = CallRules.decide(this, number, failed)
                val shown = if (number.isNullOrBlank()) "Hidden number" else number
                when (action) {
                    CallRules.BLOCK -> {
                        b.setDisallowCall(true).setRejectCall(true).setSkipCallLog(false).setSkipNotification(true)
                        Store.log("Blocked call $shown ($why)")
                    }
                    CallRules.SILENCE -> {
                        b.setSilenceCall(true)
                        Store.log("Silenced call $shown ($why)")
                    }
                }
            }
        } catch (e: Throwable) { }
        respondToCall(details, b.build())
    }
}
