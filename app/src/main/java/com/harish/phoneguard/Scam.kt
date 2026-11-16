package com.harish.phoneguard

import android.content.Context
import android.net.ConnectivityManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest

/** Scam checker. Rules run on the phone. The optional second opinion goes to the family's own model over Tailscale. */
object Scam {
    data class Verdict(val score: Int, val label: String, val reasons: List<String>)

    private val urlRx = Regex("(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+|\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\.(?:com|net|org|info|xyz|top|ca|co|io|app|link|click|live|shop|site|online|ru|cn|tk|ly|me|cc|vip|icu|buzz|club|biz|us|uk)\\b(?:/[^\\s<>\"']*)?")
    private val ipRx = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val shorteners = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly", "t.ly")
    private val badTld = setOf("xyz", "top", "click", "link", "live", "icu", "buzz", "vip", "tk", "cc", "shop", "site", "online", "club")
    private val sld = setOf("co.uk", "com.au", "co.in", "co.nz", "com.br", "gc.ca", "on.ca", "qc.ca", "co.jp")
    private val brands = mapOf(
        "paypal" to listOf("paypal.com"), "netflix" to listOf("netflix.com"), "amazon" to listOf("amazon.com", "amazon.ca"),
        "apple" to listOf("apple.com", "icloud.com"), "microsoft" to listOf("microsoft.com", "live.com", "office.com"),
        "google" to listOf("google.com", "google.ca"), "interac" to listOf("interac.ca"),
        "canadapost" to listOf("canadapost-postescanada.ca", "canadapost.ca"), "purolator" to listOf("purolator.com"),
        "fedex" to listOf("fedex.com"), "scotiabank" to listOf("scotiabank.com"), "cibc" to listOf("cibc.com"),
        "rbcroyalbank" to listOf("rbcroyalbank.com", "rbc.com"), "desjardins" to listOf("desjardins.com"),
        "tangerine" to listOf("tangerine.ca"), "wealthsimple" to listOf("wealthsimple.com"), "rogers" to listOf("rogers.com"),
        "telus" to listOf("telus.com"), "koodo" to listOf("koodomobile.com"), "fido" to listOf("fido.ca"),
        "walmart" to listOf("walmart.com", "walmart.ca"), "costco" to listOf("costco.com", "costco.ca"),
        "whatsapp" to listOf("whatsapp.com"), "facebook" to listOf("facebook.com", "fb.com"), "instagram" to listOf("instagram.com")
    )
    private val textRules = listOf(
        Triple("urgent|immediately|right away|within 24 ?h|final notice|last warning|act now|account (?:is |has been )?(?:suspended|locked|restricted|disabled)", 15, "Pressure to act fast"),
        Triple("gift ?cards?|bitcoin|crypto|usdt|wire transfer|western union|e-?transfer|google play card|itunes card", 20, "Asks for money in a form that is hard to reverse"),
        Triple("verification code|one[- ]time (?:code|password|pin)|\\botp\\b|password|\\bpin\\b|\\bsin\\b|social insurance|card number|cvv|banking details", 20, "Asks for a code, password or personal number"),
        Triple("you(?:'ve| have) won|winner|prize|lottery|unclaimed|refund|rebate|compensation|inheritance", 20, "Promises money or a prize"),
        Triple("parcel|package|delivery|shipment|customs|redeliver|tracking", 10, "Delivery notice, a common lure"),
        Triple("hi (?:mom|mum|dad|grandma|grandpa)|new (?:phone )?number|lost my phone|broke my phone|this is my new", 30, "Claims to be family on a new number"),
        Triple("work from home|part[- ]time job|daily pay|easy money|hiring now", 20, "Unsolicited job or easy-money offer"),
        Triple("anydesk|teamviewer|remote access|install (?:this|the) app|screen shar", 30, "Asks you to install remote-access software"),
        Triple("\\bcra\\b|canada revenue|service canada|\\birs\\b|arrest warrant|tax (?:refund|return|owed)", 15, "Invokes a government agency or legal threat"),
        Triple("do not (?:tell|share)|keep (?:this|it) (?:secret|confidential|between us)", 25, "Asks for secrecy")
    ).map { Triple(Regex(it.first, RegexOption.IGNORE_CASE), it.second, it.third) }

    private fun hostOf(u: String): String {
        var s = u.trim().trimEnd('.', ',', ')', '!', '?')
        s = s.substringAfter("://", s)
        s = s.substringBefore('/').substringBefore('?').substringBefore('#')
        s = s.substringAfterLast('@').substringBefore(':')
        return s.lowercase().removePrefix("www.")
    }

    private fun apex(h: String): String {
        val p = h.split('.')
        if (p.size <= 2) return h
        val last2 = p.takeLast(2).joinToString(".")
        return if (last2 in sld) p.takeLast(3).joinToString(".") else last2
    }

    fun rules(c: Context, text: String): Verdict {
        var score = 0
        val why = LinkedHashSet<String>()
        val urls = urlRx.findAll(text).map { it.value }.toList()
        for (u in urls) {
            val h = hostOf(u)
            if (h.isEmpty()) continue
            val root = apex(h)
            val tld = h.substringAfterLast('.')
            if (Defs.hostListed(c, h)) { score += 60; why.add("$h is on a known phishing or malware list") }
            if (ipRx.matches(h)) { score += 30; why.add("Link uses a raw IP address") }
            if (h.contains("xn--")) { score += 30; why.add("Link uses look-alike characters") }
            if (root in shorteners) { score += 15; why.add("Shortened link hides the real destination") }
            if (tld in badTld) { score += 15; why.add("Unusual domain ending (.$tld)") }
            if (u.substringBefore('/', u).contains('@') || u.substringAfter("://", u).substringBefore('/').contains('@')) { score += 25; why.add("Link hides its destination with an @ sign") }
            if (u.startsWith("http://", true)) { score += 10; why.add("Link is not encrypted (http)") }
            val tokens = h.split('.', '-')
            for ((brand, real) in brands) {
                if (root !in real && tokens.any { it == brand || it.startsWith(brand) }) { score += 35; why.add("Mentions $brand but is not an official $brand site") }
            }
        }
        var textHit = false
        for ((rx, pts, reason) in textRules) {
            if (rx.containsMatchIn(text)) { score += pts; why.add(reason); textHit = true }
        }
        if (textHit && urls.isNotEmpty()) score += 10
        val label = when {
            score >= 60 -> "Likely a scam"
            score >= 30 -> "Suspicious"
            score > 0 -> "Minor flags only"
            else -> "No red flags found"
        }
        return Verdict(score.coerceAtMost(100), label, why.toList())
    }

    /** Second opinion from the family's own model. Empty string when no address is set. */
    fun ai(text: String): String {
        val base = Store.str("glmUrl").trim().trimEnd('/')
        if (base.isEmpty()) return ""
        if (!base.startsWith("https://")) return "AI address must start with https://"
        return try {
            val conn = (URL("$base/check").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 8_000
                readTimeout = 180_000
                setRequestProperty("Content-Type", "application/json")
            }
            conn.outputStream.use { it.write(JSONObject().put("text", text.take(4000)).toString().toByteArray()) }
            JSONObject(conn.inputStream.bufferedReader().use { it.readText() }).optString("verdict").ifBlank { "AI gave no answer." }
        } catch (e: Exception) {
            "AI check unavailable (home PC not reachable). The rule-based result still applies."
        }
    }
}

/** Web protection through a filtering DNS that refuses to resolve known malicious sites. */
object Web {
    const val DNS = "dns.quad9.net"

    fun dnsName(c: Context): String? {
        val cm = c.getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return null
        return if (lp.isPrivateDnsActive) lp.privateDnsServerName ?: "automatic" else null
    }

    fun enable(): Boolean {
        if (!Shell.granted()) return false
        Shell.run("settings put global private_dns_specifier $DNS; settings put global private_dns_mode hostname")
        Store.log("Web protection on ($DNS)")
        return true
    }
}

object Breach {
    fun email(addr: String): String = try {
        val conn = URL("https://api.xposedornot.com/v1/check-email/" + URLEncoder.encode(addr.trim(), "UTF-8")).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        if (conn.responseCode == 404) "No known breaches for this address."
        else {
            val arr = JSONObject(conn.inputStream.bufferedReader().use { it.readText() }).optJSONArray("breaches")?.optJSONArray(0)
            val names = (0 until (arr?.length() ?: 0)).map { arr!!.getString(it) }
            if (names.isEmpty()) "No known breaches for this address."
            else "Found in ${names.size} breaches: " + names.take(25).joinToString(", ") + (if (names.size > 25) ", and more" else "") + ". Change reused passwords and turn on two-step sign-in."
        }
    } catch (e: Exception) { "Check failed: ${e.message}" }

    /** Only the first five characters of the password's hash leave the phone. */
    fun password(pw: String): String = try {
        val sha = MessageDigest.getInstance("SHA-1").digest(pw.toByteArray()).joinToString("") { "%02X".format(it) }
        val body = URL("https://api.pwnedpasswords.com/range/" + sha.take(5)).readText()
        val n = body.lineSequence().firstOrNull { it.startsWith(sha.drop(5)) }?.substringAfter(':')?.trim()
        if (n == null) "Not found in known breaches." else "Seen $n times in breaches. Stop using this password."
    } catch (e: Exception) { "Check failed: ${e.message}" }
}
