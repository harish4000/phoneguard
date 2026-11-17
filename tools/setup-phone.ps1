# One-time PhoneGuard setup for a phone, run from the family PC over a USB cable.
# It installs the latest PhoneGuard, then grants the permanent permissions that let it manage
# performance without Shizuku. Nothing here needs repeating after a restart or an app update.
#
# On the phone first: Settings > About phone > tap "Build number" 7 times,
# then Settings > System > Developer options > turn on "USB debugging".
# Plug the phone in, unlock it, and tap "Allow" on the USB debugging prompt.
#
# Usage:   .\tools\setup-phone.ps1            (one phone plugged in)
#          .\tools\setup-phone.ps1 -Serial X  (several phones: pick one from "adb devices")
#          .\tools\setup-phone.ps1 -PermissionsOnly  (install and grant only; leave scam alerts, call blocking and DNS alone)
param([string]$Serial = "", [switch]$PermissionsOnly)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$pkg = "com.harish.phoneguard"
$adb = "D:\android-toolchain\sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) { $adb = "adb" }

$found = @(& $adb devices | Select-String "\tdevice$" | ForEach-Object { ($_ -split "\t")[0] })
if (-not $Serial) {
    if ($found.Count -eq 0) { Write-Host "No phone found. Check the cable, unlock the phone and allow USB debugging."; exit 1 }
    if ($found.Count -gt 1) { Write-Host ("Several phones found: " + ($found -join ", ") + ". Run again with -Serial <one of them>."); exit 1 }
    $Serial = $found[0]
}
function Sh([string]$cmd) { & $adb -s $Serial shell $cmd 2>&1 | Out-String }

$model = (Sh "getprop ro.product.model").Trim()
Write-Host "Setting up: $model ($Serial)"

Write-Host "1. Installing the latest PhoneGuard..."
$apk = Join-Path $env:TEMP "phoneguard-latest.apk"
Invoke-WebRequest "https://github.com/harish4000/phoneguard/releases/latest/download/phoneguard.apk" -OutFile $apk -UseBasicParsing
$r = (& $adb -s $Serial install -r $apk 2>&1 | Out-String).Trim()
Write-Host "   $r"
if ($r -notmatch "Success") { Write-Host "Install failed. Stopping."; exit 1 }

Write-Host "2. Granting permanent permissions..."
foreach ($p in "WRITE_SECURE_SETTINGS", "DUMP", "PACKAGE_USAGE_STATS", "BATTERY_STATS", "READ_CONTACTS", "POST_NOTIFICATIONS") {
    Sh "pm grant $pkg android.permission.$p" | Out-Null
}
foreach ($op in "GET_USAGE_STATS", "WRITE_SETTINGS", "MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES") {
    Sh "appops set $pkg $op allow" | Out-Null
}
Sh "dumpsys deviceidle whitelist +$pkg" | Out-Null

if ($PermissionsOnly) {
    Write-Host "3. Skipped scam alerts, call blocking and web protection (-PermissionsOnly)."
} else {
    Write-Host "3. Turning on scam alerts and spam call blocking..."
    Sh "cmd notification allow_listener $pkg/$pkg.ScamWatch" | Out-Null
    Sh "cmd role add-role-holder android.app.role.CALL_SCREENING $pkg" | Out-Null

    Write-Host "4. Web protection..."
    $mode = (Sh "settings get global private_dns_mode").Trim()
    if ($mode -eq "hostname") {
        Write-Host ("   Private DNS is already set to " + (Sh "settings get global private_dns_specifier").Trim() + ". Left as it is.")
    } else {
        Sh "settings put global private_dns_specifier dns.quad9.net" | Out-Null
        Sh "settings put global private_dns_mode hostname" | Out-Null
        Write-Host "   Private DNS set to dns.quad9.net"
    }
}

Sh "am start -n $pkg/.MainActivity" | Out-Null
Start-Sleep 2

Write-Host ""
Write-Host "Result:"
$dump = Sh "dumpsys package $pkg"
foreach ($p in "WRITE_SECURE_SETTINGS", "DUMP", "READ_CONTACTS") {
    $ok = $dump -match "android.permission.${p}: granted=true"
    Write-Host ("   {0,-24} {1}" -f $p, $(if ($ok) { "granted" } else { "NOT granted" }))
}
$role = (Sh "cmd role get-role-holders android.app.role.CALL_SCREENING").Trim()
Write-Host ("   {0,-24} {1}" -f "Call blocking", $(if ($role -match $pkg) { "on" } else { "NOT on (turn it on in the Scams tab)" }))
$ver = ([regex]::Match($dump, "versionName=(\S+)")).Groups[1].Value
Write-Host "   Version                  $ver"
Write-Host ""
Write-Host "Done. On the phone: open the Scams tab, enter the phone's own number and the owner's email."
Write-Host "USB debugging can be turned off again now."
if ($dump -notmatch "android.permission.WRITE_SECURE_SETTINGS: granted=true") {
    Write-Host "WRITE_SECURE_SETTINGS was refused. On Xiaomi, Oppo, Realme and Vivo phones, also turn on"
    Write-Host "'USB debugging (Security settings)' in Developer options, then run this again."
}
