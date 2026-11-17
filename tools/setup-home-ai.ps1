# Sets up the home AI on the family PC. Safe to run again at any time.
#   1. A nightly task that lets the local model write new scam patterns and publish them (tools\ai_rules.py).
#   2. A relay that answers the phones' second-opinion requests (tools\glm-relay.py), started at logon.
#   3. Tailscale Serve, so only the family's own phones can reach the relay.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python).Source }
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Write-Host "1. Nightly AI rule writer (02:30 every night)..."
$a = New-ScheduledTaskAction -Execute $py -Argument "`"$root\tools\ai_rules.py`"" -WorkingDirectory $root
Register-ScheduledTask -TaskName "PhoneGuard AI rules" -Action $a -Trigger (New-ScheduledTaskTrigger -Daily -At "02:30") -Settings $settings -Force | Out-Null

Write-Host "2. Home AI relay (starts at logon)..."
$a = New-ScheduledTaskAction -Execute $py -Argument "`"$root\tools\glm-relay.py`"" -WorkingDirectory $root
$relaySettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "PhoneGuard home AI relay" -Action $a -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME) -Settings $relaySettings -Force | Out-Null
Stop-ScheduledTask -TaskName "PhoneGuard home AI relay" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "PhoneGuard home AI relay"
Start-Sleep 3
try {
    $h = Invoke-RestMethod "http://127.0.0.1:8787/health" -TimeoutSec 5
    Write-Host "   Relay is up, model: $($h.model)"
} catch { Write-Host "   Relay did not start. Check that Python and Ollama are installed." }

Write-Host "3. Tailscale..."
$ts = $null
try { $ts = (tailscale status --json 2>$null | Out-String | ConvertFrom-Json) } catch { }
if (-not $ts -or $ts.BackendState -ne "Running") {
    Write-Host "   Tailscale is not signed in on this PC. Sign in from the Tailscale tray icon, then run this script again."
    Write-Host "   Until then, phones cannot reach the home AI. The nightly rule writer works without it."
} else {
    tailscale serve --bg 8787 2>&1 | Out-Null
    $name = $ts.Self.DNSName.TrimEnd(".")
    Write-Host "   Published to your Tailscale network only."
    Write-Host ""
    Write-Host "   Home AI address for the phones:  https://$name"
    Write-Host "   Enter it in PhoneGuard, Scams tab, 'Home AI for second opinions'."
    Write-Host "   Each phone needs the Tailscale app, signed in to the same account."
}
