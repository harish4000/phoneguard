# Builds the signed APK and update.json into dist\. With -Publish, also creates the GitHub release that phones update from.
# Before each new version: raise versionCode and versionName in app\build.gradle.kts.
param([switch]$Publish)
$t='D:\android-toolchain'; $p=$PSScriptRoot
$env:JAVA_HOME="$t\jdk"; $env:ANDROID_HOME="$t\sdk"; $env:GRADLE_USER_HOME="$t\gradle-home"; $env:Path="$t\jdk\bin;$env:Path"
Set-Location $p
Remove-Item "$p\build.done" -ErrorAction SilentlyContinue
cmd /c "`"$t\gradle-8.9\bin\gradle.bat`" --no-daemon --console=plain assembleRelease > `"$p\build.log`" 2>&1"
$code=$LASTEXITCODE
if($code -eq 0){
  $g=Get-Content "$p\app\build.gradle.kts" -Raw
  $vc=[regex]::Match($g,'versionCode = (\d+)').Groups[1].Value
  $vn=[regex]::Match($g,'versionName = "([^"]+)"').Groups[1].Value
  New-Item -ItemType Directory -Force "$p\dist" | Out-Null
  Copy-Item "$p\app\build\outputs\apk\release\app-release.apk" "$p\dist\phoneguard.apk" -Force
  $sha=(Get-FileHash "$p\dist\phoneguard.apk" -Algorithm SHA256).Hash.ToLower()
  $json='{"versionCode":'+$vc+',"versionName":"'+$vn+'","url":"https://github.com/harish4000/phoneguard/releases/download/v'+$vn+'/phoneguard.apk","sha256":"'+$sha+'"}'
  [IO.File]::WriteAllText("$p\dist\update.json",$json)
  if($Publish){ gh release create "v$vn" "$p\dist\phoneguard.apk" "$p\dist\update.json" --title "v$vn" --notes "PhoneGuard $vn" >> "$p\build.log" 2>&1; $code=$LASTEXITCODE }
}
"EXIT $code" | Set-Content "$p\build.done"