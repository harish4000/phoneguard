# PhoneGuard

Personal Android app that keeps a phone fast and safe. Built for one family, sideloaded, no analytics.

## What it does

**Performance** (needs Shizuku)
- Smart mode: learns which apps heat the phone and adapts refresh rate, battery saver and game mode to what is on screen.
- Thermal guard, charge guard, cache cleanup, background-hog detector, storage health, reversible disabling of unused preinstalled apps.

**Protection** (works without Shizuku)
- Antivirus scan of every installed and preinstalled app, every file in shared storage that can carry code, and every running process (process scan needs Shizuku). Runs daily, on every app install, and on files as they arrive in download folders.
- Alert the moment any app gains screen control, notification access or device admin.
- Automatic scam alerts on incoming texts and chat messages, checked on the phone only.
- Protection score, weekly report, weekly breach monitoring, unsafe Wi-Fi warning.
- Web protection through filtering DNS (Quad9).
- Scam checker for messages and links: on-phone rules, plus an optional second opinion from the family's own model over Tailscale.
- Spam call blocking through Android's call screening role.
- Email and password breach check.
- Security audit of the phone's own defences.

Play Protect stays on as the first layer. PhoneGuard is the second.

## How it updates

| What | How | When |
|---|---|---|
| Threat definitions | `.github/workflows/defs.yml` builds them from public feeds and publishes them to the `defs` release | Daily |
| The app | `.github/workflows/build.yml` builds and signs every push, and publishes a release when `main` carries a new version. Phones install it by themselves while the screen is off | On each version bump |

Phones check both daily. An app update installs only if its checksum matches and it is signed with the same key.

To ship a new version: raise `versionCode` and `versionName` in `app/build.gradle.kts` and push to `main`.

## Shared family lists

Edit these files and push. Every phone picks up the change with the next definitions update.

- `data/calls.txt`: spam numbers and prefixes to block.
- `data/hosts-extra.txt`: extra domains to flag.
- `data/hosts-allow.txt`: domains that must never be flagged.
- `data/hashes-extra.txt`: extra malware hashes.
- `data/pkgs-extra.txt`: extra package names to flag.
- `data/benign-messages.txt`: ordinary messages that no scam pattern may match.

## Data sources

- Phishing and malware domains: [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) and [OpenPhish](https://openphish.com).
- Stalkerware package names, certificates and hashes: [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators), CC BY 4.0.
- Safe-to-disable preinstalled apps: [Universal Android Debloater](https://github.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation) list, GPL-3.0, entries rated Recommended.
- Malware hashes: [MalwareBazaar](https://bazaar.abuse.ch), when the key is set.
- Breach data: [XposedOrNot](https://xposedornot.com) and [Pwned Passwords](https://haveibeenpwned.com/Passwords).

## Repository secrets

- `KEYSTORE_B64`, `KEYSTORE_PASSWORD`: the signing key. Required.
- `ABUSECH_KEY`: free abuse.ch Auth-Key. Optional. Without it the malware hash list stays empty and the scan relies on behaviour checks.

## Setting up a phone

Protection works as soon as the app is installed. Performance control (profiles, smart mode, cool-down, one-tap web protection, process scan, background-hog detector) needs one of these, once:

- **PC and cable:** turn on USB debugging on the phone, plug it in, and run `tools/setup-phone.ps1`. It installs the app, grants the permanent permissions, and turns on scam alerts, call blocking and web protection.
- **Shizuku:** start it once and tap Grant access in PhoneGuard. The app grants itself the same permanent permissions.

Either way the permissions survive restarts and updates, so the step is never repeated. Stopping, blocking or disabling another app, and scanning inside `Android/data`, still need Shizuku running.

## Home AI (optional)

The family PC runs a local model through Ollama. `tools/setup-home-ai.ps1` sets up both uses of it:

- **Nightly rule writer** (`tools/ai_rules.py`, 02:30): the model reads the day's public phishing links and fraud alerts and proposes new scam phrase patterns. A pattern is published only if it passes `tools/rulecheck.py`, matches its own example, and matches none of the ordinary messages in `data/benign-messages.txt`. Accepted patterns go to `data/scam-rules.txt` and ship with the daily definitions. On the phone each AI pattern adds a small score and their total is capped, so they cannot raise an alert without the built-in rules agreeing. If a harmless message is flagged, add it to `data/benign-messages.txt`.
- **Live second opinion** (`tools/glm-relay.py`): phones ask the model about a suspicious message or app over Tailscale. Enter the PC's Tailscale address in PhoneGuard, Scams tab. Each phone needs the Tailscale app signed in to the same account.

If the PC is off, phones keep working on the built-in rules and the last published patterns.

## Local build

`release.ps1` builds on Windows with the toolchain under `D:\android-toolchain`. GitHub Actions is the normal path.
