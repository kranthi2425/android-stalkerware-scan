# Android Stalkerware Scan

A free, open-source, read-only Android triage tool for defenders, students, incident responders, and people checking a phone they are authorized to examine. It uses Android Debug Bridge (ADB), inventories user-visible package state, compares package names with a public stalkerware IOC list, and reports risky combinations of special access and permissions in plain language.

An iPhone module, `ios_scanner.py`, does the same kind of plain-language triage on a local iTunes/Finder backup. See [iPhone (iOS) backup scan](#iphone-ios-backup-scan).

> [!WARNING]
> **Finding or removing monitoring software can alert an abuser and can increase danger.** Do not uninstall, disable, revoke permissions, reset the phone, or confront anyone until you have a safety plan. Use a safer device to contact a trusted advocate or local support service. Deleting an app may also delete evidence. See the [Coalition Against Stalkerware survivor guidance](https://stopstalkerware.org/information-for-survivors/).

## What it checks

- Exact installed package-name matches against [Echap's public stalkerware/watchware IOC collection](https://github.com/AssoEchap/stalkerware-indicators), a source indexed by the [MVT indicators project](https://github.com/mvt-project/mvt-indicators)
- Enabled Accessibility services
- Active Device Administrator components
- Enabled notification-listener access
- Usage-access grants (`GET_USAGE_STATS`) for candidate packages
- Sensitive permission clusters, including SMS, call logs, microphone, camera, location, contacts, phone state, and storage
- Package installer source, with unknown/package-installer sources marked as possible sideloads
- Generic system-like package names as a weak heuristic
- Two package-verifier settings as partial Play Protect signals, plus a manual verification reminder

The current pinned IOC snapshot contains **611 unique Android package names across 131 application records**. Tests assert that every package in the snapshot produces an exact IOC finding.

## Requirements

- Windows, macOS, or Linux computer
- Python 3.9+
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools) (`adb` on `PATH`)
- A phone you own or are authorized to examine
- No root, paid API, cloud account, or special hardware

## Quick start

1. On the phone, enable Developer options and USB debugging. If safety permits, connect it by USB, unlock it, and accept the RSA debugging prompt.
2. Verify the connection:

```bash
adb devices
```

3. Run the scan from this repository:

```bash
python3 scanner.py
```

For multiple devices:

```bash
python3 scanner.py --serial DEVICE_SERIAL
```

The tool writes:

- `report.txt` - plain-language triage report
- `report.json` - structured report for labs or further review

It does not change anything on the phone. A scan may take several minutes because package details are checked individually.

## Read the result

- **CRITICAL** usually means an exact public IOC package-name match.
- **HIGH/MEDIUM** means a strong cluster of risky signals, not proof of stalkerware.
- **LOW** means a weak signal that needs context. Legitimate accessibility tools, device-management apps, antivirus, parental-control tools, and OEM components can look risky.
- **No findings does not mean the phone is clean.** Renamed packages, zero-day spyware, removed traces, work-profile apps, OEM restrictions, and tools that evade ADB-visible state can be missed.

## Play Protect limitation

Android does not expose every Play Protect UI state consistently through public ADB interfaces. The scanner reports available package-verifier settings, but these are not a conclusive Play Protect status. Confirm manually in **Play Store > profile icon > Play Protect > Settings**. Google documents that Play Protect checks Store and other-source apps and can warn, disable, or remove harmful apps: [Google Play Help](https://support.google.com/googleplay/answer/2812853).

## Evidence preservation before removal

If it is safe to continue:

1. Save `report.txt` and `report.json` somewhere the suspected monitor cannot access.
2. Capture a standard Android bugreport before changing the phone:

```bash
adb bugreport evidence/bugreport.zip
```

3. Photograph relevant app, Accessibility, Device Admin, notification access, and usage access screens with a safer device.
4. Record date/time, phone model, Android version, who handled the phone, and each action taken.
5. Hash exported evidence where possible:

```bash
sha256sum evidence/* > evidence/SHA256SUMS.txt
```

6. Seek help from a qualified forensic examiner, survivor-support organization, or law enforcement if legal action is being considered. Keep the original phone unchanged when possible.

Do not upload a victim's bugreport publicly. It can contain sensitive personal data.

## Detection design and limits

This is a triage scanner, not a forensic verdict. Scores combine independent signals so that one generic name or one sideload does not create a high-confidence claim. Exact public IOC matches are weighted strongly. Multiple special-access grants and broad surveillance-relevant permissions are weighted as a suspicious behavioral cluster.

ADB's [`dumpsys`](https://developer.android.com/tools/dumpsys) and package-manager output vary across Android versions and vendors. Some fields may be absent or formatted differently. The scanner only uses read operations, but enabling USB debugging changes device settings and may itself be visible to a person monitoring the phone.

For deeper forensic work, use [Amnesty International's Mobile Verification Toolkit](https://github.com/mvt-project/mvt). MVT warns that public IOCs are insufficient to declare a device clean and that recent or non-public traces may be missed. Kaspersky's [TinyCheck](https://github.com/KasperskyLab/TinyCheck) is a separate network-observation option, but it normally uses dedicated hardware; this project focuses on the zero-hardware ADB path.

## IOC provenance and updates

`iocs/packages.json` is a pinned derivative snapshot from:

- Echap, Stalkerware Indicators of Compromise: https://github.com/AssoEchap/stalkerware-indicators
- MVT IOC documentation and public-index context: https://github.com/mvt-project/mvt/blob/main/docs/iocs.md
- Amnesty International public investigations repository: https://github.com/AmnestyTech/investigations

`iocs/network.json` is a pinned snapshot of Echap's `generated/network.csv` (CC-BY 4.0), recorded with the upstream commit it came from. Rebuild it after reviewing upstream changes:

```bash
python3 update_network_iocs.py --ref <upstream-commit-sha>
```

`iocs/ios_jailbreak.json` is versioned in this repo and lists its public sources.

IOC lists age quickly. Review upstream changes before a high-stakes examination. Package-name matching is only one detection layer; certificate hashes require APK extraction and are not checked by the Android scanner. Network indicators are used by the iOS scanner against backup data.

## iPhone (iOS) backup scan

`ios_scanner.py` is a separate, laptop-based triage module for iPhones. iOS does not allow an on-phone scanner like the Android ADB path, so it reads a local iTunes/Finder backup instead. It uses only the Python 3.9+ standard library (`sqlite3`, `plistlib`) for unencrypted backups and filesystem dumps, costs nothing, and never writes to the phone, the backup, or the dump. Encrypted backups need one optional free package (see below).

> [!WARNING]
> The same safety rule applies: **do not delete profiles or apps, reset the phone, or confront anyone before you have a safety plan.** Making a backup on a computer the suspected abuser can access may also be risky.

### What it checks

1. **Jailbreak artifacts.** Classic iPhone stalkerware needs a jailbroken phone. The scanner matches the backup's `Manifest.db` file list and app list against `iocs/ios_jailbreak.json`, a versioned list of jailbreak apps, package managers, permanent sideloaders (TrollStore), and jailbreak file paths compiled for this project from public jailbreak project pages and published detection references. One tool is **HIGH**; traces of two or more separate tools are **CRITICAL**.
2. **Configuration profiles and MDM enrollment.** Reads installed profile records, `MDM.plist`, and supervision/automated-enrollment records from the configuration-profiles container. Profiles with MDM, VPN, global proxy, root certificate, content-filter, or DNS payloads are **HIGH**; other profiles are **MEDIUM**. Work, school, and carrier profiles are common and legitimate, so the report says so.
3. **Network IOC sweep.** Matches Echap's public stalkerware network indicators (domains, subdomains, IPv4 addresses, and URLs) against Safari history and SMS/iMessage text in the backup. A match is **CRITICAL**, with dates and direction so the user can tell an install link from their own research.
4. **Installed apps and dual-use apps.** Lists every app in the backup (report section `APP INVENTORY`, JSON `app_inventory`) and matches bundle IDs against `iocs/ios_dual_use_apps.json`: a versioned, curated list of App Store location-sharing, parental-control, couple-tracker, anti-theft/remote-access, and "phone monitoring" apps. Bundle IDs, names, and developers come from Apple's public iTunes Lookup API (each entry keeps its lookup URL); categories and roles (watched phone, watching phone, both) were assigned from each app's own App Store description. Matches are always **MEDIUM** and labeled by category. They are **not a verdict**: these apps have legitimate uses and are usually installed knowingly ([Chatterjee et al., IEEE S&P 2018](https://nixdell.com/papers/spyware.pdf) found most apps used for partner surveillance are dual-use). Apps whose brand or servers also appear in the Echap indicators are marked with that family.
5. **Enterprise and provisioning-profile traces.** Reads any `.mobileprovision` file in the source (and, in filesystem-dump mode, each app's `embedded.mobileprovision`) and classifies it as enterprise/in-house (`ProvisionsAllDevices`), ad hoc, or development ([Apple TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)). Enterprise signing lets apps install outside the App Store and has been used to spread iPhone malware ([Unit 42 on WireLurker/provisioning abuse](https://unit42.paloaltonetworks.com/protecting-users-ios-app-provisioning-profile-abuse/)). Alone these are **MEDIUM**; alongside any other finding in the same scan they become **HIGH**. Standard backups usually do not include provisioning profiles, so this check mostly matters with `--fs-dump`.

Every iOS report also includes an **"Escalate to MVT for deep analysis"** section with the exact `mvt-ios` commands for this source ([MVT backup docs](https://docs.mvt.re/en/latest/ios/backup/check/), [filesystem docs](https://docs.mvt.re/en/latest/ios/filesystem/check/)). It is marked recommended when anything HIGH or CRITICAL was found.

Every iOS report also includes the Apple Safety Check / account-hygiene checklist and the "clean scan does not mean clean" caveat, because much iPhone spying (a known Apple Account password, shared accounts, Find My or family sharing, iCloud access) leaves no trace in a backup.

### Make a backup

1. Connect the iPhone to a Mac (Finder, macOS 10.15+) or a PC (Apple Devices app or iTunes) and choose **Back up all of the data on your iPhone to this computer** ([Apple: back up with the Finder](https://support.apple.com/en-us/108796)).
2. Encrypted or not both work. Apple notes that unencrypted backups can leave out website history, call history, saved passwords, Wi-Fi settings, and Health data ([Apple: encrypted backups](https://support.apple.com/en-us/108353)), so an **encrypted** backup gives better coverage (MVT recommends it too). You need the backup password set in Finder/iTunes (not the phone passcode).
3. Find the backup folder ([Apple: locate backups](https://support.apple.com/en-us/108809)):
   - macOS: `~/Library/Application Support/MobileSync/Backup/`
   - Windows: `%USERPROFILE%\Apple\MobileSync\Backup\` or `%APPDATA%\Apple Computer\MobileSync\Backup\`

### Run it

```bash
python3 ios_scanner.py --backup "~/Library/Application Support/MobileSync/Backup/<DEVICE-ID>"
```

If the folder you pass holds exactly one backup, the scanner picks it.

**Encrypted backups.** Python's standard library has no AES, so decrypting needs one optional free package. Install either one:

```bash
pip install cryptography      # or: pip install pycryptodome
```

The scanner asks for the backup password (typing is hidden), or reads it from `IOS_BACKUP_PASSWORD` (`--password-env` picks another variable). Nothing else changes: unencrypted backups and dumps never import the package. The few files the scan reads are decrypted into a private temporary folder that is deleted when the scan ends; the password and keys are never written to the report. If the backup's `Manifest.db` is already readable (a copy decrypted with another tool), it is scanned as is. Key handling follows the public iOS 10.2+ backup format (PBKDF2 keybag, RFC 3394 key wrap, AES-CBC), as documented by [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt).

**Full filesystem dump (optional, advanced).**

```bash
python3 ios_scanner.py --fs-dump /path/to/extracted-dump
```

Point it at the folder that contains `private/var` (or a dump of `/private` alone). It reads a targeted set of paths: app bundles, provisioning profiles, configuration profiles, Safari history, messages, and jailbreak paths. Getting a dump usually means jailbreaking the phone first ([MVT: dumping the filesystem](https://docs.mvt.re/en/latest/ios/filesystem/dump/)), so jailbreak findings may come from the acquisition itself. This is examiner territory. The tool writes:

- `report_ios.txt` - plain-language triage report, safety warning first
- `report_ios.json` - structured report with the same severity ladder and top-level shape as `report.json` (`generated_at`, `device`, `package_count`, `findings`, each finding with `score`, `severity`, `reasons`), plus `platform: "ios"`, `checks`, `account_hygiene`, and `clean_scan_caveat`

The report lists which checks ran and how much data each saw, so "no findings" can be read against what was actually examined.

### iOS limits

- Standard backups do not contain the system partition, so most jailbreak files show up only as app data, preferences, or leftovers.
- Network matching covers Safari history and message text in the backup only, not live traffic or third-party apps.
- Dual-use app matching only knows the curated App Store apps in `iocs/ios_dual_use_apps.json`. Renamed, new, or enterprise-signed apps are missed, and a match is a question to ask, not proof.
- Encrypted-backup support is tested against synthetic backups built to the documented format (plus the RFC 3394 test vectors), not yet against a real Apple-made encrypted backup.
- Filesystem-dump mode is tested against synthetic dump layouts only.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite checks all pinned public IOC package names, a high-risk special-access combination, and a benign control. The iOS tests build synthetic backups and check every pinned network indicator, subdomain matching without false positives on shared hosts, jailbreak and profile/MDM detection, Safari and message IOC hits, report structure, and that the backup is left unchanged. Phase 2 tests (`tests/test_ios_phase2.py`) cover RFC 3394 key-wrap vectors and full synthetic encrypted backups on every installed AES backend, wrong/missing password, a clear error when no AES package is installed, that unencrypted scans never import one, the dual-use list's sources and MEDIUM-only scoring, app inventory, provisioning-profile types and HIGH corroboration, filesystem-dump mode, and the MVT handoff. Encrypted-backup tests are skipped if neither `cryptography` nor `pycryptodome` is installed.

## Ethical use

Use only on devices you own or have explicit permission to examine. Do not use this project to monitor another person, bypass access controls, remove evidence, or retaliate. The tool is designed for defensive detection and education.

## License

MIT for this project's code. IOC data is attributed to its upstream source; review upstream terms before redistributing modified IOC datasets.
