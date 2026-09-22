# Android Stalkerware Scan

A free, open-source, read-only Android triage tool for defenders, students, incident responders, and people checking a phone they are authorized to examine. It uses Android Debug Bridge (ADB), inventories user-visible package state, compares package names with a public stalkerware IOC list, and reports risky combinations of special access and permissions in plain language.

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

IOC lists age quickly. Review upstream changes before a high-stakes examination. Package-name matching is only one detection layer; certificate hashes and network indicators require APK extraction or network capture and are not checked in this first version.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite checks all pinned public IOC package names, a high-risk special-access combination, and a benign control.

## Ethical use

Use only on devices you own or have explicit permission to examine. Do not use this project to monitor another person, bypass access controls, remove evidence, or retaliate. The tool is designed for defensive detection and education.

## License

MIT for this project's code. IOC data is attributed to its upstream source; review upstream terms before redistributing modified IOC datasets.
