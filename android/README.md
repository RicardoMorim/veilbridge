# VeilBridge Android Lab

This directory is an Android Studio test harness for the experimental
VeilBridge v1 carrier envelope. It keeps private text inside the lab, encrypts
it locally, and sends only a `vb1.…` text payload through Android's share sheet.

> [!WARNING]
> This is not a production messenger or a finished secure-session protocol. It
> uses a manually shared test key and has not been independently audited. Do not
> use it for sensitive conversations.

## Prerequisites

- Android Studio Quail 2 (2026.1.2) or another version that supports Android
  Gradle Plugin 9.3.
- JDK 17 selected for Gradle.
- Android SDK Platform 36 and Android SDK Build-Tools 36.0.0.
- Two Android 8.0 (API 26) or newer devices or emulators for the full test.

The repository includes the Gradle 9.5.1 wrapper and verifies its distribution
checksum.

## Open and run

1. Clone or download the repository.
2. In Android Studio, choose **Open** and select the repository's `android`
   directory, not the repository root.
3. If prompted, trust the project.
4. Open **Settings > Build, Execution, Deployment > Build Tools > Gradle** and
   select JDK 17.
5. Open **Tools > SDK Manager** and install Android SDK Platform 36 and Android
   SDK Build-Tools 36.0.0.
6. Allow Gradle sync to finish.
7. Create two API 26+ virtual devices in **Tools > Device Manager**, or connect
   two physical devices with USB debugging enabled.
8. Select the `app` run configuration and run it on both devices.

The app deliberately requests no Internet permission. Its key exists only in
the visible field for the current app process and is not persisted.

## Two-device success test

Use a harmless, unique test sentence such as
`orange telescope 742 — device A`.

1. On device A, tap **Generate**, then **Copy key**.
2. Transfer that test key to device B separately and tap **Paste** beside the
   key field. For emulators, the host clipboard is sufficient for this lab.
3. On device A, enter the test sentence under **Private text** and tap
   **Encrypt into carrier text**.
4. Confirm the carrier begins with `vb1.` and does not contain the test
   sentence.
5. Tap **Share via…** and send the carrier through any text-capable app, or use
   **Copy** and move it to device B.
6. On device B, share the received text to **VeilBridge Lab**, or paste it into
   **Carrier payload**.
7. Tap **Decrypt locally**.
8. Confirm the decrypted result exactly matches the original sentence.

Passing this test demonstrates that the Android implementation can encrypt and
authenticate a carrier payload locally and that the host app only needs to
transport opaque text.

## Negative tests

Run both checks before considering a build usable:

1. Change device B to a newly generated key and decrypt the original carrier.
   The app must report `authentication_failed` and reveal no plaintext.
2. Restore the matching key, change one character near the end of the `vb1.`
   payload, and decrypt. The app must again report `authentication_failed`.

Also share ordinary text *to* VeilBridge Lab. It should appear only in the
private composer, where you must tap **Encrypt** before sharing it onward.

## Command-line verification

From this directory:

```bash
./gradlew :protocol:test :app:lintDebug :app:assembleDebug --no-daemon
```

The debug APK is written to:

```text
app/build/outputs/apk/debug/app-debug.apk
```

GitHub Actions runs the same tests and publishes the APK as the
`veilbridge-android-debug` workflow artifact.

## What this does not prove

- It does not provide invite-free discovery, identity authentication, forward
  secrecy, post-compromise security, groups, or multi-device recovery.
- It cannot protect text typed first into a host messenger, a malicious
  keyboard, a compromised operating system, screenshots, notifications, or a
  recipient who copies the decrypted text.
- It does not hide sender, recipient, timing, IP address, or message length
  metadata.
- It does not guarantee compatibility with future platform policies or
  legislation.

For the intended system boundary, see
[`../docs/architecture.md`](../docs/architecture.md) and
[`../docs/threat-model.md`](../docs/threat-model.md).
