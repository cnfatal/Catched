# APK Signature Verification

> Extracts and compares the running APK's signing certificate fingerprint against a known-good value to detect repackaging or code tampering.

---

## Overview

Every Android APK must be cryptographically signed with a developer's private key before installation. The corresponding certificate is embedded in the APK and recorded by the system's PackageManager at install time. When repackaging tools such as NPatch or LSPatch inject code into an APK, they must re-sign the modified APK with a different key because they do not possess the original developer's private key. APK Signature Verification detects this by extracting the current certificate at runtime via `PackageManager.getPackageInfo()` with `GET_SIGNATURES`, computing its SHA-256 fingerprint, and comparing it against a hardcoded known-good value.

From a defender's perspective, this technique provides a mathematically strong guarantee: it is computationally infeasible to produce a valid signature for a modified APK without the original signing key. This makes signature verification one of the most reliable indicators of APK tampering. However, the check itself can be targeted by attackers who patch out the verification logic or hook the PackageManager API to return the original certificate.

---

## Injection Side

### How Attackers Use This Technique

1. **Obtain target APK** — The attacker extracts the original APK from a device or downloads it from an app store.
2. **Decompile and modify** — Tools like apktool decompile the APK into smali/resources. The attacker modifies code, injects a hook loader (e.g., NPatch/LSPatch runtime), or patches security checks.
3. **Rebuild APK** — The modified APK is reassembled. The original signature is now invalid because the APK content has changed.
4. **Re-sign with attacker's key** — The attacker generates a new signing key and signs the modified APK. Android requires all APKs to be signed, but does not verify who signed them (except for updates to existing installations).
5. **Distribute repackaged APK** — The modified APK is installed on the target device. The signing certificate is now different from the original developer's certificate.

### Artifacts

| Artifact                    | Location                  | Indicator                                                                           |
| --------------------------- | ------------------------- | ----------------------------------------------------------------------------------- |
| Changed signing certificate | PackageManager signatures | SHA-256 fingerprint differs from original developer's certificate                   |
| Modified APK contents       | APK file on disk          | File hashes differ from original distribution                                       |
| NPatch/LSPatch loader       | DEX files inside APK      | Additional classes from the patch framework injected into the APK                   |
| Re-signed META-INF          | APK META-INF directory    | CERT.RSA / CERT.SF files contain the attacker's certificate instead of the original |
| V2/V3 signature block       | APK signing block         | Signature block signed with a different key                                         |

### Injection PoC _(optional)_

```pseudocode
// Repackaging workflow
original_apk = download("com.target.app.apk")
decompiled = apktool.decode(original_apk)

// Inject hook loader
inject_lspatch_runtime(decompiled)
patch_security_checks(decompiled)

// Rebuild and re-sign
modified_apk = apktool.build(decompiled)
attacker_key = generate_signing_key()
signed_apk = apksigner.sign(modified_apk, attacker_key)

// The signed APK now has a different certificate fingerprint
// Original: SHA-256 = "A1B2C3D4..."
// Repackaged: SHA-256 = "X9Y8Z7W6..."
```

### Evasion Techniques

| Evasion                              | Description                                                                                     |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Hook PackageManager.getPackageInfo() | Intercept the API call and return the original certificate bytes instead of the actual ones ★★★ |
| Patch out verification code          | Locate and disable the signature comparison logic in the decompiled APK before re-signing ★★    |
| Runtime certificate injection        | Hook the Signature class constructor to replace certificate data in memory ★★★                  |
| Use same debug keystore              | Not feasible for release apps — the attacker cannot obtain the original private key ★★★★★       |

---

## Detection Side

### Mechanism

The invariant is that the SHA-256 fingerprint of the running APK's signing certificate must match a known-good value that was determined at build time. Android's code signing is based on standard public-key cryptography: modifying any byte of the APK content invalidates the original signature, and producing a new valid signature requires a different private key, which produces a different certificate fingerprint. This is a mathematical guarantee — without the original private key, an attacker cannot produce a matching fingerprint. The SHA-256 hash function is collision-resistant, making it computationally infeasible to find a different certificate that produces the same fingerprint.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Cryptographic binding       | SHA-256 of the certificate is computationally infeasible to forge — the attacker cannot produce a certificate with the same fingerprint without the original private key                               |
| System-backed data source   | The certificate is stored in the system's PackageManager database, which is managed by system_server                                                                                                   |
| Single comparison operation | The check is a simple byte comparison that is hard to partially bypass — it either matches or it doesn't                                                                                               |
| Remaining bypass surface    | Hooking `PackageManager.getPackageInfo()` or `Signature.toByteArray()` to return original certificate data; patching out the check entirely; using JVMTI to redefine the verification class at runtime |

### Detection Strategy

1. **Retrieve signing certificate** — Call `PackageManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES)` to obtain the `PackageInfo` object containing the APK's signing certificates. Access `packageInfo.signatures[0]` for the primary signing certificate.
2. **Compute SHA-256 fingerprint** — Convert the `Signature` object to a byte array via `signature.toByteArray()`. Compute the SHA-256 hash of these bytes using `MessageDigest.getInstance("SHA-256")`.
3. **Compare against known-good value** — Compare the computed fingerprint against a hardcoded expected fingerprint (determined from the release signing key). Use constant-time comparison to prevent timing side-channels.
4. **Handle mismatch** — If the fingerprints do not match, the APK has been re-signed, indicating repackaging or tampering.

### Detection PoC _(optional)_

```pseudocode
// Retrieve the signing certificate from PackageManager
EXPECTED_FINGERPRINT = "a1b2c3d4e5f6..."  // SHA-256 of release certificate

package_info = packageManager.getPackageInfo(
    context.getPackageName(),
    PackageManager.GET_SIGNATURES
)
certificate_bytes = package_info.signatures[0].toByteArray()

// Compute SHA-256 fingerprint
digest = MessageDigest.getInstance("SHA-256")
fingerprint = hex(digest.digest(certificate_bytes))

// Compare with constant-time comparison
if not constant_time_equals(fingerprint, EXPECTED_FINGERPRINT):
    report("APK signature mismatch — possible repackaging",
           "expected", EXPECTED_FINGERPRINT,
           "actual", fingerprint)
```

### False Positive Risks

| Scenario                               | Mitigation                                                                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Debug build signed with debug keystore | Debug and release builds use different signing keys; exclude this check in debug builds or maintain separate expected fingerprints |
| App update changes signing key         | Android's key rotation (APK Signature Scheme v3) allows key changes; use `GET_SIGNING_CERTIFICATES` on API 28+ to handle lineage   |
| Multiple signing certificates          | Apps signed with multiple certificates (v1 + v2 + v3) should verify the primary certificate in the lineage                         |
| Play App Signing re-signs the APK      | Google Play may re-sign uploads with its own key; use the Play-assigned certificate fingerprint as the expected value              |

---

## References

- [Android APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)
- [Android APK Signature Scheme v3 — key rotation](https://source.android.com/docs/security/features/apksigning/v3)
- [PackageManager.GET_SIGNATURES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNATURES)
- [PackageInfo.signingInfo (API 28+)](https://developer.android.com/reference/android/content/pm/PackageInfo#signingInfo)
- [NPatch / LSPatch — repackaging workflow](https://github.com/LSPosed/LSPatch)
