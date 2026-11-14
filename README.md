# DeadZone Toolbox Database

The authoritative public data source of the DeadZone Toolbox.

Every production fetch of the toolbox points at **this** repository. The
reference repository `zuri1503/Toolbox-Database` is a reference for the
formats and the feature coverage; it is never the production source.

## The documents

| Document | Shape | Consumer | Secret |
|---|---|---|---|
| `device-props.json` | `{ "devices": [ { name, BRAND, DEVICE, MANUFACTURER, MODEL, FINGERPRINT, PRODUCT } ] }` | Device profile selector (`DeviceModelsRepository`) | no |
| `app-props.json` | `{ "<package>": { BRAND, DEVICE, MANUFACTURER, MODEL, FINGERPRINT, PRODUCT } }` — 65 entries | Per-application identity profile manager (`GamePropsRepository`) | no |
| `pif-props.json` | flat object with 13 identity fields | PIF profile manager (`PifRepository`) | no |
| `blacklist.json` | array of package names | Blacklist policy manager (`BlacklistCache`) | no |
| `target-list.txt` | one package per line, `#` suffix for the mode | Per-app target configuration (`TargetsRepository`) | no |
| `block-serial.txt` | one hexadecimal serial per line | Serial-policy metadata (`SerialPolicyRepository`) | no |
| `white-serial.txt` | one hexadecimal serial per line | Serial-policy metadata (`SerialPolicyRepository`) | no |
| `keybox.xml` | KeyMaster XML with private key material | **Local import only** — never fetched | **yes** |

### The thirteen fields of the PIF document

```
MANUFACTURER  BRAND  MODEL  DEVICE  PRODUCT  FINGERPRINT
RELEASE  ID  INCREMENTAL  TYPE  TAGS  SECURITY_PATCH  DEVICE_INITIAL_SDK_INT
```

### The serial policies

`block-serial.txt` and `white-serial.txt` are **metadata**. They describe
which serials the owner wants to be blocked and which ones are allowed.
They are applied by the toolbox itself and never by the hook layer of the
platform, and they never replace a real value of the platform.

The two lists must not overlap: a serial is either blocked or allowed.

### What is deliberately absent

The reference repository publishes `native-props.prop`, which carries the
legacy identifiers of the project that the reference was built on
(`ro.boot.projectryu`, `ro.boot.author=ryu`). DeadZone does not publish
those identifiers, and `tools/build_catalogue.py` refuses a catalogue that
carries them. `tools/test_catalogue.py` proves it.

## The signed manifests

```
manifests/stable.json
manifests/stable.json.sig

manifests/testing.json
manifests/testing.json.sig

publishing/pinned-public-key.txt
publishing/pinned-public-key.hex
```

The manifests are signed with Ed25519. The public key is pinned inside the
ROM and inside the application; a manifest that does not verify against it
is refused whatever its digests say.

### Schema version 2

Version 1 declared only the profiles of the Play Integrity Fix. Version 2
adds the `documents` array:

```json
{
  "schema_version": 2,
  "channel": "stable",
  "revision": "…",
  "profiles": [ … ],
  "documents": [
    { "kind": "devices", "path": "device-props.json", "sha256": "…", "size": 12782, "summary": "…" }
  ]
}
```

The array is additive, so a client of version 1 keeps working. The
`revision` now covers the digests of the profiles **and** the digests of
the public documents.

The document of the keybox is **never** declared in a manifest: a document
that can replace a private key is a document that can read one.

## The tooling

```bash
# Regenerate the catalogue and re-sign the manifests.
python3 tools/build_catalogue.py

# Prove that the committed catalogue is the one the signing key produces.
python3 tools/build_catalogue.py --check

# Run the tests of the catalogue.
python3 tools/test_catalogue.py
```

The signing key is **not** in this repository. It lives in the private
configuration of the operator:

```
~/.config/deadzone/publishing/deadzone_ed25519_private.key
```

The environment variable `DEADZONE_PUBLISHING_KEY` overrides the path.
