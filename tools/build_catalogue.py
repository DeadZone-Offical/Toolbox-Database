#!/usr/bin/env python3
"""Build the signed catalogue of DeadZone.

The script generates the manifests of the two channels, the profiles of
the Play Integrity Fix and the signature of every manifest.

The signing key is **not** stored in the repository. It lives in the
private configuration of the operator:

    ~/.config/deadzone/publishing/deadzone_ed25519_private.key

The public key is stored in the repository, in
`publishing/pinned-public-key.txt`, and it is the key that the native
core of DeadZone pins. A manifest that is signed by another key is
refused by the updater.

Usage:

    python3 tools/build_catalogue.py [--check]

The `--check` mode regenerates the catalogue in a temporary directory
and compares it with the one of the repository. It is the mode that the
continuous integration runs, and it proves that the committed catalogue
is exactly the one that the signing key produces.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REPO = pathlib.Path(__file__).resolve().parent.parent
KEY_PATH = pathlib.Path(
    os.environ.get(
        "DEADZONE_PUBLISHING_KEY",
        pathlib.Path.home() / ".config/deadzone/publishing/deadzone_ed25519_private.key",
    )
)

#: The version of the schema of a manifest.
#:
#: The version 1 carried only the profiles of the Play Integrity Fix.
#: The version 2 adds the `documents` array, which declares the digest of
#: every **public** document of the catalogue. The array is additive: a
#: client of the version 1 keeps working with a manifest of the version 2,
#: because it ignores the members that it does not know.
MANIFEST_SCHEMA_VERSION = 2

#: The version of the schema that a client of the version 1 understands.
#:
#: The updater of the native core accepts a manifest of this version or
#: of the version above it, and it never accepts a manifest of a version
#: that it does not know.
MANIFEST_SCHEMA_LEGACY = 1

#: The public documents of the catalogue.
#:
#: A document is public when it carries no private key material. The
#: document of the keybox is **not** public: it holds the private key
#: material of a device, and a document that can replace a private key is
#: a document that can read one. It is therefore never declared in a
#: manifest and never fetched by the updater.
#:
#: The serial policies are **metadata**: they describe the serials that
#: the owner wants to be blocked and the serials that the owner allows,
#: and they are applied by the toolbox itself. They are not applied by
#: the hook layer of the platform, and they never replace a real value of
#: the platform.
PUBLIC_DOCUMENTS: tuple[dict, ...] = (
    {
        "kind": "devices",
        "path": "device-props.json",
        "summary": "The catalogue of the device profiles.",
    },
    {
        "kind": "props",
        "path": "app-props.json",
        "summary": "The catalogue of the identity profiles of the applications.",
    },
    {
        "kind": "pif",
        "path": "pif-props.json",
        "summary": "The authoritative profile of the Play Integrity Fix.",
    },
    {
        "kind": "blacklist",
        "path": "blacklist.json",
        "summary": "The policy of the blacklist of the applications.",
    },
    {
        "kind": "targets",
        "path": "target-list.txt",
        "summary": "The list of the targets of the attestation.",
    },
    {
        "kind": "block_serial",
        "path": "block-serial.txt",
        "summary": "The metadata of the serial policy: the serials that are blocked.",
    },
    {
        "kind": "white_serial",
        "path": "white-serial.txt",
        "summary": "The metadata of the serial policy: the serials that are allowed.",
    },
)

#: The documents of the catalogue that are never declared in a manifest.
#:
#: The document of the keybox carries the private key material of a
#: device, so it is never signed, never published and never fetched.
PRIVATE_DOCUMENTS: tuple[str, ...] = ("keybox.xml",)

#: The identifiers of the legacy project.
#:
#: The reference catalogue carries a document of the properties of the
#: boot that names the legacy identifiers of the project that the
#: reference was built on. DeadZone does not publish them, and the
#: document is refused when it is offered, because a property that names
#: another project is a stale identifier of a runtime configuration.
LEGACY_PROPERTY_IDENTIFIERS: tuple[str, ...] = (
    "ro.boot.projectryu",
    "ro.boot.author",
    "projectryu",
)

# The profiles of the catalogue.
#
# Every profile carries the eleven identity fields that the document of
# the Play Integrity Fix has to carry, the version of the schema of the
# document and the compatibility of the profile.
#
# The fingerprints are the fingerprints of the public builds of the
# devices. They are the software identity that the platform reports and
# they are not a claim about the hardware of the owner.
PROFILES = [
    {
        "id": "pixel-6a-bluejay",
        "version": "1.0.0",
        "android_min": 13,
        "android_max": 17,
        "devices": ["bluejay", "bluejay_beta"],
        "document": {
            "schema_version": 1,
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 6a",
            "BRAND": "google",
            "PRODUCT": "bluejay",
            "DEVICE": "bluejay",
            "FINGERPRINT": (
                "google/bluejay/bluejay:14/AP2A.240705.005/12627905:user/release-keys"
            ),
            "RELEASE": "14",
            "ID": "AP2A.240705.005",
            "INCREMENTAL": "12627905",
            "TYPE": "user",
            "TAGS": "release-keys",
            "SECURITY_PATCH": "2024-07-05",
            "DEVICE_INITIAL_SDK_INT": "33",
        },
    },
    {
        "id": "pixel-7-panther",
        "version": "1.0.0",
        "android_min": 14,
        "android_max": 17,
        "devices": ["panther", "panther_eea"],
        "document": {
            "schema_version": 1,
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 7",
            "BRAND": "google",
            "PRODUCT": "panther",
            "DEVICE": "panther",
            "FINGERPRINT": (
                "google/panther/panther:14/AP2A.240705.005/11404571:user/release-keys"
            ),
            "RELEASE": "14",
            "ID": "AP2A.240705.005",
            "INCREMENTAL": "11404571",
            "TYPE": "user",
            "TAGS": "release-keys",
            "SECURITY_PATCH": "2024-07-05",
            "DEVICE_INITIAL_SDK_INT": "34",
        },
    },
    {
        "id": "pixel-9-caiman",
        "version": "1.0.0",
        "android_min": 15,
        "android_max": 17,
        "devices": ["caiman", "caiman_eea"],
        "document": {
            "schema_version": 1,
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 9",
            "BRAND": "google",
            "PRODUCT": "caiman",
            "DEVICE": "caiman",
            "FINGERPRINT": (
                "google/caiman/caiman:15/AP3A.241105.007/12654405:user/release-keys"
            ),
            "RELEASE": "15",
            "ID": "AP3A.241105.007",
            "INCREMENTAL": "12654405",
            "TYPE": "user",
            "TAGS": "release-keys",
            "SECURITY_PATCH": "2024-11-05",
            "DEVICE_INITIAL_SDK_INT": "35",
        },
    },
    {
        "id": "xperia-1-6-zulu",
        "version": "1.0.0",
        "android_min": 13,
        "android_max": 16,
        "devices": ["zulu"],
        "document": {
            "schema_version": 1,
            "MANUFACTURER": "Sony",
            "MODEL": "Xperia 1 VI",
            "BRAND": "Sony",
            "PRODUCT": "pdx223",
            "DEVICE": "zulu",
            "FINGERPRINT": (
                "Sony/pdx223/pdx223:14/68.2.A.1.75/0077.5000.0:user/release-keys"
            ),
            "RELEASE": "14",
            "ID": "68.2.A.1.75",
            "INCREMENTAL": "0077.5000.0",
            "TYPE": "user",
            "TAGS": "release-keys",
            "SECURITY_PATCH": "2024-08-01",
            "DEVICE_INITIAL_SDK_INT": "33",
        },
    },
]

# The schema of a profile of the Play Integrity Fix.
#
# The schema is published so that a client that is not the native core
# can validate a document before it stores it. It is a JSON schema of the
# draft 2020-12.
PIF_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://raw.githubusercontent.com/DeadZone-Offical/Toolbox-Database/main/pif/schemas/pif-profile.schema.json",
    "title": "DeadZone Play Integrity Fix profile",
    "description": (
        "The document of the Play Integrity Fix. It carries the identity of "
        "a public build of the platform and the compatibility of the "
        "profile."
    ),
    "type": "object",
    "required": [
        "schema_version",
        "MANUFACTURER",
        "MODEL",
        "BRAND",
        "PRODUCT",
        "DEVICE",
        "FINGERPRINT",
        "RELEASE",
        "ID",
        "INCREMENTAL",
        "TYPE",
        "TAGS",
    ],
    "properties": {
        "schema_version": {"type": "integer", "minimum": 1, "maximum": 1},
        "MANUFACTURER": {"type": "string", "minLength": 1},
        "MODEL": {"type": "string", "minLength": 1},
        "BRAND": {"type": "string", "minLength": 1},
        "PRODUCT": {"type": "string", "minLength": 1},
        "DEVICE": {"type": "string", "minLength": 1},
        "FINGERPRINT": {"type": "string", "minLength": 1},
        "RELEASE": {"type": "string", "minLength": 1},
        "ID": {"type": "string", "minLength": 1},
        "INCREMENTAL": {"type": "string", "minLength": 1},
        "TYPE": {"type": "string", "minLength": 1},
        "TAGS": {"type": "string", "minLength": 1},
        "SECURITY_PATCH": {"type": "string"},
        "DEVICE_INITIAL_SDK_INT": {"type": "string"},
        "compatibility": {
            "type": "object",
            "properties": {
                "android_min": {"type": "integer"},
                "android_max": {"type": "integer"},
                "devices": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    "additionalProperties": True,
}


def load_key() -> Ed25519PrivateKey:
    """Read the private signing key of the operator."""
    if not KEY_PATH.exists():
        raise SystemExit(
            f"the signing key is not there: {KEY_PATH}\n"
            "the key is the private key of the operator and it never enters the repository"
        )
    material = KEY_PATH.read_bytes()
    if len(material) != 32:
        raise SystemExit(f"the signing key is malformed: {KEY_PATH}")
    return Ed25519PrivateKey.from_private_bytes(material)


def canonical_json(value: object) -> bytes:
    """The canonical bytes of a document.

    The canonical form is the one that the updater verifies: the bytes
    of the body that was downloaded. The signature is therefore over the
    exact bytes of the file, and a change of the formatting of the file
    is a change of its signature.
    """
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    ).encode("utf-8")


def build(root: pathlib.Path, private: Ed25519PrivateKey) -> None:
    """Generate the catalogue under `root`."""
    profiles_dir = root / "pif" / "profiles"
    schemas_dir = root / "pif" / "schemas"
    manifests_dir = root / "manifests"
    publishing_dir = root / "publishing"

    for directory in (profiles_dir, schemas_dir, manifests_dir, publishing_dir):
        directory.mkdir(parents=True, exist_ok=True)

    # The schema of a profile.
    (schemas_dir / "pif-profile.schema.json").write_bytes(
        canonical_json(PIF_SCHEMA)
    )

    # The profiles of the stable channel.
    entries = []
    for profile in PROFILES:
        document = dict(profile["document"])
        document["compatibility"] = {
            "android_min": profile["android_min"],
            "android_max": profile["android_max"],
            "devices": profile["devices"],
        }
        relative = f"pif/profiles/{profile['id']}.json"
        body = canonical_json(document)
        (root / relative).write_bytes(body)
        entries.append(
            {
                "id": profile["id"],
                "version": profile["version"],
                "android_min": profile["android_min"],
                "android_max": profile["android_max"],
                "path": relative,
                "sha256": hashlib.sha256(body).hexdigest(),
                "devices": profile["devices"],
            }
        )

    # The public documents of the catalogue.
    #
    # Every document that the catalogue publishes and that carries no
    # private key material is declared in the manifest with its digest,
    # so that a client verifies the bytes that it downloaded against the
    # bytes that the signer signed.
    documents = []
    for document in PUBLIC_DOCUMENTS:
        source = REPO / document["path"]
        if not source.is_file():
            # A document that is not there is not declared. The manifest
            # never promises a document that the repository does not
            # hold, so the client never waits for a file that cannot
            # arrive.
            continue
        body = source.read_bytes()
        documents.append(
            {
                "kind": document["kind"],
                "path": document["path"],
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
                "summary": document["summary"],
            }
        )

    # The manifest of the stable channel.
    stable = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "channel": "stable",
        "revision": _revision(entries, documents),
        "profiles": entries,
        "documents": documents,
    }
    _write_signed(manifests_dir / "stable.json", stable, private)

    # The manifest of the testing channel.
    #
    # The testing channel carries the same profiles at the moment. It
    # exists so that a client can be pointed at a channel, and so that
    # the test of the updater has a second, independently signed
    # document to work with.
    testing = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "channel": "testing",
        "revision": _revision(entries, documents),
        "profiles": entries,
        "documents": documents,
    }
    _write_signed(manifests_dir / "testing.json", testing, private)

    # The pinned public key.
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (publishing_dir / "pinned-public-key.txt").write_text(
        base64.b64encode(public).decode() + "\n", encoding="utf-8"
    )
    (publishing_dir / "pinned-public-key.hex").write_text(
        public.hex() + "\n", encoding="utf-8"
    )


def _revision(entries: list, documents: list | None = None) -> str:
    """The revision of a manifest.

    The revision is the digest of the list of the digests of the
    profiles and of the public documents, so that two manifests that
    carry the same content carry the same revision, and any change of a
    profile or of a document changes it.

    The revision is **not** the epoch of the configuration of the device.
    The revision is a fact about the catalogue, and the epoch is a fact
    about the runtime of the device.
    """
    material = "".join(entry["sha256"] for entry in entries)
    for document in documents or []:
        material += document["sha256"]
    return hashlib.sha256(material.encode("ascii")).hexdigest()[:16]


def _write_signed(path: pathlib.Path, document: dict, private: Ed25519PrivateKey) -> None:
    """Write a manifest and the signature of its canonical bytes."""
    body = canonical_json(document)
    path.write_bytes(body)
    signature = private.sign(body)
    path.with_suffix(path.suffix + ".sig").write_text(
        base64.b64encode(signature).decode() + "\n", encoding="utf-8"
    )


def validate() -> None:
    """Check that the catalogue of the repository is coherent.

    The check is the one that the continuous integration runs. It
    refuses a catalogue that

      * publishes a document that carries private key material,
      * publishes a property of the boot that names the legacy project,
      * declares a public document that the repository does not hold.
    """
    problems: list[str] = []

    for name in PRIVATE_DOCUMENTS:
        if name in {document["path"] for document in PUBLIC_DOCUMENTS}:
            problems.append(
                f"the document {name} carries private key material and "
                "cannot be published"
            )

    for document in PUBLIC_DOCUMENTS:
        source = REPO / document["path"]
        if not source.is_file():
            problems.append(
                f"the public document {document['path']} is declared but "
                "the repository does not hold it"
            )

    for source in sorted(REPO.glob("*.prop")):
        text = source.read_text(encoding="utf-8", errors="replace")
        for identifier in LEGACY_PROPERTY_IDENTIFIERS:
            if identifier in text:
                problems.append(
                    f"the document {source.name} names the legacy identifier "
                    f"{identifier} and cannot be published"
                )

    if problems:
        raise SystemExit(
            "the catalogue is not coherent:\n"
            + "\n".join(f"  {problem}" for problem in problems)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the committed catalogue matches the signing key",
    )
    arguments = parser.parse_args()

    private = load_key()
    validate()

    if arguments.check:
        with tempfile.TemporaryDirectory() as temporary:
            build(pathlib.Path(temporary), private)
            differences = []
            for produced in sorted(pathlib.Path(temporary).rglob("*")):
                if not produced.is_file():
                    continue
                relative = produced.relative_to(temporary)
                committed = REPO / relative
                if not committed.exists():
                    differences.append(f"missing in the repository: {relative}")
                    continue
                if committed.read_bytes() != produced.read_bytes():
                    differences.append(f"differs from the repository: {relative}")
            for difference in differences:
                print(difference, file=sys.stderr)
            if differences:
                return 1
            print("the committed catalogue matches the signing key")
            return 0

    build(REPO, private)
    print(f"the catalogue was generated under {REPO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
