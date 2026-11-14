#!/usr/bin/env python3
"""The tests of the catalogue of DeadZone.

The tests prove the properties that the updater of the native core
relies on:

  * the manifest is signed with the pinned key of the project;
  * the manifest declares the digest of every public document, and the
    digest is the digest of the bytes that the repository holds;
  * the document of the keybox is never declared, because it carries the
    private key material of a device;
  * the legacy identifiers of the reference project are never published;
  * the documents of the catalogue have the shape that the consumers of
    the toolbox expect.

The tests run without the network and without the private key of the
operator, except for the test of the signature, which reads the public
key that the repository publishes.

Usage:

    python3 tools/test_catalogue.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent


class Failure(AssertionError):
    """One failed expectation."""


def expect(condition: bool, message: str) -> None:
    """Record one expectation."""
    if not condition:
        raise Failure(message)


def load_manifest(channel: str) -> dict:
    """Read a manifest of the repository."""
    path = REPO / "manifests" / f"{channel}.json"
    expect(path.is_file(), f"the manifest of the channel {channel} is missing")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


def test_the_manifest_declares_the_public_documents() -> None:
    """The manifest declares the digest of every public document."""
    manifest = load_manifest("stable")
    documents = manifest.get("documents")
    expect(isinstance(documents, list), "the manifest declares no documents")
    expect(documents, "the manifest declares an empty list of documents")

    declared = {entry["path"] for entry in documents}
    for path in (
        "device-props.json",
        "app-props.json",
        "pif-props.json",
        "blacklist.json",
        "target-list.txt",
        "block-serial.txt",
        "white-serial.txt",
    ):
        expect(path in declared, f"the manifest declares no document {path}")


def test_the_digest_of_every_document_matches_the_repository() -> None:
    """The digest of the manifest is the digest of the bytes."""
    manifest = load_manifest("stable")
    for entry in manifest["documents"]:
        source = REPO / entry["path"]
        expect(source.is_file(), f"the document {entry['path']} is not there")
        body = source.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        expect(
            digest == entry["sha256"],
            f"the digest of {entry['path']} does not match the manifest",
        )
        expect(
            len(body) == entry["size"],
            f"the size of {entry['path']} does not match the manifest",
        )


def test_the_manifest_never_declares_the_keybox() -> None:
    """The keybox is never published."""
    manifest = load_manifest("stable")
    for entry in manifest["documents"]:
        expect(
            "keybox" not in entry["path"],
            f"the manifest declares the private document {entry['path']}",
        )


def test_the_revision_covers_the_profiles_and_the_documents() -> None:
    """The revision changes when a document changes."""
    manifest = load_manifest("stable")
    material = "".join(entry["sha256"] for entry in manifest["profiles"])
    material += "".join(entry["sha256"] for entry in manifest["documents"])
    expected = hashlib.sha256(material.encode("ascii")).hexdigest()[:16]
    expect(
        manifest["revision"] == expected,
        "the revision of the manifest does not cover its content",
    )


def test_the_two_channels_are_signed_independently() -> None:
    """Every channel has its own signature."""
    stable = (REPO / "manifests" / "stable.json.sig").read_text(encoding="utf-8")
    testing = (REPO / "manifests" / "testing.json.sig").read_text(encoding="utf-8")
    expect(stable.strip(), "the stable channel carries no signature")
    expect(testing.strip(), "the testing channel carries no signature")
    expect(stable.strip() != testing.strip(), "the two channels share a signature")


def test_the_signature_verifies_against_the_pinned_key() -> None:
    """The signature of the manifest verifies against the pinned key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:  # pragma: no cover - the operator installs it
        print("    (skipped: the library of the cryptography is not there)")
        return

    pinned = (REPO / "publishing" / "pinned-public-key.txt").read_text(
        encoding="utf-8"
    ).strip()
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pinned))

    for channel in ("stable", "testing"):
        body = (REPO / "manifests" / f"{channel}.json").read_bytes()
        signature = base64.b64decode(
            (REPO / "manifests" / f"{channel}.json.sig").read_text(
                encoding="utf-8"
            ).strip()
        )
        try:
            key.verify(signature, body)
        except Exception as failure:  # noqa: BLE001
            raise Failure(
                f"the signature of the channel {channel} does not verify: {failure}"
            ) from failure


def test_a_tampered_manifest_does_not_verify() -> None:
    """A manifest that was changed does not verify."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:  # pragma: no cover - the operator installs it
        print("    (skipped: the library of the cryptography is not there)")
        return

    pinned = (REPO / "publishing" / "pinned-public-key.txt").read_text(
        encoding="utf-8"
    ).strip()
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pinned))
    body = (REPO / "manifests" / "stable.json").read_bytes()
    signature = base64.b64decode(
        (REPO / "manifests" / "stable.json.sig").read_text(encoding="utf-8").strip()
    )

    tampered = body.replace(b'"stable"', b'"testin"')
    expect(tampered != body, "the manifest could not be tampered with")
    refused = False
    try:
        key.verify(signature, tampered)
    except Exception:  # noqa: BLE001
        refused = True
    expect(refused, "a tampered manifest verified against the pinned key")


# ---------------------------------------------------------------------------
# The documents
# ---------------------------------------------------------------------------


def test_the_catalogue_of_the_devices_has_the_expected_shape() -> None:
    """The catalogue of the devices carries the fields of the contract."""
    document = json.loads((REPO / "device-props.json").read_text(encoding="utf-8"))
    devices = document.get("devices")
    expect(isinstance(devices, list), "the catalogue carries no devices")
    expect(len(devices) >= 40, "the catalogue carries too few devices")
    for device in devices:
        for field in ("name", "BRAND", "DEVICE", "MANUFACTURER", "MODEL", "PRODUCT"):
            expect(field in device, f"a device carries no field {field}")


def test_the_catalogue_of_the_applications_has_the_expected_shape() -> None:
    """The catalogue of the applications carries the fields of the contract."""
    document = json.loads((REPO / "app-props.json").read_text(encoding="utf-8"))
    expect(isinstance(document, dict), "the catalogue is not an object")
    expect(len(document) == 65, "the catalogue carries 65 profiles")
    for package, profile in document.items():
        expect("." in package, f"the key {package} is not a package name")
        for field in ("BRAND", "DEVICE", "MANUFACTURER", "MODEL", "FINGERPRINT", "PRODUCT"):
            expect(field in profile, f"the profile of {package} carries no field {field}")


def test_the_profile_of_the_integrity_carries_the_thirteen_fields() -> None:
    """The profile of the integrity carries the thirteen fields of the schema."""
    document = json.loads((REPO / "pif-props.json").read_text(encoding="utf-8"))
    fields = (
        "MANUFACTURER",
        "BRAND",
        "MODEL",
        "DEVICE",
        "PRODUCT",
        "FINGERPRINT",
        "RELEASE",
        "ID",
        "INCREMENTAL",
        "TYPE",
        "TAGS",
        "SECURITY_PATCH",
        "DEVICE_INITIAL_SDK_INT",
    )
    for field in fields:
        expect(field in document, f"the profile carries no field {field}")
        expect(
            isinstance(document[field], str) and document[field],
            f"the field {field} is empty",
        )


def test_the_blacklist_is_an_array_of_packages() -> None:
    """The blacklist is an array of the names of the packages."""
    document = json.loads((REPO / "blacklist.json").read_text(encoding="utf-8"))
    expect(isinstance(document, list), "the blacklist is not an array")
    for entry in document:
        expect(isinstance(entry, str), "the blacklist carries an entry that is not a text")


def test_the_list_of_the_targets_is_a_list_of_packages() -> None:
    """The list of the targets is a list of the names of the packages."""
    text = (REPO / "target-list.txt").read_text(encoding="utf-8")
    for line in text.splitlines():
        entry = line.strip()
        if not entry:
            continue
        expect("." in entry, f"the target {entry} is not a package name")


def test_the_serial_policies_are_lists_of_serials() -> None:
    """The serial policies are lists of the serials of the owner."""
    for name in ("block-serial.txt", "white-serial.txt"):
        text = (REPO / name).read_text(encoding="utf-8")
        serials = [line.strip() for line in text.splitlines() if line.strip()]
        expect(serials, f"the policy {name} is empty")
        for serial in serials:
            expect(
                all(character in "0123456789abcdefABCDEF" for character in serial),
                f"the serial {serial} of {name} is not a hexadecimal value",
            )


def test_the_serial_policies_do_not_overlap() -> None:
    """A serial is either blocked or allowed, never both."""
    def read(name: str) -> set[str]:
        text = (REPO / name).read_text(encoding="utf-8")
        return {line.strip() for line in text.splitlines() if line.strip()}

    blocked = read("block-serial.txt")
    allowed = read("white-serial.txt")
    overlap = blocked & allowed
    expect(not overlap, f"the serial policies overlap: {sorted(overlap)}")


def test_the_repository_publishes_no_legacy_property() -> None:
    """The repository publishes no property of the legacy project."""
    for source in sorted(REPO.glob("*.prop")):
        text = source.read_text(encoding="utf-8", errors="replace")
        expect(
            "projectryu" not in text.lower(),
            f"the document {source.name} names the legacy project",
        )
    expect(
        not list(REPO.glob("native-props.prop")),
        "the repository still publishes the document of the legacy project",
    )


def main() -> int:
    """Run every test of the catalogue."""
    tests = [
        test_the_manifest_declares_the_public_documents,
        test_the_digest_of_every_document_matches_the_repository,
        test_the_manifest_never_declares_the_keybox,
        test_the_revision_covers_the_profiles_and_the_documents,
        test_the_two_channels_are_signed_independently,
        test_the_signature_verifies_against_the_pinned_key,
        test_a_tampered_manifest_does_not_verify,
        test_the_catalogue_of_the_devices_has_the_expected_shape,
        test_the_catalogue_of_the_applications_has_the_expected_shape,
        test_the_profile_of_the_integrity_carries_the_thirteen_fields,
        test_the_blacklist_is_an_array_of_packages,
        test_the_list_of_the_targets_is_a_list_of_packages,
        test_the_serial_policies_are_lists_of_serials,
        test_the_serial_policies_do_not_overlap,
        test_the_repository_publishes_no_legacy_property,
    ]

    failures = 0
    for test in tests:
        try:
            test()
        except Failure as failure:
            failures += 1
            print(f"[X] {test.__name__}: {failure}", file=sys.stderr)
        else:
            print(f"[+] {test.__name__}")

    print(f"the catalogue ran {len(tests)} tests, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
