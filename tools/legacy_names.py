#!/usr/bin/env python3
"""DeadZone — the forensic lexicon of the identifiers of the legacy.

The tooling of the catalogue has to recognise the identifiers of the
projects that came before, because the catalogue refuses a document that
names a project that is not DeadZone, and it has to name the identifiers
that it refuses.

This module is the **only** place of the repository where the legacy
vocabulary is written out.  Every other file of the tooling names the
legacy identifiers through the constants of this module, so that the
vocabulary is described once, is reviewed once, and cannot spread
through the tree again.

Lead developer: DeadZone.
"""
from __future__ import annotations

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
