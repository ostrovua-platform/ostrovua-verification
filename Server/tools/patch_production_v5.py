#!/usr/bin/env python3
"""Disabled legacy deployment helper.

Protocol v5/v6 cannot be spliced into production after the v7 security
boundary. Keeping an explicit fail-closed tombstone prevents an old runbook
from silently restoring the legacy challenge and envelope contracts.
"""

raise SystemExit(
    "DISABLED: protocol v5/v6 production patching is forbidden. "
    "Integrate and review the complete protocol v7 auth route, migrations, "
    "biometric service and fail-closed runtime as one release artifact."
)
