# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import json
import logging

logger = logging.getLogger("plane.authentication")

# Mirrors WorkspaceMember.ROLE_CHOICES (apps/api/plane/db/models/workspace.py)
ROLE_NAME_TO_VALUE = {"admin": 20, "member": 15, "guest": 5}


def parse_group_role_mapping(raw_json):
    """Parse and validate the OIDC_GROUP_ROLE_MAPPING instance config value.

    Returns a list of {"group": str, "workspace_slug": str, "role": int} dicts.
    Invalid JSON or invalid individual entries are logged and skipped rather than
    raising, so a misconfigured mapping never blocks login.
    """
    if not raw_json:
        return []

    try:
        entries = json.loads(raw_json)
    except (TypeError, ValueError):
        logger.warning("OIDC_GROUP_ROLE_MAPPING is not valid JSON, ignoring")
        return []

    if not isinstance(entries, list):
        logger.warning("OIDC_GROUP_ROLE_MAPPING must be a JSON array, ignoring")
        return []

    mappings = []
    for entry in entries:
        if not isinstance(entry, dict):
            logger.warning("Skipping OIDC_GROUP_ROLE_MAPPING entry that is not an object: %r", entry)
            continue

        group = entry.get("group")
        workspace_slug = entry.get("workspace_slug")
        role_name = entry.get("role")

        if not group or not workspace_slug:
            logger.warning("Skipping OIDC_GROUP_ROLE_MAPPING entry missing group/workspace_slug: %r", entry)
            continue

        role = ROLE_NAME_TO_VALUE.get(role_name)
        if role is None:
            logger.warning("Skipping OIDC_GROUP_ROLE_MAPPING entry with unknown role %r: %r", role_name, entry)
            continue

        mappings.append({"group": group, "workspace_slug": workspace_slug, "role": role})

    return mappings
