# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import json

import pytest

from plane.authentication.utils.oidc_group_mapping import parse_group_role_mapping


@pytest.mark.unit
class TestParseGroupRoleMapping:
    def test_empty_input_returns_empty_list(self):
        assert parse_group_role_mapping("") == []
        assert parse_group_role_mapping(None) == []

    def test_valid_entries_are_parsed(self):
        raw = json.dumps(
            [
                {"group": "engineering", "workspace_slug": "acme", "role": "admin"},
                {"group": "support", "workspace_slug": "acme", "role": "guest"},
            ]
        )
        assert parse_group_role_mapping(raw) == [
            {"group": "engineering", "workspace_slug": "acme", "role": 20},
            {"group": "support", "workspace_slug": "acme", "role": 5},
        ]

    def test_invalid_json_returns_empty_list(self):
        assert parse_group_role_mapping("not json") == []

    def test_non_list_json_returns_empty_list(self):
        assert parse_group_role_mapping(json.dumps({"group": "engineering"})) == []

    def test_entry_missing_group_is_skipped(self):
        raw = json.dumps([{"workspace_slug": "acme", "role": "admin"}])
        assert parse_group_role_mapping(raw) == []

    def test_entry_missing_workspace_slug_is_skipped(self):
        raw = json.dumps([{"group": "engineering", "role": "admin"}])
        assert parse_group_role_mapping(raw) == []

    def test_entry_with_unknown_role_is_skipped(self):
        raw = json.dumps([{"group": "engineering", "workspace_slug": "acme", "role": "superuser"}])
        assert parse_group_role_mapping(raw) == []

    def test_entry_that_is_not_an_object_is_skipped(self):
        raw = json.dumps(["engineering"])
        assert parse_group_role_mapping(raw) == []

    def test_valid_entries_survive_alongside_invalid_ones(self):
        raw = json.dumps(
            [
                {"group": "engineering", "workspace_slug": "acme", "role": "admin"},
                {"group": "bad-entry", "role": "admin"},
            ]
        )
        assert parse_group_role_mapping(raw) == [{"group": "engineering", "workspace_slug": "acme", "role": 20}]
