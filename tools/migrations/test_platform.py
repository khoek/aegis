import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("migration", Path(__file__).with_name("platform.py"))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
HOST = "deadbeef-dead-beef-dead-beefdeadbeef"
IDENTITY = {"operating_system": "ubuntu", "architecture": "x86_64"}


class MigrationTests(unittest.TestCase):
    def test_principal_grants_rename_only_reviewed_uuid_fields(self):
        document = {
            "name": "projects/p/hosts/" + HOST,
            "updateTime": "2026-10-01T00:00:00Z",
            "fields": {"report": {"mapValue": {"fields": {"principal_grants": {
                "arrayValue": {"values": [{"mapValue": {"fields": {
                    "login_principal": {"stringValue": "aegis-bootstrap"},
                    "oauth_principal": {"stringValue": "11111111-1111-4111-8111-111111111111"},
                }}}]}
            }}}}},
        }
        writes = migration.principal_grant_updates([document])
        self.assertEqual(writes[0]["updateMask"]["fieldPaths"], ["report.principal_grants"])
        fields = writes[0]["update"]["fields"]["report"]["mapValue"]["fields"]
        grant = fields["principal_grants"]["arrayValue"]["values"][0]["mapValue"]["fields"]
        self.assertEqual(set(grant), {"login_principal", "user_id"})
        with self.assertRaises(ValueError):
            migration.principal_grant_updates([{
                **document,
                "fields": {"report": {"mapValue": {"fields": {"principal_grants": {
                    "arrayValue": {"values": [{"mapValue": {"fields": {
                        "login_principal": {"stringValue": "x"},
                        "oauth_principal": {"stringValue": "not-a-user"},
                    }}}]}
                }}}}},
            }])

    def test_no_write_until_all_identities_are_reviewed(self):
        document = {"name": f"projects/p/hosts/{HOST}", "fields": {}, "updateTime": "2026-10-01T00:00:00Z"}
        writes = migration.host_updates([document], {HOST: IDENTITY})
        self.assertEqual(writes[0]["currentDocument"], {"updateTime": document["updateTime"]})
        self.assertEqual(writes[0]["updateMask"]["fieldPaths"], ["platform"])
        with self.assertRaises(ValueError):
            migration.host_updates([document], {})
        document["fields"]["platform"] = migration.platform(IDENTITY)
        self.assertEqual(migration.host_updates([document], {HOST: IDENTITY}), [])
        with self.assertRaises(ValueError):
            migration.host_updates([document], {HOST: {**IDENTITY, "architecture": "aarch64"}})

    def test_config_preserves_other_values_and_refuses_repeat(self):
        original = 'api_base = "https://example.test"\n[bird]\nconfig_path = "/etc/bird/bird.conf"\nservice = "bird"\n'
        result = migration.routing_config(original)
        self.assertIn('backend = "bird"', result)
        self.assertIn('api_base = "https://example.test"', result)
        with self.assertRaises(ValueError):
            migration.routing_config(result)
        with self.assertRaises(ValueError):
            migration.routing_config('[bird]\nconfig_path="/etc/bird.conf"\nunknown=1\n')


if __name__ == "__main__":
    unittest.main()
