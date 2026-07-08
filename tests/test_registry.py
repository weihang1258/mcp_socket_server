from mcp_socket_server.registry import Registry, get_registry


class TestRegistry:
    def test_add_and_list(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000, ["web"], "web1")
        reg.add_target("10.0.0.2", 9000, ["db"], "db1")
        targets = reg.list_targets()
        assert len(targets) == 2
        hosts = {t["host"] for t in targets}
        assert hosts == {"10.0.0.1", "10.0.0.2"}

    def test_list_with_tag_filter(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000, ["web", "prod"])
        reg.add_target("10.0.0.2", 9000, ["db", "prod"])
        reg.add_target("10.0.0.3", 9000, ["web", "staging"])
        prod = reg.list_targets(tags=["prod"])
        assert len(prod) == 2
        web_prod = reg.list_targets(tags=["web", "prod"])
        assert len(web_prod) == 1
        assert web_prod[0]["host"] == "10.0.0.1"

    def test_remove_target(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000)
        assert reg.remove_target("10.0.0.1")["ok"] is True
        assert reg.remove_target("10.0.0.1")["ok"] is False

    def test_resolve_bare_ip(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000)
        reg.add_target("10.0.0.2", 9000, ["tag1"])
        resolved = reg.resolve(["10.0.0.1", "10.0.0.2"])
        assert resolved == [("10.0.0.1", 9000), ("10.0.0.2", 9000)]

    def test_resolve_tag(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000, ["web"])
        reg.add_target("10.0.0.2", 9000, ["web"])
        resolved = reg.resolve(["@web"])
        assert len(resolved) == 2
        assert ("10.0.0.1", 9000) in resolved

    def test_resolve_mixed(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000, ["web"])
        resolved = reg.resolve(["@web", "10.0.0.2:9090", "10.0.0.3"])
        assert resolved == [("10.0.0.1", 9000), ("10.0.0.2", 9090), ("10.0.0.3", 9000)]

    def test_resolve_unknown_tag_skipped(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000, ["web"])
        resolved = reg.resolve(["@unknown", "10.0.0.1"])
        assert resolved == [("10.0.0.1", 9000)]

    def test_unique_constraint(self, tmp_path):
        reg = Registry(str(tmp_path / "t.db"))
        reg.add_target("10.0.0.1", 9000)
        reg.add_target("10.0.0.1", 9000)  # IGNORE
        targets = reg.list_targets()
        assert len([t for t in targets if t["host"] == "10.0.0.1"]) == 1