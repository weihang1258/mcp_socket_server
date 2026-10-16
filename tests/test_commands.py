from mcp_socket_server.commands import COMMANDS, Danger, LockClass


def test_registry_has_phase1_read_tools():
    for name, dt in [("isfile", 7), ("isdir", 8),
                     ("pcap_flow_extract", 200)]:
        assert name in COMMANDS, name
        assert COMMANDS[name].datatype == dt
        assert COMMANDS[name].lock_class == LockClass.NONE
        assert COMMANDS[name].danger == Danger.SAFE


def test_registry_removed_dead_tools():
    # 终审收敛:无对应 socket_client 方法/未实现的 7 条死注册已删
    for name in ["version_query", "routeinfo", "command_exists", "filesize",
                 "version_detail", "file_upload", "file_download"]:
        assert name not in COMMANDS, name
    # 保留的 7 条仍在
    for name in ["isfile", "isdir", "pcap_flow_extract",
                 "capture_start", "capture_stop", "cmd_exec", "boce_run"]:
        assert name in COMMANDS, name


def test_registry_no_dead_or_deferred():
    # 161/162/163 死代码不注册;version_switch/firewall 本期不暴露
    for name in ["version_switch", "firewall_disable"]:
        assert name not in COMMANDS, f"{name} 本期不应暴露"


def test_file_transfer_not_registered():
    # file_upload/download 是多步会话,非单 datatype,本期不注册;
    # 终审收敛已删,此处断言不在表里防止回退
    assert "file_upload" not in COMMANDS
    assert "file_download" not in COMMANDS


def test_cmd_exec_is_danger_and_capture_locks():
    assert COMMANDS["cmd_exec"].danger == Danger.DANGER
    assert COMMANDS["cmd_exec"].lock_class == LockClass.SHELL
    assert COMMANDS["capture_start"].lock_class == LockClass.CAPTURE
    assert COMMANDS["capture_start"].lock_key_fields == ("path",)
    assert COMMANDS["boce_run"].lock_class == LockClass.BROWSER
