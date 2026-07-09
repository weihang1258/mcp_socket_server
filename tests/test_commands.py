from mcp_socket_server.commands import COMMANDS, Danger, LockClass


def test_registry_has_phase1_read_tools():
    for name, dt in [("version_query", 14), ("isfile", 7), ("isdir", 8), ("routeinfo", 4),
                     ("command_exists", 18), ("filesize", 11), ("version_detail", 19),
                     ("pcap_flow_extract", 200)]:
        assert name in COMMANDS, name
        assert COMMANDS[name].datatype == dt
        assert COMMANDS[name].lock_class == LockClass.NONE
        assert COMMANDS[name].danger == Danger.SAFE


def test_registry_no_dead_or_deferred():
    # 161/162/163 死代码不注册;version_switch/firewall 本期不暴露
    for name in ["version_switch", "firewall_disable"]:
        assert name not in COMMANDS, f"{name} 本期不应暴露"


def test_file_transfer_is_session_not_single_datatype():
    # file_upload/download 是多步会话,commands.py 不应记单 datatype
    assert "file_upload" in COMMANDS
    assert "file_download" in COMMANDS
    assert COMMANDS["file_upload"].datatype is None  # 多步会话标记
    assert COMMANDS["file_download"].datatype is None


def test_cmd_exec_is_danger_and_capture_locks():
    assert COMMANDS["cmd_exec"].danger == Danger.DANGER
    assert COMMANDS["cmd_exec"].lock_class == LockClass.SHELL
    assert COMMANDS["capture_start"].lock_class == LockClass.CAPTURE
    assert COMMANDS["capture_start"].lock_key_fields == ("path",)
    assert COMMANDS["boce_run"].lock_class == LockClass.BROWSER
