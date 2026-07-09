from .config import load_config
from .server import init_server, mcp
from .transport import run


def main() -> None:
    import sys

    cfg_path = sys.argv[1] if len(sys.argv) > 1 else None
    cfg = load_config(cfg_path)
    init_server(cfg)
    run(mcp, cfg)


if __name__ == "__main__":
    main()
