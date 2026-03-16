from pathlib import Path
import sys
import re

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config_loader import load_config
from src.joern_client import JoernClient


def main() -> None:
    cfg = load_config(Path("configs/config.yaml").resolve())
    client = JoernClient(cfg["joern"]["server_url"], int(cfg["joern"].get("timeout_seconds", 120)))

    files = {
        "CWE78_OS_Command_Injection__char_connect_socket_execl_61a.c",
        "CWE78_OS_Command_Injection__char_connect_socket_execl_61b.c",
    }

    queries = {
        "all_call_names": 'cpg.call.name.l',
        "function_calls_and_callee": (
            'cpg.call.name("EXECL|CWE78_OS_Command_Injection__char_connect_socket_execl_61b_badSource|'
            'CWE78_OS_Command_Injection__char_connect_socket_execl_61b_goodG2BSource")'
            '.map(c => (c.location.filename, c.location.lineNumber.getOrElse(-1), c.code, c.name, c.method.name)).l'
        ),
        "method_callOut": (
            'cpg.method.name("CWE78_OS_Command_Injection__char_connect_socket_execl_61_bad")'
            '.callOut.name.l'
        ),
        "method_callee": (
            'cpg.method.name("CWE78_OS_Command_Injection__char_connect_socket_execl_61_bad")'
            '.callee.name.l'
        ),
        "method_caller": (
            'cpg.method.name("CWE78_OS_Command_Injection__char_connect_socket_execl_61b_badSource")'
            '.caller.name.l'
        ),
        "method_callIn": (
            'cpg.method.name("CWE78_OS_Command_Injection__char_connect_socket_execl_61b_badSource")'
            '.callIn.code.l'
        ),
        "callee_method_definitions": (
            'cpg.method.name("CWE78_OS_Command_Injection__char_connect_socket_execl_61b_badSource|'
            'CWE78_OS_Command_Injection__char_connect_socket_execl_61b_goodG2BSource")'
            '.map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), m.lineNumberEnd.getOrElse(-1))).l'
        ),
        "macro_defs_via_identifier": (
            'cpg.identifier.name("COMMAND_INT_PATH|COMMAND_INT|COMMAND_ARG1|COMMAND_ARG2|COMMAND_ARG3|EXECL")'
            '.map(i => (i.name, i.code, i.location.filename, i.location.lineNumber.getOrElse(-1), i.method.name)).l'
        ),
        "variable_defs": (
            'cpg.local.name("data|dataBuffer|connectSocket|recvResult|service|replace")'
            '.map(l => (l.name, l.code, l.location.filename, l.location.lineNumber.getOrElse(-1), l.method.name)).l'
        ),
        "macro_names_via_local_variable_query": (
            'cpg.local.name("COMMAND_INT_PATH|COMMAND_INT|COMMAND_ARG1|COMMAND_ARG2|COMMAND_ARG3|EXECL")'
            '.map(l => (l.name, l.code, l.location.filename, l.location.lineNumber.getOrElse(-1), l.method.name)).l'
        ),
        "macro_names_via_local_exact_query": (
            'cpg.local.nameExact("COMMAND_ARG1")'
            '.map(l => (l.name, l.code, l.location.filename, l.location.lineNumber.getOrElse(-1), l.method.name)).l'
        ),
        "parameter_defs": (
            'cpg.parameter.name("data").map(x => (x.name, x.code, x.lineNumber.getOrElse(-1), x.method.name, x.file.name)).l'
        ),
        "member_defs": (
            'cpg.member.name("data").map(x => (x.name, x.code, x.lineNumber.getOrElse(-1), x.typeDecl.name, x.file.name)).l'
        ),
    }

    for name, query in queries.items():
        print(f"===== {name} =====")
        print(f"QUERY: {query}")
        try:
            data = client.query_sync(query)
            text = str(data.get("stdout", "")) if isinstance(data, dict) else str(data)
            lines = text.splitlines()
            for ln in lines[:120]:
                print(ln)
            print("-- END --")
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: {exc}")
            print("-- END --")
        print()

    print("===== macro_definitions_via_source_scan =====")
    macro_names = [
        "COMMAND_INT_PATH",
        "COMMAND_INT",
        "COMMAND_ARG1",
        "COMMAND_ARG2",
        "COMMAND_ARG3",
        "EXECL",
    ]
    define_prefix = re.compile(r"^\s*#\s*define\s+")
    for src in cfg["audit"].get("target", []):
        p = Path(src)
        if not p.exists() or not p.is_file():
            continue
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines, start=1):
            if not define_prefix.match(line):
                continue
            for macro in macro_names:
                if re.match(r"^\s*#\s*define\s+" + re.escape(macro) + r"\b", line):
                    print(f"{p.name}:{idx}: {line.strip()}")
                    break
    print("-- END --")


if __name__ == "__main__":
    main()
