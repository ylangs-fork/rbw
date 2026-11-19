"""Private CPython entrypoint; never import host/user site-packages or cwd."""
import sys

ROOT = "/usr/lib/security/rbw-howdy"
RUNTIME = ROOT + "/runtime"
sys.path[:] = [RUNTIME + "/lib/python3.10", RUNTIME + "/lib/python3.10/lib-dynload",
               RUNTIME + "/lib/python3.10/site-packages", ROOT + "/howdy"]
sys.executable = RUNTIME + "/bin/python3"
sys.prefix = sys.exec_prefix = sys.base_prefix = sys.base_exec_prefix = RUNTIME
sys.dont_write_bytecode = True

import runpy

args = sys.argv[1:]
while args and args[0] in ("-s", "-E", "-I", "-S", "-B", "-sE", "-Es"):
    args.pop(0)
if args and args[0] in ("--version", "-V"):
    print("Python " + sys.version.split()[0])
elif args and args[0] == "-c":
    if len(args) < 2:
        raise SystemExit("rbw runtime: -c requires an argument")
    sys.argv = ["-c"] + args[2:]
    exec(compile(args[1], "<string>", "exec"), {"__name__": "__main__"})
elif args and args[0] == "-m":
    if len(args) < 2:
        raise SystemExit("rbw runtime: -m requires a module")
    sys.argv = args[1:]
    runpy.run_module(args[1], run_name="__main__", alter_sys=True)
elif not args or args[0] == "-":
    sys.argv = ["-"] + args[1:]
    exec(compile(sys.stdin.read(), "<stdin>", "exec"), {"__name__": "__main__"})
else:
    if args[0].startswith("-"):
        raise SystemExit("rbw runtime: unsupported Python option " + args[0])
    sys.argv = args
    runpy.run_path(args[0], run_name="__main__")
