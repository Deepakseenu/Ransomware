#!/usr/bin/env python3
"""
run_all.py - start auth_app (5001) and dashboard (5000) together,
and ensure when one stops the other is terminated.
"""

import subprocess, time, sys, os, signal, socket

ROOT = os.path.expanduser("~/Ransomware_Project")
AUTH_PATH = os.path.join(ROOT, "auth_system", "auth_app.py")
DASH_PATH = os.path.join(ROOT, "dashboard", "combined_dashboard.py")

AUTH_PORT = 5001
DASH_PORT = 5000

def port_in_use(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        return True
    finally:
        s.close()
    return False

def start_process(cmd, cwd):
    return subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def stream_output(proc, name):
    # non-blocking-ish streaming of output
    try:
        for line in proc.stdout:
            print(f"[{name}] {line}", end="")
    except Exception:
        pass

def shutdown(auth_proc, dash_proc):
    print("Shutting down both servers...")
    procs = [p for p in (auth_proc, dash_proc) if p]
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    # give them time, then kill if needed
    time.sleep(2)
    for p in procs:
        if p and p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
    print("All servers stopped.")
    sys.exit(0)

if __name__ == "__main__":
    # basic checks
    if not os.path.isfile(AUTH_PATH):
        print("Auth app not found at:", AUTH_PATH); sys.exit(1)
    if not os.path.isfile(DASH_PATH):
        print("Dashboard app not found at:", DASH_PATH); sys.exit(1)

    # warn if ports already used
    if port_in_use(AUTH_PORT):
        print(f"Port {AUTH_PORT} is already in use. Stop the process using it, then re-run this script.")
        sys.exit(1)
    if port_in_use(DASH_PORT):
        print(f"Port {DASH_PORT} is already in use. Stop the process using it, then re-run this script.")
        sys.exit(1)

    auth_cmd = ["python3", AUTH_PATH]
    dash_cmd = ["python3", DASH_PATH]

    print("Starting auth app:", " ".join(auth_cmd))
    auth_proc = start_process(auth_cmd, cwd=os.path.dirname(AUTH_PATH))
    time.sleep(0.5)

    print("Starting dashboard app:", " ".join(dash_cmd))
    dash_proc = start_process(dash_cmd, cwd=os.path.dirname(DASH_PATH))

    try:
        # Stream outputs: loop, check for exit
        while True:
            # read a little output if available
            if auth_proc and auth_proc.stdout:
                line = auth_proc.stdout.readline()
                if line:
                    print("[auth ]", line, end='')
            if dash_proc and dash_proc.stdout:
                line = dash_proc.stdout.readline()
                if line:
                    print("[dash ]", line, end='')

            # if either exited, shutdown both
            if auth_proc.poll() is not None or dash_proc.poll() is not None:
                print("One of the processes exited. Shutting down other.")
                shutdown(auth_proc, dash_proc)
            time.sleep(0.2)
    except KeyboardInterrupt:
        shutdown(auth_proc, dash_proc)
