#!/usr/bin/env python3
"""Round-trip bench for a running cvld-stack (started with CVLD_STACK_STATE=<state>).

Sends N `global_public` calls over one keep-alive connection twice:
  direct: plain HTTP to the global service's own listener (hyper + handler),
  front:  HTTPS through the stack's TLS front (TLS + front relay + hyper + handler),
the same way a device does (one connection, one request at a time). Prints the median and
p95 per call of each, and the front's share (front - direct).

usage: bench_roundtrip.py <state dir> <out dir> [N]
"""
import http.client
import json
import ssl
import statistics
import sys
import time

WALLET = "wallet.toy.localhost"


def run(connection, host, n):
    body = b"{}"
    times = []
    for _ in range(n):
        start = time.perf_counter()
        connection.request(
            "POST",
            "/v1/global_public",
            body=body,
            headers={"host": host, "content-type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        times.append(time.perf_counter() - start)
        if response.status != 200:
            raise SystemExit(f"global_public answered {response.status}")
    return times


def summary(times):
    ordered = sorted(times)
    return statistics.median(ordered) * 1000, ordered[int(len(ordered) * 0.95) - 1] * 1000


def main():
    state, out = sys.argv[1], sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    saved = json.load(open(f"{state}/stack-saved.json"))
    direct_host, direct_port = saved["global_listen"].rsplit(":", 1)
    context = ssl.create_default_context(cadata=open(f"{out}/ca.der", "rb").read())
    context.check_hostname = False
    # The toy root carries no authority key identifier; Python's strict mode demands one.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    direct = http.client.HTTPConnection(direct_host, int(direct_port))
    front = http.client.HTTPSConnection("127.0.0.1", saved["ports"][0], context=context)
    run(direct, WALLET, 5)
    run(front, "127.0.0.1", 5)
    d = summary(run(direct, WALLET, n))
    f = summary(run(front, "127.0.0.1", n))
    print(f"N={n} global_public, one keep-alive connection, ms per call")
    print(f"direct (hyper + handler)       median {d[0]:7.2f}  p95 {d[1]:7.2f}")
    print(f"front  (TLS front + direct)    median {f[0]:7.2f}  p95 {f[1]:7.2f}")
    print(f"front share                    median {f[0] - d[0]:7.2f}  p95 {f[1] - d[1]:7.2f}")


if __name__ == "__main__":
    main()
