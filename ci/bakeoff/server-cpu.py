"""Snapshot sccache CPU including reaped compiler children; no process mutation."""
import json, os, sys
pid = int(os.environ['SCCACHE_SERVER_PID'])
try:
    fields = open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()
    # fields[0] is stat field 3, so utime/stime/cutime/cstime are 11..14.
    ticks = os.sysconf('SC_CLK_TCK')
    json.dump({'pid': pid, 'own_user_s': int(fields[11])/ticks,
               'own_system_s': int(fields[12])/ticks,
               'children_user_s': int(fields[13])/ticks,
               'children_system_s': int(fields[14])/ticks}, sys.stdout)
except FileNotFoundError:
    json.dump({'pid': pid, 'missing': True}, sys.stdout)
print()
