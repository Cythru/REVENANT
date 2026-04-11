# BlackMagic Toolkit Deploy (bm_toolkit_deploy)

## Description

Deploys the full BlackMagic sysadmin toolkit onto a compromised Linux host
via an active Metasploit session. Uploads all `.bm` sysadmin modules plus
the `bmc`, `bmpkg`, and `bmanalyze` binaries.

After deployment, the operator can run BM tools directly on the target via
the session shell — monitoring processes, inspecting files, managing the
network, and running the BigO analyzer — all without installing anything
from the internet on the target.

## Uploaded Files

- `sysmon.bm` — system overview (cpu/mem/disk)
- `nethunt.bm` — network scanner + tracer
- `inspect.bm` — process/binary inspector
- `procwatch.bm` — single-process deep-watch
- `netpipe.bm` — TCP tunnel/relay/Tor
- `vault.bm` — secrets/crypto
- `filemove.bm` — file find/sync/fetch
- `sched.bm` — task scheduler
- `bmc` — BlackMagic compiler/dispatcher
- `bmpkg` — package manager
- `bmanalyze` — BigO + language analyzer

## Usage

```
msf > use post/multi/manage/bm_toolkit_deploy
msf post(bm_toolkit_deploy) > set SESSION 1
msf post(bm_toolkit_deploy) > set DEPLOY_DIR /tmp/.bm
msf post(bm_toolkit_deploy) > run

# Then via session shell:
msf post(bm_toolkit_deploy) > sessions -i 1
meterpreter > shell
$ bash /tmp/.bm/sysadmin/procwatch.bm --top-cpu 10
$ bash /tmp/.bm/sysadmin/nethunt.bm --scan 10.0.0.0/24
$ bash /tmp/.bm/sysadmin/inspect.bm --stuck
```

## Platform

Linux (bash required on target). All .bm sysadmin modules are pure bash —
no Ruby, Python, or external runtimes needed on the target.
