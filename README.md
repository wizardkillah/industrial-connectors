# industrial-connectors

[![CI](https://github.com/wizardkillah/industrial-connectors/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wizardkillah/industrial-connectors/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Dependency-free Python clients for talking to building-automation and PLC equipment.
Extracted from real monitoring work on critical infrastructure and rewritten as generic,
anonymized, tested building blocks.

| Module | Protocol | What it does |
|---|---|---|
| [`bacnet/`](bacnet/client.py) | BACnet/IP over raw UDP 47808 | ReadProperty (value, name, units, description), Who-Is/I-Am discovery |
| [`sauter_moduweb/`](sauter_moduweb/client.py) | HTTP + session cookie | Reads point tables from login-protected controller web UIs (Sauter moduWeb style) when BACnet is not exposed |
| [`mitsubishi_mc/`](mitsubishi_mc/client.py) | MELSEC MC protocol, A-compatible **1E frame** (binary, TCP) | Batch read/write of bits and words on FX3G/FX3GC/FX3U PLCs, float helper, octal X/Y addressing |

```
Sensor / PLC ──► protocol client ──► state / DB ──► dashboard
 (BACnet, MC 1E, web UI)   (this repo)
```

## Why raw sockets?

Production dashboards on critical-infrastructure networks must be easy to audit and have a minimal
dependency surface. Each client is a single file you can read in ten minutes: packet layout,
byte masks (`(object_type << 22) | instance`), nibble-packed bit data, little-endian words.

## Usage

```python
from bacnet import BacnetClient
with BacnetClient() as c:
    print(c.read("192.0.2.10", "analogInput", 1), c.read("192.0.2.10", "analogInput", 1, "units"))

from mitsubishi_mc import McClient
with McClient("192.0.2.50", 5007) as plc:
    level = plc.read_words("D104")[0]
    pump_outputs = plc.read_bits("Y0", 16)      # X/Y are octal on FX series

from sauter_moduweb import ModuWebClient      # MODUWEB_HOST / MODUWEB_USER / MODUWEB_PASS in env
c = ModuWebClient(); c.login(); print(c.points("/path/to/points"))
```

All addresses above are from the documentation range (RFC 5737). Replace with your own.

## Safety and security design

* **No credentials, hosts or IPs in code.** moduWeb reads them from the environment; there is no default host.
* Plain HTTP is refused for public addresses; cross-host redirects and paths are blocked.
* Inputs validated (IP syntax, device kind, point counts) before anything hits the wire.
* The MC client **can write** to a PLC (`write_bits`, `write_words`). Do not point it at equipment you are not authorized to control; keep monitoring code read-only.

## Tests

```bash
pip install pytest
pytest
```

The suite runs a fake BACnet device (UDP) and a fake MC-1E PLC (TCP) on loopback. The MC client
follows the public 1E frame specification and passes against that simulator; validate it against
your own PLC before relying on it in production. The BACnet decoding logic comes from a client that ran
against live building controllers.

## License

MIT
