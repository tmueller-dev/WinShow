# Third-party notices

WinShow is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
This file records the third-party components it depends on, their licences, and the
obligations those licences place on anyone who redistributes WinShow or runs it as a network
service.

The list covers **runtime** dependencies — everything shipped inside the container image or
installed by `pip install winshow`. Development-only tools (`pytest`, `ruff`, `mypy`) are not
distributed with the software and are listed separately at the end for completeness.

---

## 1. Compatibility

Every runtime dependency is under a permissive licence — MIT, BSD-2-Clause, BSD-3-Clause,
Apache-2.0, or the PSF licence. All of them are one-way compatible with the AGPL: their code
may be combined into an AGPL-licensed work, and the combined work is distributed under the
AGPL. None of them is copyleft, so none imposes a licence on WinShow's own source.

The one direction that does **not** work is the reverse: because WinShow is AGPL, its code
cannot be copied back into an MIT- or Apache-licensed project without that project accepting
the AGPL terms. That is a deliberate consequence of the licence choice, not an oversight.

Apache-2.0 deserves a specific note. It is compatible with GPLv3 and AGPLv3 in this
direction only — Apache-2.0 code may be incorporated into an AGPLv3 work — and it carries a
patent grant and a notice requirement that survive the combination. Both are honoured below.

---

## 2. Runtime dependencies

| Component | Version | Licence | Why it is here |
|---|---|---|---|
| [`mcp`](https://github.com/modelcontextprotocol/python-sdk) | 1.28.1 | MIT | The official Model Context Protocol SDK; provides the Streamable HTTP transport and the low-level server. See [ADR 0005](docs/adr/0005-python-mcp-sdk-selection.md). |
| [`starlette`](https://github.com/encode/starlette) | 1.3.1 | BSD-3-Clause | ASGI routing; hosts `/mcp`, `/agent`, `/healthz`, `/readyz` in one application |
| [`uvicorn`](https://github.com/encode/uvicorn) | 0.51.0 | BSD-3-Clause | The ASGI server |
| [`pydantic`](https://github.com/pydantic/pydantic) | 2.13.4 | MIT | Validation of every tool input and output, and of every WSAP/1 payload |
| [`pydantic-settings`](https://github.com/pydantic/pydantic-settings) | 2.14.2 | MIT | Configuration from environment variables |
| [`prometheus-client`](https://github.com/prometheus/client_python) | 0.26.0 | Apache-2.0 AND BSD-2-Clause | Metrics exposition on the admin bind address |
| [`websockets`](https://github.com/python-websockets/websockets) | 16.1.1 | BSD-3-Clause | WebSocket protocol implementation behind uvicorn's `/agent` upgrade |
| [`anyio`](https://github.com/agronholm/anyio) | 4.14.2 | MIT | Structured concurrency primitives used by the bridge |
| [`httpx`](https://github.com/encode/httpx) | 0.28.1 | BSD-3-Clause | Pulled in by the MCP SDK |
| [`sse-starlette`](https://github.com/sysid/sse-starlette) | 3.4.6 | BSD-3-Clause | Server-sent events for the MCP Streamable HTTP response path |
| [`click`](https://github.com/pallets/click) | 8.4.2 | BSD-3-Clause | Command-line entry point |
| [`h11`](https://github.com/python-hyper/h11) | 0.16.0 | MIT | HTTP/1.1 state machine used by uvicorn and httpx |
| [`typing-extensions`](https://github.com/python/typing_extensions) | 4.16.0 | PSF-2.0 | Backported typing constructs |

---

## 3. What each licence requires of you

These obligations attach to **redistribution** — shipping the container image, publishing a
derived image, or distributing an installable package. Merely running WinShow for yourself
triggers none of them.

**MIT and BSD (2- and 3-clause).** Retain the copyright notice and the licence text in any
redistribution. This file plus the licence texts bundled in the distributed
`site-packages` — every wheel carries its own `LICENSE` in its `.dist-info` directory —
satisfies that. Do not remove those directories when slimming an image. BSD-3-Clause adds
that you may not use the project's name or its contributors' names to endorse a derived
product without permission.

**Apache-2.0** (`prometheus-client`). Retain the licence, retain any `NOTICE` file content
shipped with it, and state prominently that you changed the files if you modify them. The
patent grant terminates for anyone who initiates patent litigation over the covered work.
WinShow does not modify `prometheus-client`; it depends on the published wheel unmodified.

**PSF-2.0** (`typing-extensions`). Retain the notice and include a summary of any changes.
WinShow makes none.

**AGPL-3.0-or-later** (WinShow itself). §13 is the clause that distinguishes the AGPL from
the GPL and the one most likely to be overlooked here: if you modify WinShow and let others
interact with it **over a network**, you must offer those users the corresponding source of
your modified version. Running the stock image imposes nothing; running a patched one that
other people reach does.

---

## 4. Verifying this list

The list above is a human-readable summary and can drift from what is actually installed. The
authoritative answer comes from the environment itself:

```sh
pip install pip-licenses
pip-licenses --with-urls --with-license-file --format=markdown
```

Inside the published container image, every dependency's own licence text remains present in
its `.dist-info/` directory under `site-packages`:

```sh
docker run --rm --entrypoint sh ghcr.io/tmueller-dev/winshow:latest \
  -c 'find /usr/local/lib/python3.12/site-packages -name "LICENSE*" -path "*.dist-info*" | sort'
```

---

## 5. Development-only tools

Not redistributed, listed for completeness: `pytest` (MIT), `pytest-asyncio` (Apache-2.0),
`ruff` (MIT), `mypy` (MIT), `jsonschema` (MIT). These run in CI and on developer machines and
are absent from the runtime image, so their obligations never attach to a WinShow
distribution.
