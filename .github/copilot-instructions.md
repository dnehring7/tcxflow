# Coding Rules

Docs: README.md. `src/flow.h`: key/value shared with BPF; `src/meter.c` loads it via `build/tcxflow.skel.h`.
`make dev` (strict), `make lint`, `make indent`, `make check`; root: `sudo make test-all`.

## Hard rules
- C23 (`gnu23`) as GCC 14 / clang 19 support it: no `#embed`. Single-threaded; signal handlers only set `stop_requested`.
- O(1) per packet and flow: no walk over all flows, no per-packet allocation; memory bounded.
- BPF: always `TCX_NEXT`; headers only via `LOAD()`, checked against the IP length; malformed = `STAT_TRUNC`; bounded loops; `flow_key`/`flow_val` without implicit padding. Benchmark `account()` changes (`bool` costs 2-3 ns/packet).
- Check every return value, `(void)` to ignore. `[[nodiscard]]` on public functions returning an error or result.
- Doxygen `@param`/`@return` on public functions. Comments compact, why not what.
- Every fix gets a regression test: `tests/test_unit.c`, `test_bpf.c`, `test_bpf_native.c` or `e2e.sh`.

## Conventions
- SPDX `GPL-2.0-or-later`, copyright, `@file`/`@brief`. Includes: own header, system, `<bpf/...>`, project; IWYU.
- Exports: module prefix + snake_case; static helpers unprefixed. Typed `constexpr` with unit (`_NS`, `_LEN`); macros only for strings and function-like code; `///<` on constants and members.
- `nullptr`, `bool`, `= {}`, `[[maybe_unused]]`, `[[gnu::format]]`; initialized locals at block top; `const`; early returns.
- Errors: `0`/`-errno` or `-1` + `errno`; user text via `char *err, size_t errlen`. Never log per packet/flow: first failure or increase only.
- `TCXFLOW_VERSION` (`src/util.h`) = git tag `vX.Y.Z`; `tcxflow.spec` without `v`.

## Lifecycle
- `*_init`/`*_open` pair with `*_destroy`/`*_close`: a failed init leaves a valid empty state; close works on and zeroes a zeroed object.
- `start()`: sockets in the original netns, load BPF, enter netns, attach. `tick()` 1/s: swap, drain, expire; flush every `export-interval`. `stop()`: detach, drain both maps, export all, release in reverse; exit 1 if an interface/netns vanished.
