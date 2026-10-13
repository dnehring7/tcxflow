# Coding Rules

README.md = architecture/build/tests; `src/flow.h` = the flow key/value shared with the BPF program; `src/meter.c` loads it through the bpftool skeleton (`build/tcxflow.skel.h`).
Build `make dev` (strict `-Werror`, GCC `-fanalyzer`; plain `make` is the lenient packaging build) · lint `make lint` (clang-tidy, shellcheck) · format `make indent` · all `make check` · `sudo make test-all` (BPF + e2e, root).

## Hard rules
- C23 (`gnu23`) for userspace and the BPF program, as far as GCC 14 and clang 19 (Debian 13) support it: no `#embed`. Single-threaded; signal handlers only set `stop_requested`.
- O(1) per packet and per flow: nothing walks all cached flows per tick, nothing allocates per packet. Memory is bounded (preallocated maps, fixed-size config, cache limit).
- BPF never drops or changes a packet: every path returns `TCX_NEXT`. Read headers only with `LOAD()`, check them against the IP length; malformed counts as `STAT_TRUNC`, never as a flow. Loops bounded (`#pragma unroll`); `flow_key`/`flow_val` without implicit padding (`static_assert`). Benchmark changes to `account()`: `bool` flags there cost 2-3 ns per packet.
- Check every return value; ignore one only with an explicit `(void)`. Public functions that return an error or their only result are `[[nodiscard]]`.
- Doxygen `@param`/`@return` on every public function (`make docs` fails otherwise). Comments say why, never what.
- Every fix gets a regression test: `tests/test_unit.c`, `tests/test_bpf.c` (BPF_PROG_TEST_RUN), `tests/test_bpf_native.c` (beyond 64 KiB, CPU races) or `tests/e2e.sh`.

## Conventions
- Files start with the SPDX line (`GPL-2.0-or-later`), copyright, `@file`/`@brief`. Includes: own header, system, `<bpf/...>`, project; include what you use.
- Exported names: module prefix + snake_case (`cache_add`, `CONFIG_MAX_IFACES`, `FLOW_DIR_IN`); file-local helpers `static`, unprefixed. Constants are typed `constexpr` (`static constexpr` in .c files) and carry their unit (`_NS`, `_LEN`); macros only for strings and function-like code; `///<` on constants and members.
- `nullptr`, `bool`, `= {}`, `[[maybe_unused]]`, `[[gnu::format]]`. Locals at the top of their block, initialized; `const` where possible; early returns.
- Errors: `0`/`-errno`, or `-1` with `errno`; text for the user in `char *err, size_t errlen`. `log_msg()` never per packet or per flow; log the first failure or the increase, not every repeat.
- Version: `TCXFLOW_VERSION` in `src/util.h` is the git tag (`vX.Y.Z`), `tcxflow.spec` the same without `v`.

## Lifecycle (match existing patterns)
- `*_init`/`*_open` pair with `*_destroy`/`*_close`: init leaves a valid empty state even when it fails; close works on a zeroed object and zeroes it.
- `start()` opens sockets in the original namespace, loads BPF, enters `netns`, attaches. `tick()` once per second: swap, drain, expire, flush. `stop()` detaches, drains both maps, exports everything, releases in reverse; exit status 1 when an interface or the namespace vanished, systemd restarts.
