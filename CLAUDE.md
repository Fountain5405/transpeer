# transpeer — notes for contributors and agents

Invariants and traps that have already cost time. Session status lives in
`.claude/HANDOFF.md`; the scientific record in `docs/manuscript.md`.

## Running code

- The system `python3` on the current box is 3.8. The codebase needs
  3.10+. Use `.venv/bin/python` (3.12, created with `uv venv`). Every
  generator and runner reads the interpreter from `sim/simenv.sh`
  (`TRANSPEER_PYTHON`); do not hardcode `python3`.
- A git worktree of this repo needs two symlinks before anything runs:
  `.venv -> <main checkout>/.venv` and
  `equix/libequix.so -> <main checkout>/equix/libequix.so`. Both are
  build artifacts and must not be committed.

## Simulations

- **Never edit a checkout while a Shadow experiment is running from it.**
  bash reads `run_experiment.sh` incrementally, and the config generator
  and the `transpeer` package are re-read at the start of every scenario.
  Prepare the next experiment in a separate worktree.
- Machine-specific paths (Shadow binary, interpreter, storage roots,
  worker count) come from `sim/simenv.sh`, overridable from the
  environment. Do not put absolute paths in generators or runners.
- Simulation output must not go under home. `SIM_DATA_ROOT` points at the
  fast work volume. Commit `configs/*.yaml`, `results*.txt` and READMEs
  only; runners compress per-host logs after parsing.
- Shadow derives every simulated host's randomness from the config's
  `general.seed`. Two runs of one config are identical **only at the same
  `general.parallelism`**: changing the worker count changes event
  ordering between hosts and shifts timing-dependent metrics by a few
  points (measured, manuscript §10). Keep the worker count fixed within
  an experiment; the results header records it. A replica is a different
  seed at the same worker count; `gen_config.py` sets `general.seed` from
  `--seed`.
- Per-host stderr is `hosts/<name>/python3.12.1000.stderr`; result parsers
  glob that name. If the interpreter basename changes, they break.
- `pgrep -f` / `pkill -f` with a pattern that appears in your own command
  line matches your own shell. Exclude `$$` or use a pattern that cannot
  appear in the invoking command.
- The runner's memory guard uses a per-host estimate. Measured cost grows
  with host count (33 MB at 700 hosts, 52 MB at 3000) and the guard
  ignores swap.
- **Every simulation generator passes `--scan-legacy` to transpeer
  nodes.** The production scan profile is paced (4 probes/s) and stops
  once 3 transpeers have answered; the legacy profile (bursts of 500 per
  10 s, no backoff, no daemon-peer probing) is what every result in
  `docs/manuscript.md` was measured under. A new generator without the
  flag produces cells that are not comparable to any existing row.

## Protocol code

- Defense policies are behind flags that default off (`--bucketed`,
  `--vouchers`, `--tried-table`, `--handoff-reserve`, `--native-vouchers`,
  `--subnet-prefix`). Existing experiments depend on the defaults staying
  unchanged. The scanning-etiquette defaults (`--scan-rate`,
  `--scan-idle-rate`, `--scan-target-known`, sensitive-range exclusion)
  are production defaults and are deliberately *not* off; simulations
  opt out with `--scan-legacy`. `tests/test_bucketed.py` pins
  the default behaviour, including the current policy's known weaknesses;
  a failure there after a "fix" is the test doing its job.
- The peer-extraction loop caches each local peer's EquiX proof per
  6-hour timestamp bucket. Re-solving per cycle costs one solve per peer
  per minute in production and, in simulation, blocks the node in a sleep.

## Recording results

- Each experiment folder under `sim/tests/` carries `gen_config.py`,
  `run_experiment.sh`, committed configs, a results CSV whose header
  records machine, seed and simulated time, and a README with the
  interpretation at the time.
- After every experiment, update `docs/manuscript.md`: result table with
  its results file, claims ledger (measured / extrapolated / hypothesis),
  Appendix A for any corrected conclusion, and the commit table.
