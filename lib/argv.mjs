// Shared CLI argument hygiene, per https://clig.dev.
//
// Hand-rolled `args.includes("--json")` parsing silently ignores typos: until
// this module existed, `--jsom` ran a full human-mode scan and exited 0, which
// a CI job reads as a pass. Every flag a command accepts is registered with the
// parser so an unrecognized one is a hard error with a spelling suggestion.

// Every failure path here exits 1, which is what these CLIs have always
// returned for a failed command.
//
// sysexits.h EX_USAGE (64) would be more precise — 1 and 2 already mean
// "high-risk findings" and "critical findings" in decoy-scan and
// decoy-redteam, so a usage error is indistinguishable from a real result.
// But a published CLI's exit codes are part of its contract, and someone's
// pipeline may well branch on `$? -eq 1`. Introducing a new code to win some
// precision is not worth breaking a customer's deploy over. Change this one
// constant if that trade ever flips.
export const EXIT_USAGE = 1;

// Optimal string alignment distance: Levenshtein plus adjacent transposition
// as a single edit. Transposition is the typo people actually make — "josn"
// is one slip from "json", and plain Levenshtein scores it 2, far enough to
// suppress the suggestion exactly when it is most wanted. Inputs are flag
// names, so the full matrix costs nothing.
export function editDistance(a, b) {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

// Closest candidate, with a tolerance that scales with word length so short
// flags don't collide: "jsom" suggests "json", "xyzzy" suggests nothing.
export function nearest(input, candidates) {
  const limit = input.length <= 4 ? 1 : input.length <= 8 ? 2 : 3;
  const lower = input.toLowerCase();
  let best = null;
  let bestDistance = Infinity;
  // An abbreviation is a prefix, not a near-miss: "crit" is four edits from
  // "critical" but is obviously reaching for it. Prefixes win outright, and
  // the shortest matching candidate is the least presumptuous guess.
  const prefixed = candidates
    .filter((cand) => cand.toLowerCase().startsWith(lower) && cand.length !== lower.length)
    .sort((a, b) => a.length - b.length);
  if (lower.length >= 2 && prefixed.length > 0) return prefixed[0];
  for (const candidate of candidates) {
    const d = editDistance(lower, candidate.toLowerCase());
    if (d < bestDistance) {
      bestDistance = d;
      best = candidate;
    }
  }
  return bestDistance <= limit ? best : null;
}

// First unrecognized flag in argv, or null. Everything after a bare `--` is an
// upstream command line and is left alone. `known` holds names without leading
// dashes, covering both `--name` and `--name=value` spellings.
export function findUnknownFlag(argv, known) {
  for (const arg of argv) {
    if (arg === "--") break;
    if (arg === "-" || !arg.startsWith("-")) continue;
    const name = arg.replace(/^--?/, "").split("=")[0];
    if (name && !known.has(name)) return { arg, name };
  }
  return null;
}

function stderr(msg) {
  process.stderr.write(msg);
}

// Suggestions only ever name long flags — proposing "-y" for a mistyped
// "--yes" is not a useful correction.
export function reportUnknownFlag({ arg, name }, known, program, write = stderr) {
  const guess = nearest(name, [...known].filter((k) => k.length > 1));
  write(`error: unknown flag ${arg}\n`);
  if (guess) write(`  Did you mean --${guess}?\n`);
  write(`  Run \`${program} --help\` for the full list of flags.\n`);
}

export function reportUnknownCommand(command, commands, program, write = stderr) {
  const guess = nearest(command, commands);
  write(`error: unknown command "${command}"\n`);
  if (guess) write(`  Did you mean \`${program} ${guess}\`?\n`);
  write(`  Run \`${program} --help\` to see available commands.\n`);
}

// https://no-color.org: NO_COLOR disables color only when set to a non-empty
// value. An explicit --color wins over TTY detection, so piping into
// `less -R` or a CI log that renders ANSI still gets color.
export function resolveColor(argv, stream) {
  if (argv.includes("--no-color")) return false;
  if (argv.includes("--color")) return true;
  if (process.env.FORCE_COLOR) return true;
  if (process.env.NO_COLOR) return false;
  if (process.env.TERM === "dumb") return false;
  return !!stream.isTTY;
}

// Prompts are a convenience, never a requirement. With --no-input, or when
// stdin isn't a terminal, callers must fail with the flag that would have
// supplied the answer rather than blocking forever on a pipe.
export function canPrompt(argv) {
  return !!process.stdin.isTTY && !argv.includes("--no-input");
}

// Every network call gets a deadline. Without one, an unreachable API leaves
// the CLI spinning with no output and no way to tell hung from slow.
export function fetchWithTimeout(url, options = {}, ms = 15000) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(ms) });
}

export function isTimeoutError(err) {
  return err?.name === "TimeoutError" || err?.name === "AbortError";
}

// Ctrl-C stops now, not after the in-flight request finishes. The first INT
// clears the spinner, restores the cursor and runs cleanup under a hard cap; a
// second one skips the remaining cleanup and exits immediately.
export function onInterrupt(cleanup, { write = stderr, capMs = 2000 } = {}) {
  let interrupting = false;
  const handler = () => {
    if (interrupting) {
      write("\nForcing exit — cleanup skipped.\n");
      process.exit(130);
    }
    interrupting = true;
    write("\r\x1b[K\x1b[?25h");
    write("Interrupted.\n");
    const timer = setTimeout(() => process.exit(130), capMs);
    timer.unref?.();
    Promise.resolve()
      .then(cleanup)
      .catch(() => {})
      .finally(() => {
        clearTimeout(timer);
        process.exit(130);
      });
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
}
