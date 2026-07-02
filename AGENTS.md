This repo is a port of a sister repo, https://github.com/dhh1128/entviz, which
contains the entviz spec, other important documentation, and the reference impl
of entviz in Python. The repos are intended to be sister folders on disk and
may already exist in your dev environment. New features can be added here,
but should never violate the specification or the documentation about the
entviz technology that have their definitive embodiment in the entviz repo.

This is a **conformant Java port**: the canonical algorithm and spec live in
dhh1128/entviz; this module mirrors the certified Rust/Go ports
(dhh1128/entviz-rs, dhh1128/entviz-go) and is verified byte-for-byte against the
shared conformance corpus.

## Toolchain

This project targets **Java 21 (LTS)** and builds with **Maven**. The default
`java` on some dev machines is an old early-access build; use a real JDK 21
(e.g. Temurin). Set `JAVA_HOME` explicitly when invoking Maven if the PATH
`java` is not 21.

## Testing Protocol

This repository has an established JUnit 5 test suite. Follow strict TDD:

1. Write one or more failing tests that capture each requirement (including
   both happy paths and its edge cases/unhappy paths) before implementing.
2. Implement until all tests pass.
3. Never commit unless all tests pass. Coverage of any code you touch
   must not decrease.

The local gate mirrors CI:

```sh
mvn -B clean verify          # compiles on JDK 21, runs all JUnit tests + jacoco
```

Conformance (requires the sibling `../entviz` checkout + a Python venv with
lxml):

```sh
mvn -B -q compile
../entviz/.venv/bin/python -m compliance.runner \
  --impl-cmd "$PWD/bin/entviz-conformance" --tiers AB
# -> 54/54 vectors passed
# (run from inside ../entviz with PYTHONPATH=src:. )
```

`bin/entviz-conformance` is a thin wrapper that `exec`s `java` against the built
`target/classes` and reads one vector's JSON on stdin, writing the SVG to
stdout (exit 0) or exiting non-zero to reject.

## Versioning

The artifact version encodes the entviz **spec** level it is compliant with:

> **`0.<spec-major>.x`** — e.g. `0.10.x` ⇒ compliant with entviz spec **v10**
> (the same convention the Python reference, entviz-rs, and entviz-go use).

The canonical spec level is the `SPEC_VERSION` constant in `Core.java` (exposed
as `Entviz.SPEC_VERSION`); the per-impl stamp emitted as `data-entviz-lib` is
the `LIB_VERSION` constant (`Entviz.LIB_VERSION`).

## CI and Documentation

This repo has CI under `.github/workflows/` (`ci.yml` runs `mvn verify` on
JDK 21 plus a Tier-A/B conformance job against the reference corpus;
`release.yml` is the tag-triggered Maven Central publish pipeline). Treat CI as
part of the code you maintain, not an afterthought:

- Before you consider a change done, run the same gate CI runs locally.
- When you add or change behavior, keep the workflows in sync.

When writing or modifying GitHub Actions workflows, always SHA-pin every
third-party action to a node24-runtime (or composite/docker) release. Avoid
versions pinned to Node.js 16 or 20 (both deprecated by GitHub). Check the
GitHub Marketplace for each action's current release.

<!-- >>> tick stanza >>> (managed by `tick init`) -->

## Task tracking: `tick`

This repo tracks tasks, tech debt, and ideas in a local [`tick`](https://github.com/dhh1128/tick)
ledger (an orphan `tick` branch; the `tick` CLI is the interface). Reads are plain
files — do **not** use an external API for task tracking.

- **First, if a `tick` command says the repo isn't initialized**, run `tick init`
  once to connect this clone to the ledger — it adopts the existing remote ledger
  if a colleague already set one up, or creates a new one otherwise.
- **A tick mark is the sigil `~` immediately followed by a digit-first 4-char
  base32 id** (the id part looks like `4mz3`, so the full mark is that id with a
  leading `~`). It pins a tick to a code location.
- **Before editing a file**, grep it for marks and read what they reference:
  `rg '~[2-7][a-z2-7]{3}\b' <file>` then `tick show <id>`. A mark means recorded
  context exists for that spot — read it first.
- **Search** existing ticks with `tick grep <text>`; **list** with `tick ls`.
- **Capture** new work with `tick add "<title>"` and place the printed mark
  (`~` + the new id) at the relevant code spot.
- When your change **resolves** a tick, run `tick off <id>` and **delete the
  mark(s)** it reports still in the code.

<!-- <<< tick stanza <<< -->
