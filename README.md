# entviz-java

[![CI](https://github.com/dhh1128/entviz-java/actions/workflows/ci.yml/badge.svg)](https://github.com/dhh1128/entviz-java/actions/workflows/ci.yml)
[![Release](https://github.com/dhh1128/entviz-java/actions/workflows/release.yml/badge.svg)](https://github.com/dhh1128/entviz-java/actions/workflows/release.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.dhh1128/entviz.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.dhh1128/entviz)
[![javadoc](https://javadoc.io/badge2/io.github.dhh1128/entviz/javadoc.svg)](https://javadoc.io/doc/io.github.dhh1128/entviz)
[![Spec](https://img.shields.io/badge/entviz%20spec-v10-informational)](https://github.com/dhh1128/entviz/blob/main/docs/spec.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Java implementation of [entviz](https://github.com/dhh1128/entviz) (spec **v10**)
— visualize high-entropy values as comparable SVG diagrams.

## Status: certified against the v10 conformance corpus ✅

A full, self-contained implementation that passes the shared conformance corpus
at **Tier A** (render model) **+ Tier B** (canonical raster) for every render
vector and rejects every error vector (**54/54**). It depends only on the Java
standard library (Keccak-256 is implemented in-tree; SHA-512 comes from the
JDK). What's here:

- **`Core.java`** — the deterministic shared core: alphabets, tokenization +
  24-bit quant extension, the SHA-512 fingerprint, ftok median/quartile
  selection, the Oklab color rules + weighted-RGB edge selection, and grid
  selection.
- **`Entropy.java`** — the format-specific parsers (hex, UUID, Ethereum w/
  EIP-55, ULID, base58 / bech32 / base32 chains, CESR, LEI, snowflake, SWHID /
  gitoid semantic-prefix fold, IPFS CID, SSH, …) + the disproof-based alphabet
  detection and large-input (head / fingerprint-middle / tail) tokenization.
- **`Keccak.java`** — vendored Keccak-256 for EIP-55 checksum validation (the
  original Keccak padding, **not** NIST SHA3-256).
- **`Pipeline.java`** — the SVG renderer: geometry, 24-box surround,
  fingerprint-edge cells, ellipse overlay, color bar + markers, blank-cell map,
  quartile marks, labels, borders — emitting the normative `data-*` profile.
- **`Entviz.java`** — the public API (`Entviz.render`).
- **`cli/Conformance.java`** — the conformance CLI (the stdin→stdout contract in
  the entviz repo's `compliance/README.md`), driven by a dependency-free JSON
  reader.

## How to consume

Add the dependency (Maven):

```xml
<dependency>
  <groupId>io.github.dhh1128</groupId>
  <artifactId>entviz</artifactId>
  <version>0.10.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("io.github.dhh1128:entviz:0.10.0")
```

Then render:

```java
import io.github.dhh1128.entviz.Entviz;
import io.github.dhh1128.entviz.RenderOptions;

// Defaults: aspect ratio 1.0, 12pt, no note.
String svg = Entviz.render("a1b2c3d4e5f6a7b8");

// Or with options: RenderOptions(targetAspectRatio, fontSizePt, note).
String wide = Entviz.render("a1b2c3d4e5f6a7b8",
        new RenderOptions(2.0, 12.0, "wallet"));
```

`render` throws a `RenderException` for rejected inputs: out-of-range parameters
(font size must be 6–30 pt, aspect ratio 0.01–100), notes that are not printable
ASCII (U+0020–U+007E) or longer than 10 code points, and Ethereum addresses
whose EIP-55 mixed-case checksum is invalid (the `Eip55RenderException` subtype
names the first mismatched-case position via `position()`).

### Entropy characterization

Every rendered SVG carries the structured [entropy characterization](https://dhh1128.github.io/entviz/integration-guide/#the-characterization-model)
on its root `<svg>` element as `data-*` attributes (`data-encoding`,
`data-scheme`, `data-role`, `data-qualifiers`, `data-size-basis`,
`data-size-bits`, `data-parts`, `data-entropy-type`). The Java port exposes the
characterization through those attributes rather than a public `characterize`
function — parse the returned SVG (e.g. with your XML reader of choice) and read
them off the root element. For the field-by-field model and how the other four
languages expose it directly, see the
[Developer Integration Guide](https://dhh1128.github.io/entviz/integration-guide/).

## Build + test

Requires **JDK 21** and Maven.

```sh
mvn -B clean verify          # compiles on JDK 21, runs all JUnit tests + jacoco
```

Conformance against the golden corpus (requires a checkout of the entviz
reference repo as a sibling `../entviz` and a Python venv with `lxml`):

```sh
mvn -B -q compile

# from a checkout of the entviz reference repo (sibling ../entviz):
PYTHONPATH=src:. python -m compliance.runner \
  --impl-cmd "$PWD/../entviz-java/bin/entviz-conformance" --tiers AB
# -> 54/54 vectors passed
```

`bin/entviz-conformance` is a thin wrapper that `exec`s `java` against the built
`target/classes`.

## Spec compliance & versioning

The artifact version encodes the entviz **spec** level it is compliant with:

> **`0.<spec-major>.x`** — e.g. `0.10.x` ⇒ compliant with entviz spec **v10**
> (the same convention the Python reference, entviz-rs, and entviz-go use, where
> spec v10 ↔ `0.10.0`).

A spec bump (v10 → v11) is a **minor** release here (`0.10.x` → `0.11.0`); a
**patch** is a code-only change within a spec version. The canonical spec level
is the `SPEC_VERSION` constant in `Core.java` (exposed as `Entviz.SPEC_VERSION`);
the per-impl stamp emitted as `data-entviz-lib` is `LIB_VERSION`
(`Entviz.LIB_VERSION`).

## Releasing

Releases are **human-run** and publish to **Maven Central** via the Sonatype
[Central Portal](https://central.sonatype.com). From a clean, in-sync `main`,
bump the version (in `pom.xml` and the `LIB_VERSION` constant in `Core.java`),
commit, then tag and push:

```sh
git tag v0.10.0
git push origin v0.10.0
```

The tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which re-runs the full gate (`mvn verify` + Tier-A/B conformance), then runs
`mvn deploy -Prelease` to publish the signed artifact (jar + sources + javadoc).
Publishing requires repo secrets the maintainer supplies — a Central Portal user
token and a GPG signing key:

- `CENTRAL_TOKEN_USERNAME` / `CENTRAL_TOKEN_PASSWORD` — the Central Portal token,
  wired to a `<server id="central">` entry in `settings.xml`.
- `MAVEN_GPG_KEY` / `MAVEN_GPG_PASSPHRASE` — the ASCII-armored signing key and
  its passphrase for `maven-gpg-plugin`.

The `release` Maven profile (off by default, so a plain `mvn verify` needs no
secrets) carries the `maven-source-plugin`, `maven-javadoc-plugin`,
`maven-gpg-plugin`, and the `central-publishing-maven-plugin`.

## Sister projects

- **[entviz](https://github.com/dhh1128/entviz)** — the Python reference
  implementation and the **canonical spec**
  ([`docs/spec.md`](https://github.com/dhh1128/entviz/blob/main/docs/spec.md)),
  plus the [gallery](https://github.com/dhh1128/entviz) and the shared
  conformance corpus this module is certified against.
- **[entviz-rs](https://github.com/dhh1128/entviz-rs)** — the certified Rust
  port.
- **[entviz-go](https://github.com/dhh1128/entviz-go)** — the certified Go port.
- **[entviz-js](https://github.com/dhh1128/entviz-js)** — the certified
  TypeScript/JavaScript port.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
