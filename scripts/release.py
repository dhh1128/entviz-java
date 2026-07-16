#!/usr/bin/env python3
"""Cut an entviz-java release: bump version, run the gate, commit, push, tag.

HUMAN-run by default: pushes to main and tags are reserved for a human
maintainer. An AI agent may run this script ONLY when a human has explicitly
instructed it to cut a release.

The version follows a spec-tracking convention: 0.<spec-major>.x means "this
artifact is compliant with entviz spec v<spec-major>" (so 0.10.x => spec v10,
matching the Python reference's 0.10.0). A spec bump (v10 -> v11) is therefore a
MINOR bump here (0.10.x -> 0.11.0); patch covers code-only changes within a spec
version. The script warns if the sibling entviz reference (../entviz) is on a
newer spec than this artifact claims.

The version source of truth is the <version> in pom.xml and the LIB_VERSION
constant in src/main/java/io/github/dhh1128/entviz/Core.java; both are updated
together. After the tag reaches GitHub, .github/workflows/release.yml re-runs
the gate, verifies the tag matches the POM, and deploys to Maven Central.

Usage:
    python scripts/release.py                       # patch bump, default message
    python scripts/release.py -m "fix parser bug"   # patch bump, custom message
    python scripts/release.py --minor -m "spec v11" # minor bump (e.g. spec bump)
    python scripts/release.py --major -m "1.0"      # major bump
    python scripts/release.py --set 0.10.0 -m "..." # set an explicit version
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
POM = REPO_ROOT / "pom.xml"
CORE_JAVA = REPO_ROOT / "src" / "main" / "java" / "io" / "github" / "dhh1128" / "entviz" / "Core.java"
ENTVIZ_REF = REPO_ROOT.parent / "entviz"


def run(cmd, *, capture=False, check=True):
    return subprocess.run(cmd, capture_output=capture, text=True, check=check, cwd=REPO_ROOT)


def get(cmd):
    return run(cmd, capture=True).stdout.strip()


def current_version():
    # The project's own <version>, which is the first <version> after the
    # <artifactId>entviz</artifactId> coordinate line.
    text = POM.read_text()
    m = re.search(r"<artifactId>entviz</artifactId>\s*<version>([^<]+)</version>", text)
    if not m:
        sys.exit("Could not find project <version> in pom.xml")
    return m.group(1)


def set_version(new_version):
    text = POM.read_text()
    updated, count = re.subn(
        r"(<artifactId>entviz</artifactId>\s*<version>)[^<]+(</version>)",
        rf"\g<1>{new_version}\g<2>",
        text,
        count=1,
    )
    if count != 1:
        sys.exit("Version substitution in pom.xml had no effect.")
    POM.write_text(updated)

    ctext = CORE_JAVA.read_text()
    cupdated, ccount = re.subn(
        r'(LIB_VERSION\s*=\s*)"[^"]+"',
        rf'\g<1>"{new_version}"',
        ctext,
        count=1,
    )
    if ccount != 1:
        sys.exit("Version substitution in Core.java had no effect.")
    CORE_JAVA.write_text(cupdated)


def bump(version, part):
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def parse_explicit_version(value, current, *, allow_major_jump=False):
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        sys.exit(f"--set expects X.Y.Z (got {value!r}).")
    as_tuple = lambda v: tuple(int(p) for p in v.split("."))  # noqa: E731
    new, cur = as_tuple(value), as_tuple(current)
    if new < cur:
        sys.exit(f"--set {value} is older than current {current}; refusing to downgrade.")
    # new == cur is allowed: a first release (or re-cut) of the version the POM
    # already carries. ensure_tag_unused() guards the real footgun — re-releasing
    # a version whose tag already exists.
    if new[0] - cur[0] > 1 and not allow_major_jump:
        sys.exit(
            f"--set {value} raises the major version by more than one step — "
            f"almost always a typo. Re-run with --allow-major-jump if intentional."
        )
    return value


def spec_version_of(path, pattern):
    try:
        m = re.search(pattern, path.read_text())
        return m.group(1) if m else None
    except OSError:
        return None


def warn_if_behind_spec():
    ours = spec_version_of(CORE_JAVA, r'SPEC_VERSION\s*=\s*"v(\d+)"')
    ref = spec_version_of(ENTVIZ_REF / "src" / "entviz" / "__init__.py",
                          r'SPEC_VERSION\s*=\s*"v(\d+)"')
    if ours and ref and int(ref) > int(ours):
        print(
            f"\n  WARNING spec drift: the entviz reference is on spec v{ref}, but this "
            f"artifact targets v{ours}.\n      Releasing now ships an artifact that is "
            f"behind the spec. Upgrade first, or release knowingly.\n"
        )


def check_branch():
    branch = get(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    if branch != "main":
        sys.exit(f"Must be on main branch (currently on {branch!r}).")


def check_clean():
    if run(["git", "status", "--porcelain"], capture=True).stdout.strip():
        sys.exit("Working tree is not clean. Commit or stash changes first.")


def ensure_tag_unused(tag):
    """Refuse to re-release a version whose tag already exists (local or origin)."""
    if get(["git", "tag", "-l", tag]):
        sys.exit(f"Tag {tag} already exists locally — that version is already released.")
    if run(["git", "ls-remote", "--tags", "origin", tag], capture=True).stdout.strip():
        sys.exit(f"Tag {tag} already exists on origin — that version is already released.")


def check_in_sync():
    run(["git", "fetch", "--quiet"])
    if get(["git", "rev-parse", "HEAD"]) != get(["git", "rev-parse", "origin/main"]):
        ahead = get(["git", "rev-list", "--count", "origin/main..HEAD"])
        behind = get(["git", "rev-list", "--count", "HEAD..origin/main"])
        sys.exit(
            f"Local main is not in sync with origin/main "
            f"({ahead} ahead, {behind} behind). Push or pull first."
        )


def run_gate():
    """The same gate CI enforces."""
    print("Running the gate (mvn clean verify)...")
    run(["mvn", "-B", "clean", "verify"])


def prompt_message(part):
    if not sys.stdin.isatty():
        sys.exit(f"--{part} release requires a commit message; pass -m '<message>'.")
    try:
        msg = input(f"Commit message for {part} release: ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\nAborted.")
    if not msg:
        sys.exit("Commit message cannot be empty.")
    return msg


def main():
    parser = argparse.ArgumentParser(
        description="Cut a release. Defaults to --patch if no bump flag is given.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--major", dest="part", action="store_const", const="major")
    group.add_argument("--minor", dest="part", action="store_const", const="minor")
    group.add_argument("--patch", dest="part", action="store_const", const="patch")
    group.add_argument("--set", dest="explicit", metavar="X.Y.Z", default=None,
                       help="set an explicit version instead of bumping; must be >= current "
                            "(equal is allowed for a first release if its tag does not exist)")
    parser.add_argument("--allow-major-jump", action="store_true",
                        help="permit --set to raise the major version by more than one step")
    parser.add_argument("-m", dest="message", default=None, help="commit message")
    args = parser.parse_args()

    old = current_version()
    if args.explicit:
        new = parse_explicit_version(args.explicit, old, allow_major_jump=args.allow_major_jump)
        label = "set"
    else:
        label = args.part or "patch"
        new = bump(old, label)

    tag = f"v{new}"

    if args.message:
        message = args.message
    elif label == "patch":
        message = "misc fixes/enhancements"
    else:
        message = prompt_message(label)

    check_branch()
    check_clean()
    check_in_sync()
    ensure_tag_unused(tag)
    warn_if_behind_spec()
    run_gate()

    if new != old:
        verb = "Setting" if args.explicit else "Bumping"
        print(f"{verb} {old} -> {new}")
        set_version(new)
        run(["git", "add", "pom.xml", str(CORE_JAVA.relative_to(REPO_ROOT))])
        run(["git", "commit", "-s", "-m", f"Release {tag}: {message}"])
        run(["git", "push", "origin", "main"])
    else:
        print(f"pom.xml already carries {new}; tagging the current commit "
              f"(no version-bump commit needed for this first release).")
    run(["git", "tag", "-a", tag, "-m", f"Release {tag}: {message}"])
    run(["git", "push", "origin", tag])

    print(f"Tagged and pushed {tag}. The release workflow will gate + publish to "
          f"Maven Central via the Central Portal.")


if __name__ == "__main__":
    main()
