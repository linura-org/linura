# Linura for Python

**The intelligent system layer for Linux.**

`linura` is the canonical Python package for the
[Linura](https://linura.org) project.

The initial package is intentionally narrow. It provides canonical project and
Experimental `Control1` contract metadata plus local `linuractl` discovery
without executing the CLI. It does not duplicate Linura's authority, policy,
provider, executor, verification, or persistence logic.

## Install

```bash
python -m pip install linura
```

## Use

```python
import linura

print(linura.__version__)
print(linura.CONTROL1_SERVICE)

installation = linura.find_installation()
if installation is not None:
    print(installation.linuractl)
```

`find_installation()` performs executable discovery only. It does not invoke
`linuractl`, connect to D-Bus, or request system changes.

## Publication

Normal PyPI publication is not driven by a package-specific tag or by a second
release build path. Trusted Release Proof builds the wheel from the exact authorized
Linura release source using Python 3.12.10 and a hash-locked wheels-only build-toolchain
lock for pip plus every PEP 517 build requirement, with build isolation disabled
and a fixed wheel timestamp epoch. It seals that wheel into the
promotable payload, independently reproduces it byte-for-byte under the same pinned
toolchain, and attests it. The fixed wheel epoch and build-toolchain lock keep an
unchanged independently versioned Python package byte-identical across later Linura
releases.

Before any immutable GitHub publication, Release queries the exact PyPI package
version. An absent version is eligible for Trusted Publishing; an existing
version must already have exactly the same complete filename set and SHA-256
bytes as the sealed artifacts. Exact existing bytes are reused without another
upload. Extra, yanked, or mismatched distributions fail closed. Independent
release verification repeats the complete-set check and freshly downloads every
sealed PyPI artifact before terminal release handoff. The only job allowed to mint
PyPI OIDC credentials is a minimal GitHub Environment named `pypi`; artifact
preflight and post-publication verification run without OIDC authority.

The initial namespace claim has one explicitly bounded exception: `release.yml`
may be manually dispatched in `bootstrap-pypi` mode only for `linura==0.0.1`.
That path requires the exact current protected-`main` SHA and successful native
main CI/Security/CodeQL, builds only `bindings/python`, uses the same hash-locked
Python 3.12.10 toolchain and fixed wheel epoch, independently reproduces the wheel
byte-for-byte, and then hands the verified wheel to the same minimal `pypi`
Environment job used by normal releases. It creates no Linura version tag, GitHub
Release, crates.io publication, release closure, or broader product artifact. After
the first verified PyPI publication, this bootstrap mode is removed.

## Compatibility

This package is currently pre-1.0 and its public surface is intentionally
small while the Python client transport is designed against Linura's versioned
public contracts.

`org.linura.Control1` remains Experimental. The package must not be interpreted
as a second authority plane or as a way to bypass Linura Control.

## Links

- [Website](https://linura.org)
- [Source](https://github.com/linura-org/linura)
- [Documentation](https://github.com/linura-org/linura/blob/main/docs/index.md)
- [Issues](https://github.com/linura-org/linura/issues)

## License

Apache-2.0.
