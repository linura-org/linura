# Embedded Unicode Compose table

`en_US.UTF-8` is the complete X.Org libX11 Compose table shipped by Ubuntu
Noble package `libx11-data` version `2:1.8.7-1build1`, obtained from the
official Ubuntu archive snapshot `20261006T000000Z`.

Its canonical SHA-256 is:

```text
272667553c5abc2e7940507502963092defbdaa52740a59efc1acfdfe1f4cef2
```

The table is compiled into the native input component. Runtime code accepts only
those exact embedded bytes and does not consult locale, home/XDG paths,
`XCOMPOSEFILE`, filesystem Compose data or recursive includes. `LICENSE` retains
the distribution's complete libX11 copyright and license notice.

Updating this asset requires reviewing the upstream table and license, changing
the source digest in `native_compose.cpp`, exercising the positive and malformed
Compose tests, and rerunning the full canonical CI and applicable workstation
qualification gates on the final exact source.
