# Native authentication development builder

Repository-owned **development/build infrastructure only**. This supplies actual
distribution Polkit/GLib headers and libraries for the S17 native adapter; it
does not vendor headers or implement an alternative authentication ABI.

`contract.json` pins a single Linux/amd64 official Ubuntu-based noble-curl
buildpack image manifest and archive snapshot. The immutable base supplies its
CA trust store; all new package acquisition uses only the HTTPS snapshot and
Ubuntu's signed archive keyring. TLS and signature checks are never disabled,
and any failed index acquisition fails the build rather than using stale data.
The installed package/version inventory is retained inside the image; its complete
graph SHA-256 and exact compiler/CMake/Ninja/pkg-config/scanner/Python/module versions are
pinned in the contract and rechecked against actual native tools. Dependency
selection is reproducible from these fixed inputs; this is not a claim of
bit-identical Docker images or application binaries.

Image creation is an explicit environment-preparation action, never a task-time
repair of an existing environment. This does not replace the Codex Rust preflight,
full gates, Security, CodeQL, or the pinned Arch native qualification substrate.
Official Wayland protocol bindings are generated in the build directory from the
snapshot-pinned distribution XML, not copied into the repository. The private
presentation renderer uses the matching exact Qt QML runtime packages from that
same snapshot. Their installed status/version and the full package graph are
checked; no user QML imports or separately selected desktop stack are installed.
The actual first-party UI component sources are a separate read-only source mount.
The canonical private D-Bus XML is another read-only source input; compiled Qt
metadata and registered wire signatures must match it exactly in component tests.
The locker owns its exclusive native connection; Qt supplies presentation rather than
a second protocol reader. No PAM/account, system-bus, login-session, compositor, privileged
executor, suspend/resume, VM, visual or hardware qualification is implied.
Every readiness report sets `qualification_evidence` to false.

From the repository root, create the image (network is needed only for image
creation). The restricted build context never uploads the checkout, `.git`,
credentials, product binaries, or development caches to the Docker builder:

```sh
docker build --platform linux/amd64 --tag linura-native-auth:20261006 \
  tools/codex/native-auth
```

Create a separate named container using the built immutable image ID. Source is
read-only. The container has no network, host/system/session sockets, devices,
credentials, extra capabilities or writable host mounts. All build outputs stay
in bounded private tmpfs; removing the container discards those outputs.

```sh
S17_BUILD_IMAGE=$(docker image inspect --format '{{.Id}}' linura-native-auth:20261006)
docker run --detach --platform linux/amd64 --name linura-s17-native-auth \
  --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --cpus 2 --memory 2g --memory-swap 2g \
  --pids-limit 256 --ulimit core=0 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000 \
  --tmpfs /build:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000 \
  --mount "type=bind,source=$PWD/apps/linura-shell/security-owner,target=/source/security-owner,readonly" \
  --mount "type=bind,source=$PWD/apps/linura-shell/ui,target=/source/ui,readonly" \
  --mount "type=bind,source=$PWD/interfaces/dbus/org.linura.SecurityOwner1.xml,target=/source/contracts/org.linura.SecurityOwner1.xml,readonly" \
  --mount "type=bind,source=$PWD/packaging,target=/source/packaging,readonly" \
  "$S17_BUILD_IMAGE"
docker exec linura-s17-native-auth python3 /opt/linura-native-auth/check.py --json
docker exec linura-s17-native-auth cmake -S /source/security-owner \
  -B /build/security-owner -G Ninja -DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON \
  -DLINURA_SECURITY_OWNER_CONTRACT=/source/contracts/org.linura.SecurityOwner1.xml \
  -DLINURA_SECURITY_OWNER_PACKAGING_DIR=/source/packaging
docker exec linura-s17-native-auth cmake --build /build/security-owner --parallel 2
docker exec linura-s17-native-auth ctest --test-dir /build/security-owner --output-on-failure
```

Image creation itself runs the same readiness checker with network disabled.
The named `native-auth-dependencies` stage retains the signed package inventory
for pin-maintenance diagnostics. It is not the checked final builder; development
and CI use the default final stage, whose exact-graph and capability checks must
pass. The inventory hash is over the actual `dpkg-query` output order, including
its final newline; do not derive it from a differently sorted prediction.
Readiness is fail-closed: wrong platform/UID/distribution/Python/module versions,
missing build tools or incompatible **official** headers produce nonzero status.
The checker does not install anything or expose raw compiler diagnostics. CMake
builds against official dependencies without the component-only auth omission.
Passing component tests remain component results, not native qualification.
The private build tmpfs is explicitly executable so generated test binaries can
run; `/tmp` remains non-executable. Neither mount can supply setuid/device authority.
Canonical CI executes the same recipe/checks/build/tests without any host daemon,
PAM conversation or qualification producer; the build context and source mount
exclude checkout credentials. Container lifetime does not define reproducibility:
the checked-in recipe and pins do, for both a persistent developer container and
an isolated CI invocation.

Update the base digest, signed snapshot and exact capability pins together through
review. Do not use mutable image tags as dependencies, ambient SDK paths, latest
packages, vendored headers, fake authentication or ignored build failures.
