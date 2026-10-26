#pragma once

#include "session_bootstrap.h"

#include <QByteArrayView>
#include <QByteArray>
#include <QString>

#include <optional>

namespace Linura::SecurityOwner {

// Adapter-local postcondition, not a portable observation envelope, policy
// approval, or authority. The production adapter emits canonical evidence only
// after revalidating its original native session/actual Wayland connection.
enum class NativeCompositorLockState { Locked, Unlocked };

// Fixed nonsecret failure categories; never path, peer IDs, errno text or reply bytes.
enum class NativeCompositorProbeFailure {
    None,
    Binding,
    Route,
    Socket,
    Connect,
    Peer,
    Send,
    Receive,
    Deadline,
    Reply,
    ReplyLimit
};

[[nodiscard]] std::optional<NativeCompositorLockState>
decodeNativeHyprlandLock(QByteArrayView reply);

// The private runtime obtains this route from its qualified native launch
// configuration; no public client/QML/model supplies a socket path. Even a
// substituted pathname cannot supply evidence: the actual connected fd's peer
// must be the same compositor UID/PID as the actual Wayland session binding.
// One read-only j/locked request, fixed 500ms total deadline, at most 64 bytes.
[[nodiscard]] std::optional<NativeCompositorLockState>
observeNativeHyprlandLock(const QString &nativeSocketPath, const NativeSessionBinding &binding,
                          NativeCompositorProbeFailure *failure = nullptr);

// Fixed read-only native monitor metadata, on a freshly connected stream whose
// peer must equal the actual owned Wayland compositor. At most 256 KiB and the
// same 500 ms total deadline. Typed decoding belongs to the Rust adapter.
[[nodiscard]] std::optional<QByteArray>
observeNativeHyprlandOutputs(const QString &nativeSocketPath, const NativeSessionBinding &binding);

} // namespace Linura::SecurityOwner
