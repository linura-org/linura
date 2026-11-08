#pragma once

#include "compositor_display_service.h"
#include "native_first_frame_gate.h"

#include <string>
#include <cstddef>
#include <optional>
#include <memory>
#include <string_view>
#include <vector>

struct wl_display;
namespace Monitor {
class CMonitor;
}
namespace Config {
class CMonitorRule;
}

namespace Linura::HyprlandDisplay {
class OriginalFinalizationGrant;
class OwnedNativeFd;
[[nodiscard]] std::unique_ptr<OriginalFinalizationGrant>
receiveOriginalFinalizationGrant(OwnedNativeFd, const Correlation &, std::string_view material,
                                 std::uint64_t sampledBootMs);
[[nodiscard]] bool originalRestorationPresented(const Correlation &);
// Read-only actual DRM/KMS connector observations from the SAME pinned
// compositor, original supervised Root channel and unchanged output inventory.
// This is NOT a native release attempt, grant, frame-completion receipt, or
// Control authority. The release consumer must still verify each actual native
// buffer/commit and match fresh post-spend output high-water marks.
[[nodiscard]] std::optional<std::vector<NativeFirstFrameGate::NativeScanout>>
nativeFirstFrameKernel(const Correlation &original, const Snapshot &expected);
// Arm the comparison-only gate against the same pinned original Recovery,
// KMS evidence, Root channel and retained safety frames. Does not spend
// a grant or establish output-wide spend-time high-water.
using NativeFirstFrameArm = std::optional<NativeFirstFrameGate>;
using NativeOutputCommits = std::optional<std::vector<NativeFirstFrameGate::Output>>;
[[nodiscard]] NativeOutputCommits nativeOutputHighWater(const Correlation &, const Snapshot &);
[[nodiscard]] NativeFirstFrameArm nativeFirstFrameArm(const Correlation &, const Snapshot &);

inline constexpr char UpstreamCommit[] = "efb50993780079460b0cbed1363e2166a2de1d9f";
inline constexpr char UpstreamVersion[] = "0.56.2";

// Private source integration points. These are compiled into the exact pinned
// compositor, not symbol hooks, a generic eval interface or a plugin ABI.
void initialize(wl_display &, wl_event_loop &);
void shutdown();
[[nodiscard]] bool startupBlocked();
// Private presentation eligibility only, never original restoration authority.
[[nodiscard]] bool startupRecoveryAvailable();
// Atomic compositor-thread admission: a live/failed display reservation cannot
// lose protected lock state or change its security epoch before restoration.
[[nodiscard]] bool lockReleased();
void commitObserved(Monitor::CMonitor *, bool success);
[[nodiscard]] bool ownedCommitAllowed();
[[nodiscard]] bool ordinaryCommitAllowed();
// Comparison with the compositor-thread owned write, never an admission API.
// Protected buffer initialization must not assist an unrelated IPC modeset.
[[nodiscard]] bool ownedModesetInProgress();
[[nodiscard]] bool ownsMonitor(Monitor::CMonitor *);
[[nodiscard]] Config::CMonitorRule overlayRule(Monitor::CMonitor *, Config::CMonitorRule);
// Read-only capture at the actual native selection point, before wlr applies.
// No selected index or source kind is accepted from a client.
void nativeRuleSource(Monitor::CMonitor *, const Config::CMonitorRule &, std::optional<std::size_t>,
                      bool wlr, std::uint32_t committed, std::uint32_t refreshMilliHz);
[[nodiscard]] Backend *nativeBackend();
[[nodiscard]] CompositorDisplayService *nativeTransactions();
[[nodiscard]] std::optional<std::string> nativeOutputName(OutputKey);
[[nodiscard]] Monitor::CMonitor *nativeOutputMonitor(OutputKey);
[[nodiscard]] const std::string &compositorInstance();

} // namespace Linura::HyprlandDisplay
