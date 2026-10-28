#pragma once

#include "compositor_display_service.h"

#include <string>

struct wl_display;
namespace Monitor {
class CMonitor;
}
namespace Config {
class CMonitorRule;
}

namespace Linura::HyprlandDisplay {

inline constexpr char UpstreamCommit[] = "efb50993780079460b0cbed1363e2166a2de1d9f";
inline constexpr char UpstreamVersion[] = "0.56.2";

// Private source integration points. These are compiled into the exact pinned
// compositor, not symbol hooks, a generic eval interface or a plugin ABI.
void initialize(wl_display &, wl_event_loop &);
void shutdown();
// Atomic compositor-thread admission: a live/failed display reservation cannot
// lose protected lock state or change its security epoch before restoration.
[[nodiscard]] bool lockReleased();
void commitObserved(Monitor::CMonitor *, bool success);
[[nodiscard]] bool ownedCommitAllowed();
[[nodiscard]] bool ownsMonitor(Monitor::CMonitor *);
[[nodiscard]] Config::CMonitorRule overlayRule(Monitor::CMonitor *, Config::CMonitorRule);
[[nodiscard]] Backend *nativeBackend();
[[nodiscard]] CompositorDisplayService *nativeTransactions();
[[nodiscard]] std::optional<std::string> nativeOutputName(OutputKey);
[[nodiscard]] const std::string &compositorInstance();

} // namespace Linura::HyprlandDisplay
