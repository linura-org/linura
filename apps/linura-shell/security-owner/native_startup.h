#pragma once

#include <QString>
#include <QStringList>
#include <QtGlobal>
#include <chrono>
#include <optional>

namespace Linura::SecurityOwner {

class NativeRuntime;

// Bounded connection candidates ONLY, never session identity/authority. The
// runtime independently attests the actual connected peers through logind.
struct NativeSocketRoutes final
{
    QStringList wayland;
    QStringList compositor;
};
[[nodiscard]] std::optional<NativeSocketRoutes>
discoverNativeSocketRoutes(const QString &runtimeDirectory, quint32 uid);
[[nodiscard]] std::optional<NativeSocketRoutes>
waitForNativeSocketRoutes(const QString &runtimeDirectory, quint32 uid,
                          std::chrono::milliseconds readinessBudget,
                          std::chrono::milliseconds pollInterval);

// A process-local startup result, not an approval or execution permit. Only the
// secure-exec entry point can construct it, before QGuiApplication/plugin load.
// No test/embedding constructor can assert that the native protections hold.
class NativeStartup final
{
  public:
    NativeStartup(const NativeStartup &) = delete;
    NativeStartup &operator=(const NativeStartup &) = delete;
    NativeStartup(NativeStartup &&other) noexcept;
    NativeStartup &operator=(NativeStartup &&) = delete;
    [[nodiscard]] static std::optional<NativeStartup> prepare();

  private:
    friend class NativeRuntime;
    NativeStartup(quint32 owner, NativeSocketRoutes routes);
    quint32 uid_ = 0;
    NativeSocketRoutes routes_;
};

} // namespace Linura::SecurityOwner
