#include "native_startup.h"
#include "native_runtime.h"

#include <QGuiApplication>
#include <utility>
#include <unistd.h>

namespace {
void suppressDiagnostic(QtMsgType, const QMessageLogContext &, const QString &) {}
constexpr int NativeUnavailable = 78;
} // namespace

int main(int argc, char **argv)
{
    if (argc != 1)
        return NativeUnavailable;
    auto startup = Linura::SecurityOwner::NativeStartup::prepare();
    if (!startup)
        return NativeUnavailable;
    // Protection/environment isolation precedes QGuiApplication, native plugins
    // and QML. Never repair ordinary exec by setting dumpability after Qt loads.
    qInstallMessageHandler(suppressDiagnostic);
    QGuiApplication application(argc, argv);
    auto runtime = Linura::SecurityOwner::NativeRuntime::create(std::move(*startup));
    if (!runtime || !runtime->exportNativeEndpoint())
        return NativeUnavailable;
    const int result = application.exec();
    // An event-loop exit cannot unwind an active locker or release Wayland.
    _exit(result == 0 ? NativeUnavailable : result);
}
