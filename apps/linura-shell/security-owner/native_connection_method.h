#pragma once

#include <QDBusMessage>
#include <QMap>
#include <QString>

#include <optional>

namespace Linura::SecurityOwner {

// S18-7: exactly two native NetworkManager connection-lifecycle methods.
// A fixed call encoder is NOT policy, an approval, a D-Bus sender, or a
// durably spent Control grant. No public endpoint is backed by this type.
enum class NativeConnectionMutation { Activate, Deactivate };
enum class NativeConnectionMedia { Ethernet, Wifi };

// Atomic typed native correlation, NEVER execution permission. A profile,
// kernel device and Wi-Fi AP cannot be chosen through independent methods.
struct NativeConnectionActivationTarget final
{
    QString owner;
    QString profile;
    QString device;
    NativeConnectionMedia media = NativeConnectionMedia::Ethernet;
    QString accessPoint;
};

// The *actual* original-login sender must read these permissions from the
// current, pinned NetworkManager daemon; the map itself is not a permit.
[[nodiscard]] bool nativeConnectionPermissionGranted(const QMap<QString, QString> &permissions);

class NativeConnectionMethod final
{
  public:
    [[nodiscard]] static std::optional<NativeConnectionMethod>
    activate(const NativeConnectionActivationTarget &target);
    [[nodiscard]] static std::optional<NativeConnectionMethod>
    deactivate(const QString &networkManagerUniqueOwner, const QString &activeConnectionPath);

    [[nodiscard]] QDBusMessage message() const;
    [[nodiscard]] NativeConnectionMutation mutation() const noexcept
    {
        return mutation_;
    }
    [[nodiscard]] const QString &targetPath() const noexcept
    {
        return target_;
    }
    [[nodiscard]] const QString &devicePath() const noexcept
    {
        return device_;
    }
    [[nodiscard]] const QString &accessPointPath() const noexcept
    {
        return accessPoint_;
    }

  private:
    NativeConnectionMethod(QString owner, NativeConnectionMutation mutation, QString target,
                           QString device, QString accessPoint);
    QString owner_;
    NativeConnectionMutation mutation_ = NativeConnectionMutation::Activate;
    QString target_;
    QString device_;
    QString accessPoint_;
};

} // namespace Linura::SecurityOwner
