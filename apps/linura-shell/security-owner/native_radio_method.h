#pragma once

#include <QDBusMessage>
#include <QString>

#include <optional>

namespace Linura::SecurityOwner {

// Exactly two NetworkManager manager mutations. No arbitrary destination,
// object path, interface, method, or properties map can be selected here.
// Encoding a call is NOT authorization or a dispatch grant.
enum class NativeRadioMutation { NetworkingEnabled, WirelessEnabled };

class NativeRadioMethod final
{
  public:
    // 'owner' MUST be independently pinned to the exact supervised NM daemon
    // by a caller. Parsing it here cannot attest that identity.
    [[nodiscard]] static std::optional<NativeRadioMethod>
    encode(const QString &pinnedUniqueOwner, NativeRadioMutation mutation, bool enabled);

    // A future user-owned native sender may transmit this only after Control
    // durably spends its sealed one-use attempt. This module never sends.
    [[nodiscard]] QDBusMessage message() const;
    [[nodiscard]] NativeRadioMutation mutation() const noexcept
    {
        return mutation_;
    }
    [[nodiscard]] bool enabled() const noexcept
    {
        return enabled_;
    }

  private:
    NativeRadioMethod(QString owner, NativeRadioMutation mutation, bool enabled);
    QString owner_;
    NativeRadioMutation mutation_;
    bool enabled_ = false;
};

} // namespace Linura::SecurityOwner
