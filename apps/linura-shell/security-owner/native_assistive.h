#pragma once

#include <QString>
#include <memory>
#include <optional>

namespace Linura::SecurityOwner {

// Presentation metadata only. There is intentionally no response, length,
// cursor, selection, executable action, approval or current-security fact.
struct NativeAssistiveProjection final
{
    QString heading, description, prompt;
    bool visible = false;
    bool accepting = false;
    bool focused = false;
    [[nodiscard]] bool valid() const;
    bool operator==(const NativeAssistiveProjection &) const = default;
};

// Narrow local AT-SPI address parser. No ambient bus, abstract/TCP transport,
// escaped address, caller-selected UID or alternate filesystem routing.
[[nodiscard]] std::optional<QString> nativeAssistiveSocket(const QString &address, quint32 uid);

// Untrusted assistive readers get bounded, non-secret presentation metadata.
// No pointer to the entry, native lock, PAM conversation or Control is retained.
// All D-Bus work runs away from native keyboard/rendering dispatch.
class NativeAssistiveBridge final
{
  public:
    explicit NativeAssistiveBridge(quint32 ownerUid);
    ~NativeAssistiveBridge();
    NativeAssistiveBridge(const NativeAssistiveBridge &) = delete;
    NativeAssistiveBridge &operator=(const NativeAssistiveBridge &) = delete;
    void publish(const NativeAssistiveProjection &projection);
    [[nodiscard]] bool registered() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace Linura::SecurityOwner
