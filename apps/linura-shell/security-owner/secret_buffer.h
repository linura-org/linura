#pragma once

#include <QStringView>

#include <cstddef>
#include <functional>
#include <string_view>

namespace Linura::SecurityOwner {

// Native-only storage: deliberately not a QObject, QVariant, QString property,
// copyable value, debug formatter or transport payload. Failure to establish the
// locked/non-dumpable mapping disables input rather than falling back to heap.
class SecretBuffer final
{
  public:
    static constexpr std::size_t MaximumBytes = 1024;
    static constexpr std::size_t MaximumScalars = 256;

    SecretBuffer();
    ~SecretBuffer();
    SecretBuffer(const SecretBuffer &) = delete;
    SecretBuffer &operator=(const SecretBuffer &) = delete;
    SecretBuffer(SecretBuffer &&) = delete;
    SecretBuffer &operator=(SecretBuffer &&) = delete;

    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] std::size_t length() const noexcept;
    [[nodiscard]] bool append(QStringView text) noexcept;
    // Direct bounded native keyboard input; no owning Qt text/event copy.
    [[nodiscard]] bool appendUtf8(std::string_view text) noexcept;
    void eraseLast() noexcept;
    void clear() noexcept;

    // The callback is the native PolkitAgentSession protected-channel response,
    // never a QML callback. Storage is wiped even if that callback throws.
    [[nodiscard]] bool respond(const std::function<void(const char *)> &response);

  private:
    char *mapping_ = nullptr;
    std::size_t mappingBytes_ = 0;
    std::size_t bytes_ = 0;
    std::size_t scalars_ = 0;
};

} // namespace Linura::SecurityOwner
