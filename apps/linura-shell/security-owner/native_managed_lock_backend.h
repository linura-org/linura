#pragma once

#include <QObject>
#include <functional>

namespace Linura::SecurityOwner {

// Private typed native mechanism. No writable QML effect properties, slots,
// invokables, transport DTOs or policy ownership. The immutable runtime factory
// owns provenance; this type itself is not caller/executor authorization.
class NativeManagedLockBackend : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool locked READ requestedSecure NOTIFY nativeStateChanged)
    Q_PROPERTY(bool secure READ secureCoverage NOTIFY nativeStateChanged)
  public:
    using EffectGate = std::function<bool(bool secure)>;
    explicit NativeManagedLockBackend(QObject *parent = nullptr);
    ~NativeManagedLockBackend() override = default;
    [[nodiscard]] bool requestedSecure() const noexcept;
    [[nodiscard]] bool secureCoverage() const noexcept;
    [[nodiscard]] bool installManagedEffectGate(EffectGate gate);
    [[nodiscard]] bool dispatchNative(bool secure);

  Q_SIGNALS:
    void nativeStateChanged();

  protected:
    // Check immediately BEFORE each wire effect. Cleanup/rendering/hotplug
    // failure and object destruction must never release the native lock.
    void consumeNativeEffectGate(bool secure);
    void publishNativeState(bool requested, bool coverage);
    [[nodiscard]] virtual bool applyNative(bool secure) = 0;

  private:
    EffectGate gate_;
    bool requested_ = false;
    bool coverage_ = false;
};

} // namespace Linura::SecurityOwner
