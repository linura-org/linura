#pragma once

#include "native_display_layout.h"

namespace Linura::SecurityOwner {

// Private native mechanism state, never policy, durable authority or a client
// credential. Runtime admission must independently attest the prepared executor
// and correlate its strictly parsed metadata with a fresh native sample.
class NativeDisplayAttempt final
{
  public:
    NativeDisplayAttempt(const NativeDisplayAttempt &) = delete;
    NativeDisplayAttempt &operator=(const NativeDisplayAttempt &) = delete;
    NativeDisplayAttempt(NativeDisplayAttempt &&) = default;
    NativeDisplayAttempt &operator=(NativeDisplayAttempt &&) = delete;
    enum class State { Armed, Pending, Restoring, Confirmed, Restored, RecoveryFailed };
    static constexpr quint64 ConfirmationWindowMs = 15'000;

    [[nodiscard]] static std::optional<NativeDisplayAttempt>
    arm(const NativeDisplayIntent &intent, const QString &transaction, const QString &effectDigest,
        const QString &dispatchDigest, quint64 deadlineUnixMs, quint64 nowUnixMs, quint64 nowBootMs,
        const NativeDisplaySnapshot &baseline, const QString &topology,
        const NativeLockIdentity &lock, bool secure);

    // These reserve the corresponding potentially effectful call BEFORE it is
    // constructed. A lost response cannot make either reservation reusable.
    [[nodiscard]] bool beginApply(quint64 nowUnixMs, quint64 nowBootMs,
                                  const NativeDisplaySnapshot &current, const QString &topology,
                                  const NativeLockIdentity &lock, bool secure);
    [[nodiscard]] bool beginRestore(const NativeDisplaySnapshot &current, const QString &topology,
                                    const NativeLockIdentity &lock, bool secure);
    [[nodiscard]] bool recoveryDue(quint64 nowUnixMs, quint64 nowBootMs) const;
    // Full metadata (including mirror/DPMS) must have been independently decoded
    // and correlated to this same fresh native snapshot before these calls.
    [[nodiscard]] bool confirm(const QString &transaction, const QString &dispatchDigest,
                               quint64 nowUnixMs, quint64 nowBootMs,
                               const NativeDisplayLayout &observed,
                               const NativeDisplaySnapshot &snapshot, const QString &topology,
                               const NativeLockIdentity &lock, bool secure);
    [[nodiscard]] bool verifyRestored(const NativeDisplayLayout &observed,
                                      const NativeDisplaySnapshot &snapshot,
                                      const QString &topology, const NativeLockIdentity &lock,
                                      bool secure);
    void recoveryFailed();
    [[nodiscard]] State state() const noexcept
    {
        return state_;
    }
    [[nodiscard]] bool fenced() const noexcept;
    [[nodiscard]] const NativeDisplayIntent &intent() const noexcept
    {
        return intent_;
    }
    [[nodiscard]] const QString &transaction() const noexcept
    {
        return transaction_;
    }
    [[nodiscard]] const QString &effectDigest() const noexcept
    {
        return effectDigest_;
    }
    [[nodiscard]] const QString &dispatchDigest() const noexcept
    {
        return dispatchDigest_;
    }
    [[nodiscard]] quint64 deadlineUnixMs() const noexcept
    {
        return deadlineUnixMs_;
    }

  private:
    NativeDisplayIntent intent_;
    QString transaction_, effectDigest_, dispatchDigest_;
    quint64 armedUnixMs_ = 0, armedBootMs_ = 0;
    quint64 deadlineUnixMs_ = 0, deadlineBootMs_ = 0;
    bool initiallySecure_ = false;
    State state_ = State::Armed;
    NativeDisplayAttempt() = default;
    [[nodiscard]] bool currentScope(const NativeDisplaySnapshot &snapshot, const QString &topology,
                                    const NativeLockIdentity &lock, bool secure) const;
};

} // namespace Linura::SecurityOwner
