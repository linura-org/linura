#pragma once

#include "native_display_connection.h"
#include "native_display_prompt.h"
#include "native_display_watchdog.h"
#include "peer_guard.h"
#include <QObject>
#include <QTimer>
#include <functional>

namespace Linura::SecurityOwner {
class NativeWaylandLock;
class NativePresentation;
class AuthenticationAgent;

// Trusted native presentation/PAM composition only. It owns no planner, policy,
// durable signer, executor or public client API. Runtime supplies fresh transport
// principal/session revalidation; root dispatch remains a separate boundary.
class NativeDisplayFlow final : public QObject
{
    Q_OBJECT
  public:
    using Revalidate = std::function<bool()>;
    using Presented = std::function<void(bool)>;
    [[nodiscard]] static std::unique_ptr<NativeDisplayFlow>
    create(NativeApprovalScope, NativeWaylandLock &, NativePresentation &, AuthenticationAgent &,
           NativePeerIdentity control, Revalidate);
    ~NativeDisplayFlow() override;
    [[nodiscard]] bool matches(const NativeApprovalScope &) const;
    [[nodiscard]] bool fenced() const noexcept;
    [[nodiscard]] bool readyForPolkit(const NativeApprovalScope &);
    [[nodiscard]] bool consume(const NativeApprovalScope &);
    // The trusted runtime calls only after independently admitting the prepared
    // root executor. This reserves the exact live human receipt before effect.
    [[nodiscard]] bool redeem(const NativeDisplayIntent &, const NativeDisplayCorrelation &);
    void presentPrompt(const NativeApprovalScope &, quint64 token, Presented);
    void cancel();
    void revalidateOrigin();

  Q_SIGNALS:
    void closed();

  private:
    NativeDisplayFlow(NativeApprovalScope, NativeDisplayIntent, NativeDisplaySnapshot,
                      NativeWaylandLock &, NativePresentation &, AuthenticationAgent &,
                      NativePeerIdentity, Revalidate);
    [[nodiscard]] bool window();
    [[nodiscard]] bool refreshPresentation();
    void pulse();
    void reviewed(std::size_t page, quint64 epoch, bool accepted);
    NativeApprovalScope scope_;
    NativeDisplayIntent intent_;
    NativeDisplaySnapshot snapshot_;
    NativeDisplayPromptScope prompt_;
    NativeWaylandLock &backend_;
    NativePresentation &presentation_;
    AuthenticationAgent &authentication_;
    Revalidate revalidate_;
    NativePeerIdentity control_;
    QTimer timer_;
    NativeDisplayClock last_{};
    quint64 deadlineBoot_ = 0, epoch_ = 0, proofGeneration_ = 0, inputGeneration_ = 0;
    std::size_t page_ = 0, pageCount_ = 0;
    bool failed_ = false, reviewArmed_ = false, authenticateSelected_ = false;
    bool authenticationArmed_ = false, consumed_ = false, spent_ = false;
    bool ownsPresentation_ = false;
    bool awaitingRevision_ = true;
    struct Pending final
    {
        quint64 token;
        Presented completed;
    };
    std::optional<Pending> pending_;
};
} // namespace Linura::SecurityOwner
