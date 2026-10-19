#pragma once

#include "native_approval.h"
#include "polkit_conversation.h"
#include "peer_guard.h"

#include <QObject>
#include <QPointer>
#include <QTimer>

#include <memory>
#include <optional>

typedef struct _PolkitAgentListener PolkitAgentListener;
typedef struct _PolkitDetails PolkitDetails;
typedef struct _GTask GTask;
typedef struct _GList GList;

namespace Linura::SecurityOwner {

// Official Polkit injects these identities into BeginAuthentication. It does
// NOT forward caller-authored CheckAuthorization details to the agent.
[[nodiscard]] bool nativeAuthenticationOriginMatches(PolkitDetails *details, quint32 controlPid,
                                                     quint32 compositorPid);

class AuthenticationAgent final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool registered READ registered NOTIFY presentationChanged)
    Q_PROPERTY(bool confirmationPending READ confirmationPending NOTIFY presentationChanged)
    Q_PROPERTY(bool authenticationPending READ authenticationPending NOTIFY presentationChanged)

  public:
    AuthenticationAgent(NativeLockIdentity identity, NativeApproval::MonotonicClock clock,
                        SecretEntry *entry, QObject *parent = nullptr);
    AuthenticationAgent(NativeLockIdentity identity, SecretEntry *entry, QObject *parent = nullptr);
    ~AuthenticationAgent() override;

    [[nodiscard]] bool registered() const noexcept;
    [[nodiscard]] bool confirmationPending() const noexcept;
    [[nodiscard]] bool authenticationPending() const noexcept;

    // Native-only methods. Before register/arm/consume the production transport
    // must freshly attest the native session and the unique Control service
    // owner. These are never public SDK/client methods or writable QML state.
    [[nodiscard]] bool registerNativeSession(quint32 attestedCompositorPid);
    [[nodiscard]] bool arm(const NativeApprovalScope &scope, bool compositorSecure,
                           const NativePeerIdentity &controlPeer);
    [[nodiscard]] bool consume(const NativeApprovalScope &scope);
    [[nodiscard]] bool advanceIdentity(const NativeLockIdentity &identity);
    // Same-UID native subject query, with NO interaction or custom details.
    // Availability is not human approval or executor authority.
    [[nodiscard]] std::optional<QString>
    observePowerPermission(const NativeTransitionIdentity &identity);
    void ownerLost();

    // Only presentation interaction; cannot assert PAM success or unlock.
    Q_INVOKABLE void confirmLock();
    Q_INVOKABLE void cancelInteraction();

    // Official listener adapter entry, C++ only. The callback/cookie/identity
    // originate in native Polkit, never an ordinary shell's supplied boolean.
    void initiateNative(PolkitAgentListener *listener, const char *action, PolkitDetails *details,
                        const char *cookie, GList *identities, GCancellable *cancellable,
                        GTask *task);

  Q_SIGNALS:
    void presentationChanged();
    void confirmationAvailable();
    void denied();

  private:
    struct Registration;
    void finishNative(bool success);

    NativeLockIdentity identity_;
    NativeApproval approval_;
    QPointer<SecretEntry> entry_;
    PolkitConversation conversation_;
    std::unique_ptr<Registration> registration_;
    std::optional<PeerGuard> peerGuard_;
    std::optional<NativePeerIdentity> polkitPeer_;
    std::optional<NativePeerIdentity> controlPeer_;
    quint32 compositorPid_ = 0;
    quint64 compositorStartTicks_ = 0;
    std::optional<NativeApprovalScope> scope_;
    GTask *task_ = nullptr;
    QTimer eventTimer_;
};

} // namespace Linura::SecurityOwner
