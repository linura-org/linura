#pragma once

#include "native_approval.h"
#include "secret_entry.h"

#include <QObject>
#include <QPointer>
#include <QTimer>

#include <memory>
#include <optional>

// Official opaque types, implemented using the distribution's actual headers.
// No copied ABI, dynamically guessed symbols or hand-invoked privileged helper.
typedef struct _PolkitIdentity PolkitIdentity;
typedef struct _GCancellable GCancellable;

namespace Linura::SecurityOwner {

class PolkitConversation final : public QObject
{
    Q_OBJECT

  public:
    explicit PolkitConversation(NativeApproval &approval, QObject *parent = nullptr);
    ~PolkitConversation() override;

    // Called only by the native attested authentication-agent listener. It must
    // supply the currently armed Control challenge and native Polkit cookie.
    [[nodiscard]] bool begin(const NativeApprovalScope &scope, PolkitIdentity *identity,
                             const char *cookie, GCancellable *cancellable, SecretEntry *entry);
    void cancel();
    void ownerLost();
    [[nodiscard]] bool active() const noexcept;

  Q_SIGNALS:
    // No secret/prompt/cookie payload. Success records native conversation proof
    // only; neither this class nor this signal can release the compositor lock.
    void finished(bool nativeAuthenticationSucceeded);
    void inputRequested();

  private:
    struct Native;
    void submit();
    void completed(bool success);
    void requested(NativePromptKind kind);
    void releaseNative();

    NativeApproval &approval_;
    std::unique_ptr<Native> native_;
    std::optional<NativeApprovalScope> scope_;
    QPointer<SecretEntry> entry_;
    QTimer deadlineTimer_;
    QTimer eventTimer_;
    bool waiting_ = false;
    bool cancelling_ = false;
    bool responding_ = false;
    bool deferredRequest_ = false;
    bool submitted_ = false;
    NativePromptKind deferredPromptKind_ = NativePromptKind::Response;
    quint32 promptStep_ = 0;
    quint32 authenticatedUid_ = 0;
    std::optional<bool> deferredCompletion_;
};

} // namespace Linura::SecurityOwner
