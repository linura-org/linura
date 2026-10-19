#include "polkit_conversation.h"

#include <QThread>

#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <gio/gio.h>

#include <cstring>

namespace Linura::SecurityOwner {
namespace {

class ThreadContext final
{
  public:
    explicit ThreadContext(GMainContext *context) : context_(context)
    {
        g_main_context_push_thread_default(context_);
    }
    ~ThreadContext()
    {
        g_main_context_pop_thread_default(context_);
    }

  private:
    GMainContext *context_;
};

} // namespace

struct PolkitConversation::Native final
{
    GMainContext *context = g_main_context_new();
    PolkitAgentSession *session = nullptr;
    GCancellable *cancellable = nullptr;
    gulong cancellationHandler = 0;
    gulong requestHandler = 0;
    gulong completionHandler = 0;

    ~Native()
    {
        if (session) {
            if (requestHandler)
                g_signal_handler_disconnect(session, requestHandler);
            if (completionHandler)
                g_signal_handler_disconnect(session, completionHandler);
            polkit_agent_session_cancel(session);
            g_object_unref(session);
        }
        if (cancellable) {
            if (cancellationHandler)
                g_cancellable_disconnect(cancellable, cancellationHandler);
            g_object_unref(cancellable);
        }
        g_main_context_unref(context);
    }
};

PolkitConversation::PolkitConversation(NativeApproval &approval, QObject *parent)
    : QObject(parent), approval_(approval)
{
    deadlineTimer_.setSingleShot(true);
    deadlineTimer_.setInterval(int(NativeApproval::ConversationMs));
    connect(&deadlineTimer_, &QTimer::timeout, this, &PolkitConversation::cancel);
    eventTimer_.setInterval(10);
    connect(&eventTimer_, &QTimer::timeout, this, [this] {
        if (!native_)
            return;
        // Hold the context independently: a completion callback can destroy the
        // session/container while one bounded iteration is dispatching it.
        GMainContext *context = g_main_context_ref(native_->context);
        {
            ThreadContext scopeContext(context);
            for (int budget = 0; budget < 8 && native_ && g_main_context_pending(context); ++budget)
                g_main_context_iteration(context, FALSE);
        }
        g_main_context_unref(context);
        if (native_ && approval_.state() != NativeApproval::State::Authenticating)
            cancel();
    });
}

PolkitConversation::~PolkitConversation()
{
    // Do not emit success/cancellation into partially destroyed object graphs.
    if (scope_)
        approval_.cancel();
    releaseNative();
}

bool PolkitConversation::active() const noexcept
{
    return native_ != nullptr;
}

bool PolkitConversation::begin(const NativeApprovalScope &scope, PolkitIdentity *identity,
                               const char *cookie, GCancellable *cancellable, SecretEntry *entry)
{
    if (QThread::currentThread() != thread() || native_ || !entry || !identity || !cookie ||
        entry->thread() != thread() || !entry->storageAvailable() ||
        scope.purpose == ApprovalPurpose::ConfirmLock || !scope.valid() ||
        approval_.state() != NativeApproval::State::Authenticating ||
        !POLKIT_IS_UNIX_USER(identity) || scope.lock.uid > quint32(G_MAXINT) ||
        polkit_unix_user_get_uid(POLKIT_UNIX_USER(identity)) < 0 ||
        (scope.requiresSessionOwnerAuthentication() &&
         polkit_unix_user_get_uid(POLKIT_UNIX_USER(identity)) != int(scope.lock.uid)) ||
        strnlen(cookie, 1025) == 0 || strnlen(cookie, 1025) > 1024 || !cancellable ||
        g_cancellable_is_cancelled(cancellable))
        return false;

    scope_ = scope;
    authenticatedUid_ = quint32(polkit_unix_user_get_uid(POLKIT_UNIX_USER(identity)));
    entry_ = entry;
    native_ = std::make_unique<Native>();
    native_->cancellable = G_CANCELLABLE(g_object_ref(cancellable));
    native_->session = polkit_agent_session_new(identity, cookie);
    if (!native_->session) {
        approval_.cancel();
        releaseNative();
        return false;
    }
    native_->requestHandler = g_signal_connect(
        native_->session, "request",
        G_CALLBACK(+[](PolkitAgentSession *, const gchar *question, gboolean, gpointer data) {
            // The native PAM question/echo flag never puts secret material in
            // QML. For the qualified owner conversation all input stays masked.
            auto *conversation = static_cast<PolkitConversation *>(data);
            const auto kind = classifyNativePrompt(question);
            if (kind)
                conversation->requested(*kind);
            else
                conversation->cancel();
        }),
        this);
    native_->completionHandler =
        g_signal_connect(native_->session, "completed",
                         G_CALLBACK(+[](PolkitAgentSession *, gboolean success, gpointer data) {
                             static_cast<PolkitConversation *>(data)->completed(success != FALSE);
                         }),
                         this);
    native_->cancellationHandler = g_cancellable_connect(
        cancellable, G_CALLBACK(+[](GCancellable *, gpointer data) {
            // GCancellable may be cancelled from another thread. Always perform
            // response wiping/session cancellation in the native Qt owner thread.
            auto *owner = static_cast<PolkitConversation *>(data);
            QMetaObject::invokeMethod(owner, &PolkitConversation::cancel, Qt::QueuedConnection);
        }),
        this, nullptr);
    connect(entry, &SecretEntry::submissionRequested, this, &PolkitConversation::submit);
    connect(entry, &SecretEntry::cancellationRequested, this, &PolkitConversation::cancel);
    connect(entry, &QObject::destroyed, this, &PolkitConversation::cancel);
    deadlineTimer_.start();
    eventTimer_.start();
    GMainContext *context = g_main_context_ref(native_->context);
    PolkitAgentSession *session = POLKIT_AGENT_SESSION(g_object_ref(native_->session));
    {
        ThreadContext scopeContext(context);
        polkit_agent_session_initiate(session);
    }
    g_object_unref(session);
    g_main_context_unref(context);
    return true;
}

void PolkitConversation::requested(NativePromptKind kind)
{
    if (responding_) {
        // An official helper may synchronously request its next response. Do
        // not clear/reuse the protected mapping while the previous callback
        // still owns its const-char pointer. Open the next prompt after wiping.
        if (deferredRequest_)
            deferredCompletion_ = false;
        else {
            deferredRequest_ = true;
            deferredPromptKind_ = kind;
        }
        return;
    }
    if (!native_ || !scope_ || !entry_ || waiting_ || !approval_.nativePrompt(*scope_) ||
        promptStep_ >= NativeApproval::MaximumConversationPrompts ||
        !entry_->beginNativePrompt(kind, promptStep_ + 1, authenticatedUid_)) {
        cancel();
        return;
    }
    waiting_ = true;
    ++promptStep_;
    Q_EMIT inputRequested();
}

void PolkitConversation::submit()
{
    if (!native_ || !waiting_ || !scope_ || !entry_ ||
        approval_.state() != NativeApproval::State::Authenticating) {
        cancel();
        return;
    }
    waiting_ = false;
    // Hold a reference through response reentrancy: PAM completion may release
    // native_ synchronously. The protected response buffer is always wiped.
    PolkitAgentSession *session = POLKIT_AGENT_SESSION(g_object_ref(native_->session));
    GMainContext *context = g_main_context_ref(native_->context);
    bool sent = false;
    responding_ = true;
    {
        ThreadContext scopeContext(context);
        sent = entry_->respondToNativePrompt([this, session](const char *response) {
            submitted_ = true;
            polkit_agent_session_response(session, response);
        });
    }
    responding_ = false;
    g_object_unref(session);
    g_main_context_unref(context);
    if (!sent)
        cancel();
    else if (native_ && deferredCompletion_) {
        const bool success = *deferredCompletion_;
        deferredCompletion_.reset();
        completed(success);
    } else if (native_ && deferredRequest_) {
        deferredRequest_ = false;
        requested(deferredPromptKind_);
    }
}

void PolkitConversation::completed(bool success)
{
    if (!native_ || !scope_)
        return;
    if (responding_) {
        // No confirmation or presentation/teardown callback may escape while
        // SecretBuffer::respond still holds the response. A duplicate native
        // completion is a denial, never a second confirmation.
        deferredCompletion_ = deferredCompletion_.has_value() ? false : success;
        return;
    }
    const bool confirmed = !cancelling_ && !waiting_ && !deferredRequest_ && submitted_ &&
                           success && !g_cancellable_is_cancelled(native_->cancellable) &&
                           approval_.nativeCompleted(*scope_, true);
    if (!confirmed)
        approval_.cancel();
    releaseNative();
    Q_EMIT finished(confirmed);
}

void PolkitConversation::cancel()
{
    if (!native_)
        return;
    cancelling_ = true;
    approval_.cancel();
    if (responding_) {
        // A synchronous native request/error may cancel during response delivery.
        // Keep its protected pointer alive until respondToNativePrompt wipes it.
        deferredCompletion_ = false;
        return;
    }
    // Disconnect before cancellation: its official completion callback is a
    // denial, not a possible reentrant success. Emit exactly one fixed result.
    releaseNative();
    Q_EMIT finished(false);
}

void PolkitConversation::ownerLost()
{
    approval_.ownerLost();
    cancel();
}

void PolkitConversation::releaseNative()
{
    deadlineTimer_.stop();
    eventTimer_.stop();
    if (entry_) {
        disconnect(entry_, nullptr, this, nullptr);
        entry_->cancelNativePrompt();
    }
    entry_.clear();
    scope_.reset();
    waiting_ = false;
    responding_ = false;
    deferredRequest_ = false;
    submitted_ = false;
    promptStep_ = 0;
    authenticatedUid_ = 0;
    deferredPromptKind_ = NativePromptKind::Response;
    deferredCompletion_.reset();
    // Destruction cancels the official session only after signal disconnection.
    native_.reset();
    cancelling_ = false;
}

} // namespace Linura::SecurityOwner
