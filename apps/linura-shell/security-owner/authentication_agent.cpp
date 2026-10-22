#include "authentication_agent.h"

#include <QByteArray>
#include <QPair>
#include <QThread>

#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <gio/gio.h>

#include <unistd.h>

#include <cstring>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <limits>
#include <strings.h>
#include <thread>
#include <utility>

namespace {

template <std::size_t N> bool registrationUnavailable(const char (&reason)[N]) noexcept
{
    const ssize_t written = ::write(STDERR_FILENO, reason, N - 1);
    (void)written;
    return false;
}

// The official registration API is synchronous. Bound it with its supported
// cancellable rather than letting native service loss indefinitely freeze the
// security owner. Cancellation has no authentication-success interpretation.
class RegistrationDeadline final
{
  public:
    explicit RegistrationDeadline(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(2'000))
        : cancellable_(g_cancellable_new()), worker_([this, timeout] {
              std::unique_lock lock(mutex_);
              if (!condition_.wait_for(lock, timeout, [this] { return done_; }))
                  g_cancellable_cancel(cancellable_);
          })
    {}

    ~RegistrationDeadline()
    {
        {
            std::lock_guard lock(mutex_);
            done_ = true;
        }
        condition_.notify_one();
        worker_.join();
        g_object_unref(cancellable_);
    }

    [[nodiscard]] GCancellable *cancellable() const noexcept
    {
        return cancellable_;
    }

  private:
    GCancellable *cancellable_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread worker_;
};

typedef struct _LinuraPolkitListener
{
    PolkitAgentListener parent;
    Linura::SecurityOwner::AuthenticationAgent *owner;
} LinuraPolkitListener;

typedef struct _LinuraPolkitListenerClass
{
    PolkitAgentListenerClass parent;
} LinuraPolkitListenerClass;

G_DEFINE_TYPE(LinuraPolkitListener, linura_polkit_listener, POLKIT_AGENT_TYPE_LISTENER)

void linura_polkit_listener_init(LinuraPolkitListener *listener)
{
    listener->owner = nullptr;
}

void linura_polkit_listener_class_init(LinuraPolkitListenerClass *klass)
{
    auto *listenerClass = POLKIT_AGENT_LISTENER_CLASS(klass);
    listenerClass->initiate_authentication =
        +[](PolkitAgentListener *listener, const gchar *action, const gchar *, const gchar *,
            PolkitDetails *details, const gchar *cookie, GList *identities,
            GCancellable *cancellable, GAsyncReadyCallback callback, gpointer data) {
            GTask *task = g_task_new(listener, cancellable, callback, data);
            auto *native = reinterpret_cast<LinuraPolkitListener *>(listener);
            if (!native->owner) {
                g_task_return_new_error(task, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                                        "Native authentication owner unavailable");
            } else {
                native->owner->initiateNative(listener, action, details, cookie, identities,
                                              cancellable, task);
            }
            g_object_unref(task);
        };
    listenerClass->initiate_authentication_finish =
        +[](PolkitAgentListener *listener, GAsyncResult *result, GError **error) -> gboolean {
        if (!g_task_is_valid(result, listener)) {
            g_set_error_literal(error, POLKIT_ERROR, POLKIT_ERROR_FAILED,
                                "Invalid native authentication result");
            return FALSE;
        }
        return g_task_propagate_boolean(G_TASK(result), error);
    };
}

bool detailMatches(PolkitDetails *details, const char *key, const QString &expected)
{
    const char *value = polkit_details_lookup(details, key);
    if (!value || strnlen(value, 513) > 512)
        return false;
    return QByteArray(value) == expected.toUtf8();
}

} // namespace

namespace Linura::SecurityOwner {

bool nativeAuthenticationOriginMatches(PolkitDetails *details, quint32 controlPid,
                                       quint32 compositorPid)
{
    return details && controlPid != 0 && compositorPid != 0 &&
           detailMatches(details, "polkit.caller-pid", QString::number(controlPid)) &&
           detailMatches(details, "polkit.subject-pid", QString::number(compositorPid));
}

std::optional<QVector<quint32>> nativeAuthenticationChoices(const NativeApprovalScope &scope,
                                                            GList *identities)
{
    QVector<quint32> choices;
    for (auto *item = identities; item; item = item->next) {
        if (choices.size() == 8 || !item->data || !POLKIT_IS_UNIX_USER(item->data))
            return std::nullopt;
        const auto uid = polkit_unix_user_get_uid(POLKIT_UNIX_USER(item->data));
        if (uid < 0 || choices.contains(static_cast<quint32>(uid)))
            return std::nullopt;
        choices.append(static_cast<quint32>(uid));
    }
    if (choices.isEmpty())
        return std::nullopt;
    if (scope.requiresSessionOwnerAuthentication()) {
        if (!choices.contains(scope.lock.uid))
            return std::nullopt;
        return QVector<quint32>{scope.lock.uid};
    }
    return choices;
}

struct AuthenticationAgent::IdentitySelection final
{
    QVector<QPair<quint32, PolkitIdentity *>> identities;
    QByteArray cookie;

    ~IdentitySelection()
    {
        for (const auto &option : identities)
            g_object_unref(option.second);
        if (!cookie.isEmpty())
            explicit_bzero(cookie.data(), static_cast<std::size_t>(cookie.size()));
    }
};

struct AuthenticationAgent::Registration final
{
    GMainContext *context = g_main_context_new();
    LinuraPolkitListener *listener = nullptr;
    gpointer handle = nullptr;

    ~Registration()
    {
        if (listener)
            listener->owner = nullptr;
        if (handle)
            polkit_agent_listener_unregister(handle);
        if (listener)
            g_object_unref(listener);
        g_main_context_unref(context);
    }
};

AuthenticationAgent::AuthenticationAgent(NativeLockIdentity identity,
                                         NativeApproval::MonotonicClock clock, SecretEntry *entry,
                                         QObject *parent)
    : QObject(parent), identity_(std::move(identity)), approval_(identity_, std::move(clock)),
      entry_(entry), conversation_(approval_, this)
{
    connect(&conversation_, &PolkitConversation::finished, this,
            &AuthenticationAgent::finishNative);
    if (entry_) {
        connect(entry_, &SecretEntry::identitySelected, this, &AuthenticationAgent::selectIdentity);
        connect(entry_, &SecretEntry::cancellationRequested, this, [this] {
            if (identitySelection_)
                cancelInteraction();
        });
    }
    eventTimer_.setInterval(10);
    connect(&eventTimer_, &QTimer::timeout, this, [this] {
        if (registration_) {
            GMainContext *context = g_main_context_ref(registration_->context);
            g_main_context_push_thread_default(context);
            for (int budget = 0; budget < 8 && registration_ && g_main_context_pending(context);
                 ++budget)
                g_main_context_iteration(context, FALSE);
            g_main_context_pop_thread_default(context);
            g_main_context_unref(context);
        }
        const auto state = approval_.state();
        if (identitySelection_ && (!task_ || !entry_ || !entry_->acceptsInput() ||
                                   g_cancellable_is_cancelled(g_task_get_cancellable(task_)))) {
            finishNative(false);
            return;
        }
        if (scope_ && state != NativeApproval::State::Confirming &&
            state != NativeApproval::State::Authenticating &&
            state != NativeApproval::State::Confirmed) {
            if (conversation_.active())
                conversation_.cancel();
            else if (identitySelection_ || task_)
                finishNative(false);
            else {
                scope_.reset();
                controlPeer_.reset();
                Q_EMIT presentationChanged();
            }
        }
    });
}

AuthenticationAgent::AuthenticationAgent(NativeLockIdentity identity, SecretEntry *entry,
                                         QObject *parent)
    : AuthenticationAgent(std::move(identity), NativeApproval::nativeBootTimeClock(), entry, parent)
{}

AuthenticationAgent::~AuthenticationAgent()
{
    disconnect(&conversation_, nullptr, this, nullptr);
    conversation_.cancel();
    if (identitySelection_ && entry_)
        entry_->cancelNativePrompt();
    identitySelection_.reset();
    if (task_) {
        g_task_return_new_error(task_, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                                "Native authentication owner lost");
        g_object_unref(task_);
        task_ = nullptr;
    }
    registration_.reset();
}

bool AuthenticationAgent::registered() const noexcept
{
    return registration_ && registration_->handle;
}

bool AuthenticationAgent::confirmationPending() const noexcept
{
    return scope_ && scope_->purpose == ApprovalPurpose::ConfirmLock;
}

bool AuthenticationAgent::authenticationPending() const noexcept
{
    return scope_ && scope_->purpose != ApprovalPurpose::ConfirmLock &&
           (identitySelection_ || conversation_.active());
}

bool AuthenticationAgent::registerNativeSession(quint32 attestedCompositorPid)
{
    if (QThread::currentThread() != thread() || registration_ || !entry_ ||
        !entry_->storageAvailable() || getuid() != identity_.uid || geteuid() != identity_.uid ||
        approval_.state() == NativeApproval::State::Faulted)
        return registrationUnavailable("linura-security-owner: authentication/preconditions\n");
    // The root-controlled launcher fixes this address. Refuse ambient transport
    // overrides rather than silently authorizing through another Polkit daemon.
    const QByteArray address = qgetenv("DBUS_SYSTEM_BUS_ADDRESS");
    if (!address.isEmpty() && address != QByteArrayLiteral("unix:path=/run/dbus/system_bus_socket"))
        return registrationUnavailable("linura-security-owner: authentication/bus-route\n");
    peerGuard_ = PeerGuard::connect();
    if (!peerGuard_)
        return registrationUnavailable("linura-security-owner: authentication/system-bus\n");
    polkitPeer_ = peerGuard_->namedPeer(NativePeerPurpose::NativeAuthenticationDaemon);
    if (!polkitPeer_)
        return registrationUnavailable(
            "linura-security-owner: authentication/daemon-attestation\n");

    auto registration = std::make_unique<Registration>();
    registration->listener = static_cast<LinuraPolkitListener *>(
        g_object_new(linura_polkit_listener_get_type(), nullptr));
    registration->listener->owner = this;
    // Register only the actual Wayland peer / native session leader's process,
    // never take over the general desktop agent. This supervised security owner
    // is a separate service; it must not mislabel its own service cgroup as the
    // user's active graphical login. Runtime freshly attests this peer before
    // registration and before each approval. Polkit also pins process start time.
    if (getuid() > static_cast<uid_t>(std::numeric_limits<gint>::max()) ||
        attestedCompositorPid == 0 ||
        attestedCompositorPid > quint32(std::numeric_limits<gint>::max()))
        return registrationUnavailable("linura-security-owner: authentication/subject-identity\n");
    PolkitSubject *subject = polkit_unix_process_new_for_owner(
        static_cast<gint>(attestedCompositorPid), 0, static_cast<gint>(getuid()));
    if (!subject || polkit_unix_process_get_start_time(POLKIT_UNIX_PROCESS(subject)) == 0) {
        if (subject)
            g_object_unref(subject);
        return registrationUnavailable("linura-security-owner: authentication/subject-start\n");
    }
    const auto compositorStart = polkit_unix_process_get_start_time(POLKIT_UNIX_PROCESS(subject));
    GError *error = nullptr;
    {
        // The cancellable bounds only the synchronous registration operation.
        // Destroy it before independent peer revalidation so a completed,
        // successful registration cannot be cancelled by later checks.
        RegistrationDeadline deadline;
        g_main_context_push_thread_default(registration->context);
        registration->handle = polkit_agent_listener_register(
            POLKIT_AGENT_LISTENER(registration->listener), POLKIT_AGENT_REGISTER_FLAGS_NONE,
            subject, "/org/linura/SecurityOwner/AuthenticationAgent", deadline.cancellable(),
            &error);
        g_main_context_pop_thread_default(registration->context);
    }
    g_object_unref(subject);
    if (error)
        g_error_free(error); // Native daemon messages are never logged or surfaced.
    if (!registration->handle)
        return registrationUnavailable("linura-security-owner: authentication/register\n");
    if (!peerGuard_->stillCurrent(NativePeerPurpose::NativeAuthenticationDaemon, *polkitPeer_))
        return registrationUnavailable(
            "linura-security-owner: authentication/daemon-revalidation\n");
    registration_ = std::move(registration);
    compositorPid_ = attestedCompositorPid;
    compositorStartTicks_ = compositorStart;
    eventTimer_.start();
    Q_EMIT presentationChanged();
    return true;
}

bool AuthenticationAgent::arm(const NativeApprovalScope &scope, bool compositorSecure,
                              const NativePeerIdentity &controlPeer)
{
    if (QThread::currentThread() != thread() || !registered() || scope_ || !peerGuard_ ||
        !peerGuard_->stillCurrent(NativePeerPurpose::ControlApproval, controlPeer) ||
        !approval_.begin(scope, compositorSecure))
        return false;
    scope_ = scope;
    controlPeer_ = controlPeer;
    Q_EMIT presentationChanged();
    return true;
}

std::optional<QString>
AuthenticationAgent::observePowerPermission(const NativeTransitionIdentity &identity)
{
    const auto action = identity.powerPermissionAction();
    if (QThread::currentThread() != thread() || !registered() || identity.lock != identity_ ||
        !action || !peerGuard_ || !polkitPeer_ || compositorPid_ == 0 ||
        getuid() != identity_.uid || geteuid() != identity_.uid ||
        !peerGuard_->stillCurrent(NativePeerPurpose::NativeAuthenticationDaemon, *polkitPeer_))
        return std::nullopt;
    // A service running as linura-authority cannot inspect vendor actions on
    // another UID's behalf. This native owner is the session's own UID and
    // queries the original compositor process, NOT its service cgroup.
    PolkitSubject *subject = polkit_unix_process_new_for_owner(static_cast<gint>(compositorPid_), 0,
                                                               static_cast<gint>(getuid()));
    const auto started =
        subject ? polkit_unix_process_get_start_time(POLKIT_UNIX_PROCESS(subject)) : 0;
    if (!started || started != compositorStartTicks_) {
        if (subject)
            g_object_unref(subject);
        return std::nullopt;
    }
    RegistrationDeadline deadline(std::chrono::milliseconds(500));
    GError *error = nullptr;
    PolkitAuthority *authority = polkit_authority_get_sync(deadline.cancellable(), &error);
    PolkitAuthorizationResult *result =
        authority ? polkit_authority_check_authorization_sync(authority, subject, action, nullptr,
                                                              POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                                              deadline.cancellable(), &error)
                  : nullptr;
    std::optional<QString> availability;
    if (result && !error && !g_cancellable_is_cancelled(deadline.cancellable())) {
        const bool authorized = polkit_authorization_result_get_is_authorized(result);
        const bool challenge = polkit_authorization_result_get_is_challenge(result);
        if (!(authorized && challenge))
            availability = authorized  ? QStringLiteral("yes")
                           : challenge ? QStringLiteral("challenge")
                                       : QStringLiteral("no");
    }
    if (result)
        g_object_unref(result);
    if (authority)
        g_object_unref(authority);
    if (error)
        g_error_free(error); // No daemon diagnostic text crosses the boundary.
    PolkitSubject *fresh = polkit_unix_process_new_for_owner(static_cast<gint>(compositorPid_), 0,
                                                             static_cast<gint>(getuid()));
    if (!fresh || polkit_unix_process_get_start_time(POLKIT_UNIX_PROCESS(fresh)) != started ||
        !peerGuard_->stillCurrent(NativePeerPurpose::NativeAuthenticationDaemon, *polkitPeer_))
        availability.reset();
    if (fresh)
        g_object_unref(fresh);
    g_object_unref(subject);
    return availability;
}

bool AuthenticationAgent::consume(const NativeApprovalScope &scope)
{
    if (QThread::currentThread() != thread() || !scope_ || *scope_ != scope ||
        !approval_.consume(scope))
        return false;
    scope_.reset();
    controlPeer_.reset();
    Q_EMIT presentationChanged();
    return true;
}

void AuthenticationAgent::confirmLock()
{
    if (scope_ && scope_->purpose == ApprovalPurpose::ConfirmLock &&
        approval_.confirmHuman(*scope_)) {
        Q_EMIT presentationChanged();
        Q_EMIT confirmationAvailable();
    }
}

bool AuthenticationAgent::advanceIdentity(const NativeLockIdentity &identity)
{
    if (QThread::currentThread() != thread() || !registered() || scope_ || task_ ||
        conversation_.active() || !approval_.advanceIdentity(identity))
        return false;
    identity_ = identity;
    return true;
}

void AuthenticationAgent::cancelInteraction()
{
    approval_.cancel();
    if (conversation_.active())
        conversation_.cancel();
    else if (identitySelection_ || task_)
        finishNative(false);
    else {
        scope_.reset();
        controlPeer_.reset();
        Q_EMIT presentationChanged();
        Q_EMIT denied();
    }
}

void AuthenticationAgent::ownerLost()
{
    approval_.ownerLost();
    if (identitySelection_)
        finishNative(false);
    conversation_.ownerLost();
    scope_.reset();
    controlPeer_.reset();
    compositorPid_ = 0;
    compositorStartTicks_ = 0;
    registration_.reset();
    polkitPeer_.reset();
    peerGuard_.reset();
    eventTimer_.stop();
    Q_EMIT presentationChanged();
}

void AuthenticationAgent::initiateNative(PolkitAgentListener *, const char *action,
                                         PolkitDetails *details, const char *cookie,
                                         GList *identities, GCancellable *cancellable, GTask *task)
{
    const char *expectedAction = scope_ ? scope_->authenticationAction() : nullptr;
    if (QThread::currentThread() != thread() || task_ || !scope_ || !entry_ || !peerGuard_ ||
        !polkitPeer_ || !controlPeer_ ||
        !peerGuard_->stillCurrent(NativePeerPurpose::NativeAuthenticationDaemon, *polkitPeer_) ||
        !peerGuard_->stillCurrent(NativePeerPurpose::ControlApproval, *controlPeer_) ||
        !expectedAction || !action || strnlen(action, 129) > 128 ||
        std::strcmp(action, expectedAction) != 0 ||
        !nativeAuthenticationOriginMatches(details, controlPeer_->pid, compositorPid_) ||
        !cancellable || g_cancellable_is_cancelled(cancellable) || !cookie ||
        strnlen(cookie, 1025) == 0 || strnlen(cookie, 1025) > 1024 ||
        approval_.state() != NativeApproval::State::Authenticating) {
        g_task_return_new_error(task, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                                "Native authentication scope unavailable or mismatched");
        return;
    }
    const auto choices = nativeAuthenticationChoices(*scope_, identities);
    if (!choices) {
        g_task_return_new_error(task, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                                "Native authentication identities unavailable");
        return;
    }
    task_ = G_TASK(g_object_ref(task));
    if (choices->size() == 1) {
        for (auto *item = identities; item; item = item->next) {
            if (static_cast<quint32>(polkit_unix_user_get_uid(POLKIT_UNIX_USER(item->data))) ==
                choices->front()) {
                if (!conversation_.begin(*scope_, POLKIT_IDENTITY(item->data), cookie, cancellable,
                                         entry_))
                    finishNative(false);
                Q_EMIT presentationChanged();
                return;
            }
        }
        finishNative(false);
        return;
    }

    // Official daemon identities are retained only until the user explicitly
    // selects a bounded UID using the native protected-input surface. Selection
    // is not PAM authentication or Control approval.
    auto selection = std::make_unique<IdentitySelection>();
    selection->cookie = QByteArray(cookie);
    for (auto *item = identities; item; item = item->next) {
        const auto uid =
            static_cast<quint32>(polkit_unix_user_get_uid(POLKIT_UNIX_USER(item->data)));
        selection->identities.append({uid, POLKIT_IDENTITY(g_object_ref(item->data))});
    }
    identitySelection_ = std::move(selection);
    if (!entry_->beginNativeIdentitySelection(*choices))
        finishNative(false);
    Q_EMIT presentationChanged();
}

void AuthenticationAgent::selectIdentity(quint32 uid)
{
    if (!identitySelection_ || !scope_ || !task_ || !entry_ || !peerGuard_ || !polkitPeer_ ||
        !controlPeer_ || QThread::currentThread() != thread() ||
        approval_.state() != NativeApproval::State::Authenticating ||
        g_cancellable_is_cancelled(g_task_get_cancellable(task_)) ||
        !peerGuard_->stillCurrent(NativePeerPurpose::NativeAuthenticationDaemon, *polkitPeer_) ||
        !peerGuard_->stillCurrent(NativePeerPurpose::ControlApproval, *controlPeer_)) {
        finishNative(false);
        return;
    }
    PolkitIdentity *identity = nullptr;
    for (const auto &choice : identitySelection_->identities) {
        if (choice.first == uid) {
            identity = choice.second;
            break;
        }
    }
    if (!identity) {
        finishNative(false);
        return;
    }
    entry_->cancelNativePrompt();
    const bool started =
        conversation_.begin(*scope_, identity, identitySelection_->cookie.constData(),
                            g_task_get_cancellable(task_), entry_);
    identitySelection_.reset();
    if (!started)
        finishNative(false);
    Q_EMIT presentationChanged();
}

void AuthenticationAgent::finishNative(bool success)
{
    if (identitySelection_ && entry_)
        entry_->cancelNativePrompt();
    identitySelection_.reset();
    if (!success)
        approval_.cancel(); // Failed startup cannot leave a stranded armed conversation.
    if (task_) {
        if (success)
            g_task_return_boolean(task_, TRUE);
        else
            g_task_return_new_error(task_, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                                    "Native authentication cancelled or denied");
        g_object_unref(task_);
        task_ = nullptr;
    }
    if (!success) {
        scope_.reset();
        controlPeer_.reset();
    }
    Q_EMIT presentationChanged();
    if (success)
        Q_EMIT confirmationAvailable();
    else
        Q_EMIT denied();
}

} // namespace Linura::SecurityOwner
