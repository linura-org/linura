#include "native_runtime.h"
#include "authentication_agent.h"
#include "native_deadline.h"
#include "native_endpoint.h"
#include "native_lock_protocol.h"
#include "native_presentation.h"
#include "native_wayland_lock.h"
#include "native_wayland_readiness.h"
#include "native_unlock_status.h"
#include "native_assistive.h"
#include "native_transition_fence.h"
#include "peer_guard.h"
#include "session_bootstrap.h"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QDBusPendingCallWatcher>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <wayland-client.h>
#include <chrono>
#include <cstddef>
#include <utility>
#include <sys/prctl.h>
#include <unistd.h>

namespace Linura::SecurityOwner {
namespace {
template <std::size_t N> bool runtimeUnavailable(const char (&reason)[N]) noexcept
{
    // Fixed, nonsecret stage only; no session identifiers or authentication input.
    const ssize_t written = ::write(STDERR_FILENO, reason, N - 1);
    (void)written;
    return false;
}

[[noreturn]] void failClosed()
{
    _exit(NativeLockProtocol::NativeLockFaultExit);
}
} // namespace

class NativeRuntime::Impl final
{
  public:
    NativeRuntime &owner;
    std::optional<PeerGuard> peers;
    std::optional<NativeSessionBinding> binding;
    NativeProbeProgress probeProgress;
    QString compositorSocket;
    std::unique_ptr<NativePresentation> presentation;
    std::unique_ptr<NativeAssistiveBridge> assistive;
    std::unique_ptr<NativeWaylandLock> backend;
    std::unique_ptr<NativeLockProtocol> protocol;
    std::unique_ptr<AuthenticationAgent> authentication;
    std::optional<NativePeerIdentity> approvalPeer;
    std::optional<NativeApprovalScope> approvalScope;
    NativeTransitionFence transitionFence;
    NativeSleepFence sleepFence;
    bool sleepNotVerified = false;
    // Correlation only, captured from the consumed exact native challenge. Not
    // durable intent, approval or prepared authority. Used solely to ask Control
    // for historical status/observe-only recovery while the shell is covered.
    std::optional<std::pair<NativeTransitionIdentity, QString>> transitionRequest;
    bool transitionRecoveryPending = false;
    unsigned transitionRecoveryAttempts = 0;
    QTimer maintenance;
    bool initialized = false;
    bool inCall = false;
    bool unlockRequestPending = false;
    std::optional<NativeLockIdentity> unlockRequestLock;
    QString unlockOperation;
    // Set only after actual consumption of this operation's native proof.
    // An error after that point can hide execution and must remain fenced.
    bool unlockProofConsumed = false;
    unsigned unlockRecoveryAttempts = 0;
    NativeEndpoint *endpoint = nullptr;

    explicit Impl(NativeRuntime &instance) : owner(instance) {}
    ~Impl()
    {
        // Never unwind QObject/Wayland objects while coverage or a release is
        // active. Exit without any cleanup opcode, leaving compositor recovery
        // responsible for retaining its native blank lock.
        if (backend && (backend->requestedSecure() || backend->secureCoverage()))
            failClosed();
        maintenance.stop();
        if (endpoint && peers) {
            auto connection = peers->nativeConnection();
            connection.unregisterObject(NativeEndpoint::objectPath());
            delete endpoint;
            endpoint = nullptr;
        }
        authentication.reset();
        assistive.reset();
        protocol.reset();
        backend.reset();
        presentation.reset();
    }
    void correctThread() const
    {
        if (owner.thread() != QThread::currentThread())
            failClosed();
    }
    bool currentSession() const
    {
        if (!peers || !binding || !backend || prctl(PR_GET_DUMPABLE) != 0 ||
            (initialized && (!presentation || !presentation->ready())))
            return false;
        return inspectNativeSession(peers->nativeConnection(), backend->actualDisplayFd(),
                                    probeProgress) == binding;
    }
    std::optional<NativePeerIdentity> caller(const QDBusMessage &received,
                                             NativePeerPurpose purpose)
    {
        correctThread();
        if (!initialized || inCall || received.type() != QDBusMessage::MethodCallMessage ||
            !peers || !currentSession())
            return std::nullopt;
        return peers->attest(purpose, received.service());
    }
    std::optional<NativeCompositorLockState> independentState() const
    {
        if (!currentSession())
            return std::nullopt;
        const auto result = observeNativeHyprlandLock(compositorSocket, *binding);
        if (!result || !currentSession())
            return std::nullopt;
        return result;
    }
    void clearApproval()
    {
        // Clear before invoking callbacks, which can emit presentation signals.
        approvalScope.reset();
        approvalPeer.reset();
        if (backend)
            backend->cancelLockConfirmation();
        if (authentication)
            authentication->cancelInteraction();
    }
    void refreshPresentation()
    {
        if (!initialized || !authentication || !presentation || !backend)
            return;
        if (transitionFence.active() || sleepFence.active())
            presentation->present(NativePresentation::State::Recovering);
        else if (approvalScope && approvalScope->purpose != ApprovalPurpose::ConfirmLock)
            presentation->presentAuthentication(approvalScope->purpose);
        else if (authentication->confirmationPending())
            presentation->present(NativePresentation::State::ConfirmingLock);
        else if (sleepNotVerified)
            presentation->present(NativePresentation::State::SleepNotVerified);
        else
            presentation->present(NativePresentation::State::Locked);
    }
    void publishAssistiveMetadata()
    {
        if (assistive && presentation && backend)
            assistive->publish(presentation->assistiveProjection(
                backend->secureCoverage() || backend->lockConfirmationVisible()));
    }
};

NativeRuntime::NativeRuntime() : impl_(std::make_unique<Impl>(*this)) {}
NativeRuntime::~NativeRuntime() = default;

std::unique_ptr<NativeRuntime> NativeRuntime::create(NativeStartup startup)
{
    auto runtime = std::unique_ptr<NativeRuntime>(new NativeRuntime());
    if (!runtime->initialize(std::move(startup)))
        return {};
    return runtime;
}

bool NativeRuntime::initialize(NativeStartup startup)
{
    impl_->correctThread();
    if (startup.uid_ == 0 || startup.uid_ != getuid() || geteuid() != getuid() ||
        !qobject_cast<QGuiApplication *>(QCoreApplication::instance()) ||
        prctl(PR_GET_DUMPABLE) != 0)
        return runtimeUnavailable("linura-security-owner: runtime/process-state\n");
    NativeDeadline deadline(std::chrono::milliseconds(8'000),
                            NativeDeadline::Stage::RuntimeInitialization);
    impl_->peers = PeerGuard::connect();
    if (!impl_->peers)
        return runtimeUnavailable("linura-security-owner: runtime/system-bus\n");
    wl_display *display = nullptr;
    for (const auto &candidate : startup.routes_.wayland) {
        auto *connected = wl_display_connect(candidate.toLocal8Bit().constData());
        if (!connected)
            continue;
        const auto binding =
            inspectNativeSession(impl_->peers->nativeConnection(), wl_display_get_fd(connected));
        if (!binding) {
            wl_display_disconnect(connected);
            continue;
        }
        if (display) {
            wl_display_disconnect(connected);
            wl_display_disconnect(display);
            return runtimeUnavailable("linura-security-owner: runtime/ambiguous-session\n");
        }
        display = connected;
        impl_->binding = binding;
    }
    if (!display || !impl_->binding)
        return runtimeUnavailable("linura-security-owner: runtime/session-attestation\n");
    // The exact owned connection is adopted before any protocol binding. Never
    // probe one socket and let Qt/a later pathname connect to another server.
    impl_->backend = std::make_unique<NativeWaylandLock>(display, [this](quint32, QImage &frame) {
        return impl_->presentation && impl_->presentation->paint(frame);
    });
    // A published/listening socket can precede the compositor event loop.
    // Require a reply on the SAME attested Wayland connection before probing
    // the independent control socket. This emits no lock or input opcode.
    if (!waitForNativeWaylandReady(display, NativeCompositorReadinessContract::maximumWait))
        return runtimeUnavailable("linura-security-owner: runtime/compositor-readiness\n");
    for (const auto &candidate : startup.routes_.compositor) {
        NativeCompositorProbeFailure failure;
        if (!observeNativeHyprlandLock(candidate, *impl_->binding, &failure)) {
            switch (failure) {
            case NativeCompositorProbeFailure::Binding:
                runtimeUnavailable("linura-security-owner: compositor/binding\n");
                break;
            case NativeCompositorProbeFailure::Route:
                runtimeUnavailable("linura-security-owner: compositor/route\n");
                break;
            case NativeCompositorProbeFailure::Socket:
                runtimeUnavailable("linura-security-owner: compositor/socket\n");
                break;
            case NativeCompositorProbeFailure::Connect:
                runtimeUnavailable("linura-security-owner: compositor/connect\n");
                break;
            case NativeCompositorProbeFailure::Peer:
                runtimeUnavailable("linura-security-owner: compositor/peer\n");
                break;
            case NativeCompositorProbeFailure::Send:
                runtimeUnavailable("linura-security-owner: compositor/send\n");
                break;
            case NativeCompositorProbeFailure::Receive:
                runtimeUnavailable("linura-security-owner: compositor/receive\n");
                break;
            case NativeCompositorProbeFailure::Deadline:
                runtimeUnavailable("linura-security-owner: compositor/deadline\n");
                break;
            case NativeCompositorProbeFailure::Reply:
                runtimeUnavailable("linura-security-owner: compositor/reply\n");
                break;
            case NativeCompositorProbeFailure::ReplyLimit:
                runtimeUnavailable("linura-security-owner: compositor/reply-limit\n");
                break;
            case NativeCompositorProbeFailure::None:
                runtimeUnavailable("linura-security-owner: compositor/unavailable\n");
                break;
            }
            continue;
        }
        if (!impl_->compositorSocket.isEmpty())
            return runtimeUnavailable("linura-security-owner: runtime/ambiguous-compositor\n");
        impl_->compositorSocket = candidate;
    }
    if (impl_->compositorSocket.isEmpty())
        return runtimeUnavailable("linura-security-owner: runtime/compositor-attestation\n");
    if (!impl_->currentSession())
        return runtimeUnavailable("linura-security-owner: runtime/session-revalidation\n");
    impl_->presentation = std::make_unique<NativePresentation>();
    if (!impl_->presentation->initialize() ||
        !impl_->backend->bindProtectedInput(
            impl_->presentation->protectedEntry(),
            [this] { QTimer::singleShot(0, this, &NativeRuntime::requestNativeUnlock); },
            [this] { return impl_->presentation->primaryRequestAvailable(); },
            [this](QSize viewport, const QPointF &position) {
                return impl_->presentation->pointerTarget(viewport, position);
            }) ||
        !impl_->backend->initialize())
        return runtimeUnavailable("linura-security-owner: runtime/protected-input\n");
    impl_->protocol = std::make_unique<NativeLockProtocol>(*impl_->backend, impl_->binding->lock);
    if (!impl_->protocol->bound())
        return runtimeUnavailable("linura-security-owner: runtime/protocol-identity\n");
    // An admitted lock can receive its compositor acknowledgement while a
    // synchronous peer/session audit is still running. Progress only the owned
    // Wayland fd between bounded reads, never a nested Qt event loop. All probe
    // clocks and post-progress identity/scope/coverage checks remain in force.
    impl_->probeProgress = [this] { impl_->backend->progressNativeState(); };
    impl_->peers->setNativeProgress(impl_->probeProgress);
    if (!impl_->currentSession())
        return runtimeUnavailable("linura-security-owner: runtime/protocol-identity\n");
    impl_->authentication = std::make_unique<AuthenticationAgent>(
        impl_->binding->lock, &impl_->presentation->protectedEntry());
    if (!impl_->authentication->registerNativeSession(impl_->binding->compositorPid))
        return runtimeUnavailable("linura-security-owner: runtime/auth-registration\n");
    if (!impl_->authentication->setNativeProgress(impl_->probeProgress))
        return runtimeUnavailable("linura-security-owner: runtime/auth-progress\n");
    impl_->assistive = std::make_unique<NativeAssistiveBridge>(startup.uid_);
    impl_->publishAssistiveMetadata();
    connect(impl_->presentation.get(), &NativePresentation::repaintRequested, this,
            [this] { impl_->publishAssistiveMetadata(); });
    connect(impl_->backend.get(), &NativeManagedLockBackend::nativeStateChanged, this,
            [this] { impl_->publishAssistiveMetadata(); });

    connect(impl_->presentation.get(), &NativePresentation::repaintRequested, impl_->backend.get(),
            &NativeWaylandLock::repaint, Qt::QueuedConnection);
    connect(impl_->authentication.get(), &AuthenticationAgent::presentationChanged, this,
            [this] { impl_->refreshPresentation(); });
    connect(impl_->authentication.get(), &AuthenticationAgent::confirmationAvailable, this,
            &NativeRuntime::approvalInteractionCompleted);
    connect(impl_->authentication.get(), &AuthenticationAgent::scopeRetired, this,
            [this](const NativeApprovalScope &retired) {
                if (!impl_->approvalScope || *impl_->approvalScope != retired)
                    return;
                impl_->approvalScope.reset();
                impl_->approvalPeer.reset();
                impl_->backend->cancelLockConfirmation();
                // A retired, never-consumed native unlock proof cannot have
                // authorized dispatch for this exact operation. A transport
                // error alone is NOT evidence of absence and never clears it.
                const auto prefix = QStringLiteral("request:v010:session-lock:");
                const auto request = prefix + impl_->unlockOperation;
                if (retired.purpose == ApprovalPurpose::AuthenticateUnlock &&
                    !impl_->unlockProofConsumed && impl_->unlockRequestLock == retired.lock &&
                    retired.request == request) {
                    impl_->unlockRequestLock.reset();
                    impl_->unlockOperation.clear();
                    impl_->unlockRecoveryAttempts = 0;
                }
                impl_->refreshPresentation();
            });
    connect(impl_->authentication.get(), &AuthenticationAgent::denied, this, [this] {
        impl_->approvalScope.reset();
        impl_->approvalPeer.reset();
        impl_->backend->cancelLockConfirmation();
        impl_->presentation->present(NativePresentation::State::Denied);
    });
    impl_->maintenance.setInterval(2'000);
    connect(&impl_->maintenance, &QTimer::timeout, this, [this] {
        if (!impl_->currentSession())
            failClosed();
        if (impl_->approvalPeer &&
            !impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, *impl_->approvalPeer))
            impl_->clearApproval();
        if (impl_->protocol->inspect() == LockMechanism::State::Faulted)
            failClosed();
        if (impl_->sleepFence.active())
            recoverNativeSleepEntry();
        impl_->publishAssistiveMetadata();
    });
    impl_->initialized = true;
    impl_->maintenance.start();
    return true;
}

const NativeLockIdentity &NativeRuntime::identity() const noexcept
{
    return impl_->protocol->identity();
}

void NativeRuntime::requestNativeUnlock()
{
    impl_->correctThread();
    if (impl_->sleepFence.active()) {
        recoverNativeSleepEntry(); // Observation only; this input never unlocks.
        return;
    }
    if (impl_->transitionFence.active()) {
        // Explicit native input can recheck recovery, never bypass the fence or
        // turn an uncertain power operation into a fresh unlock/effect request.
        impl_->transitionRecoveryAttempts = 0;
        recoverNativeTransition();
        return;
    }
    if (!impl_->initialized || impl_->unlockRequestPending || impl_->approvalScope ||
        impl_->transitionFence.active() || !impl_->currentSession() ||
        impl_->protocol->inspect() != LockMechanism::State::Secure ||
        impl_->independentState() != NativeCompositorLockState::Locked)
        return;
    const auto control = impl_->peers->namedPeer(NativePeerPurpose::ControlApproval);
    if (!control) {
        impl_->presentation->present(NativePresentation::State::Unavailable);
        return;
    }
    const auto lock = identity();
    impl_->sleepNotVerified =
        false; // Explicit native unlock interaction, not a sleep success claim.
    // Never submit a second ConvergeSessionLock for unresolved correlation,
    // even with an identical idempotency key. Historical recovery is read-only
    // with respect to effect dispatch.
    if (impl_->unlockRequestLock == lock) {
        impl_->unlockRecoveryAttempts = 0;
        recoverNativeUnlock();
        return;
    }
    impl_->unlockRequestLock = lock;
    impl_->unlockProofConsumed = false;
    impl_->unlockOperation =
        QStringLiteral("unlock-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    const auto operation = impl_->unlockOperation;
    auto message = QDBusMessage::createMethodCall(
        control->uniqueOwner, QStringLiteral("/org/linura/Authority1"),
        QStringLiteral("org.linura.Authority1"), QStringLiteral("ConvergeSessionLock"));
    message.setArguments({operation, lock.resource, false,
                          QStringLiteral("Unlock my current native graphical session")});
    impl_->unlockRequestPending = true;
    impl_->unlockRecoveryAttempts = 0;
    auto *watcher = new QDBusPendingCallWatcher(
        impl_->peers->nativeConnection().asyncCall(message, 90'000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, control = *control, lock, operation](QDBusPendingCallWatcher *reply) {
                reply->deleteLater();
                if (impl_->unlockRequestLock != lock || impl_->unlockOperation != operation) {
                    impl_->unlockRequestPending = false;
                    return;
                }
                // The receipt is NOT native post-state or authentication success. Only
                // Control's already-separated native dispatch/verify/commit calls can
                // release coverage and rotate this generation. No effect is retried.
                const bool peerCurrent =
                    impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, control);
                const bool definitive =
                    peerCurrent &&
                    definitiveNativeUnlockReject(reply->reply(), impl_->unlockProofConsumed,
                                                 impl_->approvalScope.has_value()) &&
                    impl_->protocol->inspect() == LockMechanism::State::Secure &&
                    impl_->independentState() == NativeCompositorLockState::Locked;
                if (definitive) {
                    // The authenticated Control reply is complete, and this
                    // operation never obtained a consumed native proof. No
                    // prepared executor dispatch could have been authorized.
                    impl_->unlockRequestLock.reset();
                    impl_->unlockOperation.clear();
                    impl_->unlockRecoveryAttempts = 0;
                } else if (!peerCurrent || reply->isError()) {
                    impl_->presentation->present(NativePresentation::State::Recovering);
                    QTimer::singleShot(2'000, this, &NativeRuntime::recoverNativeUnlock);
                } else if (lock.wasRetiredBy(identity())) {
                    impl_->unlockRequestLock.reset();
                    impl_->unlockOperation.clear();
                }
                impl_->unlockRequestPending = false;
            });
}

void NativeRuntime::recoverNativeTransition()
{
    impl_->correctThread();
    if (!impl_->initialized || !impl_->transitionRequest || !impl_->transitionFence.active() ||
        impl_->transitionRecoveryPending || impl_->transitionRecoveryAttempts >= 3 ||
        !impl_->currentSession())
        return;
    const auto [target, request] = *impl_->transitionRequest;
    if (target.transition != NativeSessionTransition::Suspend || target.lock != identity())
        return;
    ++impl_->transitionRecoveryAttempts;
    const auto retry = [this] {
        QTimer::singleShot(2'000, this, &NativeRuntime::recoverNativeTransition);
    };
    const auto control = impl_->peers->namedPeer(NativePeerPurpose::ControlApproval);
    if (!control) {
        retry();
        return;
    }
    auto message = QDBusMessage::createMethodCall(
        control->uniqueOwner, QStringLiteral("/org/linura/Authority1"),
        QStringLiteral("org.linura.Authority1"),
        QStringLiteral("GetSessionTransitionRequestStatus"));
    message.setArguments({request});
    impl_->transitionRecoveryPending = true;
    auto *status = new QDBusPendingCallWatcher(
        impl_->peers->nativeConnection().asyncCall(message, 2'000), this);
    connect(status, &QDBusPendingCallWatcher::finished, this,
            [this, control = *control, target, request, retry](QDBusPendingCallWatcher *result) {
                result->deleteLater();
                if (!impl_->transitionRequest ||
                    *impl_->transitionRequest != std::pair{target, request} ||
                    !impl_->transitionFence.active())
                    return;
                impl_->transitionRecoveryPending = false;
                if (!impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, control)) {
                    retry();
                    return;
                }
                const auto step = decodeNativeTransitionStatus(result->reply(), request, target);
                if (!step) {
                    retry();
                    return;
                }
                if (*step == NativeTransitionRecoveryStep::Stop)
                    return;
                auto recovery = QDBusMessage::createMethodCall(
                    control.uniqueOwner, QStringLiteral("/org/linura/Authority1"),
                    QStringLiteral("org.linura.Authority1"),
                    *step == NativeTransitionRecoveryStep::AcknowledgeCommitted
                        ? QStringLiteral("AcknowledgeSessionTransition")
                        : QStringLiteral("RecoverSessionTransition"));
                recovery.setArguments({request});
                impl_->transitionRecoveryPending = true;
                auto *completion = new QDBusPendingCallWatcher(
                    impl_->peers->nativeConnection().asyncCall(recovery, 10'000), this);
                connect(completion, &QDBusPendingCallWatcher::finished, this,
                        [this, target, request, retry](QDBusPendingCallWatcher *reply) {
                            reply->deleteLater();
                            if (impl_->transitionRequest != std::pair{target, request})
                                return;
                            impl_->transitionRecoveryPending = false;
                            // No receipt/boolean releases coverage. Only the separately
                            // gated commit endpoint's own native cycle/coverage check.
                            if (impl_->transitionRequest == std::pair{target, request} &&
                                impl_->transitionFence.active())
                                retry();
                        });
            });
}

void NativeRuntime::recoverNativeUnlock()
{
    impl_->correctThread();
    if (!impl_->unlockRequestLock || impl_->unlockRequestPending || !impl_->currentSession())
        return;
    const auto lock = *impl_->unlockRequestLock;
    if (lock.wasRetiredBy(identity())) {
        impl_->unlockRequestLock.reset();
        impl_->unlockOperation.clear();
        return;
    }
    if (lock != identity() || impl_->unlockRecoveryAttempts >= 3)
        return;
    ++impl_->unlockRecoveryAttempts;
    const auto control = impl_->peers->namedPeer(NativePeerPurpose::ControlApproval);
    if (!control) {
        QTimer::singleShot(2'000, this, &NativeRuntime::recoverNativeUnlock);
        return;
    }
    const auto request = QStringLiteral("request:v010:session-lock:") + impl_->unlockOperation;
    auto message = QDBusMessage::createMethodCall(
        control->uniqueOwner, QStringLiteral("/org/linura/Authority1"),
        QStringLiteral("org.linura.Authority1"), QStringLiteral("GetSessionLockRequestStatus"));
    message.setArguments({request});
    impl_->unlockRequestPending = true;
    auto *watcher = new QDBusPendingCallWatcher(
        impl_->peers->nativeConnection().asyncCall(message, 2'000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, control = *control, lock, request](QDBusPendingCallWatcher *reply) {
                reply->deleteLater();
                if (!impl_->unlockRequestLock || *impl_->unlockRequestLock != lock) {
                    impl_->unlockRequestPending = false;
                    return;
                }
                if (!impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, control) ||
                    reply->isError()) {
                    impl_->unlockRequestPending = false;
                    QTimer::singleShot(2'000, this, &NativeRuntime::recoverNativeUnlock);
                    return;
                }
                const auto step = decodeNativeUnlockStatus(reply->reply(), request, lock);
                if (!step || *step == NativeUnlockRecoveryStep::Stop) {
                    impl_->unlockRequestPending = false;
                    return;
                }
                if (*step == NativeUnlockRecoveryStep::Aborted) {
                    // Authenticated terminal transaction state is not a new
                    // approval; confirm native coverage is still secure before
                    // abandoning its correlation. Never dispatch or unlock here.
                    if (impl_->protocol->inspect() == LockMechanism::State::Secure &&
                        impl_->independentState() == NativeCompositorLockState::Locked &&
                        !impl_->transitionFence.active() && !impl_->sleepFence.active()) {
                        impl_->unlockRequestLock.reset();
                        impl_->unlockOperation.clear();
                        impl_->unlockRecoveryAttempts = 0;
                    }
                    impl_->unlockRequestPending = false;
                    return;
                }
                const bool acknowledge = *step == NativeUnlockRecoveryStep::AcknowledgeCommitted;
                auto recovery = QDBusMessage::createMethodCall(
                    control.uniqueOwner, QStringLiteral("/org/linura/Authority1"),
                    QStringLiteral("org.linura.Authority1"),
                    acknowledge ? QStringLiteral("AcknowledgeSessionLockRelease")
                                : QStringLiteral("RecoverSessionLock"));
                recovery.setArguments({request});
                impl_->unlockRequestPending = true;
                // Neither method accepts an executor or approval. A timeout cannot
                // generate a new effect/request; only status is observed again.
                auto *completion = new QDBusPendingCallWatcher(
                    impl_->peers->nativeConnection().asyncCall(recovery, 10'000), this);
                connect(completion, &QDBusPendingCallWatcher::finished, this,
                        [this, lock](QDBusPendingCallWatcher *result) {
                            result->deleteLater();
                            impl_->unlockRequestPending = false;
                            // Receipt/boolean is not evidence. Only our separately gated
                            // private commit call can actually rotate the native generation.
                            if (lock.wasRetiredBy(identity())) {
                                impl_->unlockRequestLock.reset();
                                impl_->unlockOperation.clear();
                            } else
                                QTimer::singleShot(2'000, this,
                                                   &NativeRuntime::recoverNativeUnlock);
                        });
            });
}

bool NativeRuntime::armApproval(const QDBusMessage &received, const NativeApprovalScope &scope)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (!peer || impl_->approvalScope || impl_->transitionFence.active() ||
        impl_->sleepFence.active() || !scope.valid() || scope.lock != identity())
        return false;
    NativeDeadline deadline(std::chrono::milliseconds(5'000), NativeDeadline::Stage::ApprovalArm);
    const auto state = impl_->independentState();
    if (!state || !impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, *peer))
        return false;
    const auto mechanism = impl_->protocol->inspect();
    const bool secure = *state == NativeCompositorLockState::Locked;
    if ((scope.purpose == ApprovalPurpose::ConfirmLock &&
         (secure || mechanism != LockMechanism::State::Ready)) ||
        (scope.purpose != ApprovalPurpose::ConfirmLock &&
         (!secure || mechanism != LockMechanism::State::Secure)))
        return false;
    impl_->approvalScope = scope;
    impl_->approvalPeer = *peer;
    impl_->inCall = true;
    const bool armed = impl_->authentication->arm(scope, secure, *peer);
    impl_->inCall = false;
    if (!armed) {
        impl_->approvalScope.reset();
        impl_->approvalPeer.reset();
        return false;
    }
    if (scope.purpose == ApprovalPurpose::ConfirmLock) {
        if (!impl_->backend->showLockConfirmation([this, scope, peer = *peer](bool confirmed) {
                // Do native attestation outside the Wayland callback/500ms pump.
                QTimer::singleShot(0, this, [this, scope, peer, confirmed] {
                    if (!impl_->approvalScope || *impl_->approvalScope != scope ||
                        impl_->approvalPeer != peer)
                        return;
                    if (!confirmed || !impl_->currentSession() ||
                        !impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, peer) ||
                        impl_->independentState() != NativeCompositorLockState::Unlocked) {
                        impl_->clearApproval();
                        return;
                    }
                    impl_->authentication->confirmLock();
                });
            })) {
            impl_->clearApproval();
            return false;
        }
    }
    return true;
}

bool NativeRuntime::consumeApproval(const QDBusMessage &received, const NativeApprovalScope &scope)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (!peer || impl_->approvalPeer != peer || !impl_->approvalScope ||
        *impl_->approvalScope != scope || scope.lock != identity())
        return false;
    const auto state = impl_->independentState();
    const auto expected = scope.purpose == ApprovalPurpose::ConfirmLock
                              ? NativeCompositorLockState::Unlocked
                              : NativeCompositorLockState::Locked;
    if (state != expected || !impl_->authentication->consume(scope))
        return false;
    if (scope.transition)
        impl_->transitionRequest = std::pair{*scope.transition, scope.request};
    if (scope.purpose == ApprovalPurpose::AuthenticateUnlock &&
        impl_->unlockRequestLock == scope.lock)
        impl_->unlockProofConsumed = true;
    impl_->approvalScope.reset();
    impl_->approvalPeer.reset();
    if (scope.purpose == ApprovalPurpose::EnableProtectiveLock ||
        scope.purpose == ApprovalPurpose::RevokeProtectiveLock)
        impl_->refreshPresentation(); // Authentication emitted before runtime scope retirement.
    return true;
}

bool NativeRuntime::dispatchPrepared(const QDBusMessage &received, const NativeLockIdentity &lock,
                                     bool secure)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::PreparedSessionDispatch);
    if (!peer || lock != identity() || impl_->approvalScope || impl_->transitionFence.active() ||
        impl_->sleepFence.active())
        return false;
    // Only the separately attested root session executor can call this. A human
    // approval or its identifiers never reach dispatch as reusable authority.
    return impl_->protocol->dispatch(lock, secure);
}

std::optional<NativeObservedLockState> nativeObservedLockState(NativeCompositorLockState compositor,
                                                               LockMechanism::State mechanism,
                                                               bool requested, bool coverage)
{
    if (compositor != NativeCompositorLockState::Locked &&
        compositor != NativeCompositorLockState::Unlocked)
        return std::nullopt;
    if (mechanism == LockMechanism::State::Acquiring && requested && !coverage)
        return NativeObservedLockState::Acquiring;
    if (mechanism == LockMechanism::State::Releasing) {
        if (!requested && !coverage && compositor == NativeCompositorLockState::Unlocked)
            return NativeObservedLockState::Unlocked;
        if (requested || !coverage)
            return NativeObservedLockState::Releasing;
        return std::nullopt;
    }
    if (mechanism == LockMechanism::State::Secure && requested && coverage &&
        compositor == NativeCompositorLockState::Locked)
        return NativeObservedLockState::Secure;
    if ((mechanism == LockMechanism::State::Ready || mechanism == LockMechanism::State::Released) &&
        !requested && !coverage && compositor == NativeCompositorLockState::Unlocked)
        return NativeObservedLockState::Unlocked;
    return std::nullopt;
}

std::optional<NativeObservedLockState> NativeRuntime::observe(const QDBusMessage &received)
{
    if (!impl_->caller(received, NativePeerPurpose::ControlApproval))
        return std::nullopt;
    impl_->backend->refreshNativeState();
    const auto independent = impl_->independentState();
    if (!independent)
        return std::nullopt;
    const auto mechanism = impl_->protocol->inspect();
    return nativeObservedLockState(*independent, mechanism, impl_->backend->requestedSecure(),
                                   impl_->backend->secureCoverage());
}

bool NativeRuntime::fencePreparedTransition(const QDBusMessage &received,
                                            const NativeTransitionIdentity &target)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::PreparedSessionDispatch);
    if (!peer || impl_->approvalScope || impl_->sleepFence.active() || impl_->unlockRequestLock ||
        !impl_->transitionRequest || impl_->transitionRequest->first != target ||
        impl_->protocol->inspect() != LockMechanism::State::Secure ||
        impl_->independentState() != NativeCompositorLockState::Locked)
        return false;
    const auto cycles = target.transition == NativeSessionTransition::Suspend
                            ? nativeSuccessfulSuspendCycles()
                            : std::nullopt;
    if (!impl_->currentSession() ||
        !impl_->peers->stillCurrent(NativePeerPurpose::PreparedSessionDispatch, *peer))
        return false;
    const bool armed = impl_->transitionFence.arm(target, identity(), true, cycles);
    if (armed) {
        impl_->transitionRecoveryAttempts = 0;
        impl_->transitionRecoveryPending = false;
        QTimer::singleShot(2'000, this, &NativeRuntime::recoverNativeTransition);
    }
    impl_->refreshPresentation();
    return armed;
}

bool NativeRuntime::cancelUndispatchedTransition(const QDBusMessage &received,
                                                 const NativeTransitionIdentity &target)
{
    // Only the separately attested executor can know it has NOT queued an OS effect.
    // Control/client cancellation, lost replies and timeouts cannot clear this.
    const auto peer = impl_->caller(received, NativePeerPurpose::PreparedSessionDispatch);
    if (!peer || target.lock != identity() ||
        impl_->protocol->inspect() != LockMechanism::State::Secure ||
        impl_->independentState() != NativeCompositorLockState::Locked ||
        (target.transition == NativeSessionTransition::Suspend &&
         nativeSuccessfulSuspendCycles() != target.successfulCyclesBefore) ||
        !impl_->peers->stillCurrent(NativePeerPurpose::PreparedSessionDispatch, *peer))
        return false;
    const bool cancelled = impl_->transitionFence.cancelUndispatched(target);
    if (cancelled) {
        impl_->transitionRequest.reset();
        impl_->transitionRecoveryPending = false;
    }
    impl_->refreshPresentation();
    return cancelled;
}

bool NativeRuntime::commitVerifiedTransition(const QDBusMessage &received,
                                             const NativeTransitionIdentity &target)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (!peer || impl_->protocol->inspect() != LockMechanism::State::Secure ||
        impl_->independentState() != NativeCompositorLockState::Locked)
        return false;
    const auto cycles = nativeSuccessfulSuspendCycles();
    if (!impl_->currentSession() ||
        !impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, *peer))
        return false;
    const bool committed = impl_->transitionFence.commitSuspend(target, identity(), true, cycles);
    if (committed && !impl_->transitionFence.active() && impl_->transitionRequest &&
        impl_->transitionRequest->first == target) {
        impl_->transitionRequest.reset();
        impl_->transitionRecoveryPending = false;
    }
    impl_->refreshPresentation();
    return committed;
}

bool NativeRuntime::verifyReleased(const QDBusMessage &received, const NativeLockIdentity &lock)
{
    if (!impl_->caller(received, NativePeerPurpose::ControlApproval) ||
        impl_->sleepFence.active() || lock != identity() ||
        impl_->independentState() != NativeCompositorLockState::Unlocked)
        return false;
    return impl_->protocol->independentlyVerifiedReleased(lock);
}

bool NativeRuntime::retainedVerifiedRelease(const QDBusMessage &received,
                                            const NativeLockIdentity &lock)
{
    // This is retained native proof, not a second release event. The actual
    // authenticated Control peer and independent compositor must still agree;
    // requested=false by itself is never sufficient (Ready is also unlocked).
    if (!impl_->caller(received, NativePeerPurpose::ControlApproval))
        return false;
    if (impl_->sleepFence.active() || lock != identity())
        return false;
    if (impl_->backend->requestedSecure() || impl_->backend->secureCoverage())
        return false;
    if (impl_->independentState() != NativeCompositorLockState::Unlocked)
        return false;
    return impl_->protocol->retainedVerifiedRelease(lock);
}

bool NativeRuntime::fenceSleepEntry(const QDBusMessage &received,
                                    const NativeSleepEntryIdentity &event,
                                    const NativeLockIdentity &lock)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (!peer)
        return runtimeUnavailable("native-sleep-owner-denied reason=peer\n");
    if (lock != identity() || event.boot != lock.boot)
        return runtimeUnavailable("native-sleep-owner-denied reason=binding\n");
    if (impl_->approvalScope || impl_->unlockRequestLock)
        return runtimeUnavailable("native-sleep-owner-denied reason=scope\n");
    if (impl_->protocol->inspect() != LockMechanism::State::Secure)
        return runtimeUnavailable("native-sleep-owner-denied reason=mechanism\n");
    if (impl_->independentState() != NativeCompositorLockState::Locked)
        return runtimeUnavailable("native-sleep-owner-denied reason=compositor\n");
    NativeDeadline deadline(std::chrono::milliseconds(8'000), NativeDeadline::Stage::SleepEntry);
    const auto cycles = nativeSuccessfulSuspendCycles();
    const auto unit = impl_->peers->sleepUnitSnapshot(true);
    if (!cycles)
        return runtimeUnavailable("native-sleep-owner-denied reason=counter\n");
    if (!unit)
        return runtimeUnavailable("native-sleep-owner-denied reason=unit-snapshot\n");
    if (impl_->transitionFence.active() && !impl_->transitionFence.coversSuspend(lock, *cycles))
        return runtimeUnavailable("native-sleep-owner-denied reason=transition\n");
    if (!impl_->currentSession())
        return runtimeUnavailable("native-sleep-owner-denied reason=session\n");
    if (!impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, *peer))
        return runtimeUnavailable("native-sleep-owner-denied reason=peer-generation\n");
    if (nativeSuccessfulSuspendCycles() != cycles)
        return runtimeUnavailable("native-sleep-owner-denied reason=counter-generation\n");
    if (impl_->independentState() != NativeCompositorLockState::Locked)
        return runtimeUnavailable("native-sleep-owner-denied reason=coverage\n");
    // This is solely a fence around already-verified coverage. It cannot make
    // the pre-start helper's receipt into lock, power or unlock authority.
    const bool fenced = impl_->sleepFence.arm(event, lock, true, cycles, *unit);
    if (!fenced)
        (void)runtimeUnavailable("native-sleep-owner-denied reason=arm\n");
    impl_->refreshPresentation();
    return fenced;
}

void NativeRuntime::recoverNativeSleepEntry()
{
    impl_->correctThread();
    if (!impl_->initialized || !impl_->sleepFence.active() || !impl_->currentSession())
        return;
    NativeDeadline deadline(std::chrono::milliseconds(8'000), NativeDeadline::Stage::SleepRecovery);
    const auto unit = impl_->peers->sleepUnitSnapshot();
    const auto cycles = nativeSuccessfulSuspendCycles();
    if (unit && cycles && impl_->protocol->inspect() == LockMechanism::State::Secure &&
        impl_->independentState() == NativeCompositorLockState::Locked && impl_->currentSession() &&
        nativeSuccessfulSuspendCycles() == cycles) {
        // No caller-supplied completion, replay, timer expiry or unlock opcode.
        const auto before = impl_->sleepFence.baselineCycles();
        if (impl_->sleepFence.retire(identity(), true, cycles, *unit))
            impl_->sleepNotVerified = before == cycles;
    }
    impl_->refreshPresentation();
}

std::optional<QString>
NativeRuntime::observePowerPermission(const QDBusMessage &received,
                                      const NativeTransitionIdentity &transition)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (!peer || transition.lock != identity() || !transition.powerPermissionAction())
        return std::nullopt;
    // Bound even a native library ignoring cancellation. Timeout exits without
    // sending any unlock opcode; never synthesize permission from unavailability.
    NativeDeadline deadline(std::chrono::milliseconds(2'000),
                            NativeDeadline::Stage::PowerPermission);
    const auto result = impl_->authentication->observePowerPermission(transition);
    if (!impl_->currentSession() || transition.lock != identity() ||
        !impl_->peers->stillCurrent(NativePeerPurpose::ControlApproval, *peer))
        return std::nullopt;
    return result;
}

bool NativeRuntime::commitVerifiedRelease(const QDBusMessage &received,
                                          const NativeLockIdentity &lock)
{
    if (!impl_->caller(received, NativePeerPurpose::ControlApproval))
        return false;
    // A lost acknowledgement reply must not rotate twice, cancel a NEW
    // conversation or demand that a later generation be unlocked. Retired
    // generations cannot be dispatched/authenticated/observed as current.
    if (lock.wasRetiredBy(identity()))
        return true;
    if (lock != identity() || impl_->approvalScope ||
        impl_->independentState() != NativeCompositorLockState::Unlocked ||
        impl_->protocol->inspect() != LockMechanism::State::Released)
        return false;
    if (!impl_->protocol->commitVerifiedRelease(lock))
        return false;
    if (!impl_->authentication->advanceIdentity(identity()))
        failClosed(); // Partial rotation is terminal, not reuse.
    return true;
}

void NativeRuntime::cancelApproval(const QDBusMessage &received)
{
    const auto peer = impl_->caller(received, NativePeerPurpose::ControlApproval);
    if (peer && peer == impl_->approvalPeer)
        impl_->clearApproval();
}

bool NativeRuntime::exportNativeEndpoint()
{
    impl_->correctThread();
    if (!impl_->initialized || impl_->endpoint || !impl_->currentSession())
        return runtimeUnavailable("linura-security-owner: endpoint/session\n");
    NativeEndpoint::registerWireTypes();
    auto endpoint = std::make_unique<NativeEndpoint>(*this);
    auto connection = impl_->peers->nativeConnection();
    if (!connection.registerObject(NativeEndpoint::objectPath(), endpoint.get(),
                                   QDBusConnection::ExportAllSlots |
                                       QDBusConnection::ExportAllSignals))
        return runtimeUnavailable("linura-security-owner: endpoint/export\n");
    impl_->endpoint = endpoint.release();
    return true;
}

} // namespace Linura::SecurityOwner
