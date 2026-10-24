#include "native_endpoint.h"
#include "native_runtime.h"

#include <QDBusMetaType>
#include <limits>
#include <time.h>

namespace Linura::SecurityOwner {
namespace {
std::optional<quint64> bootMilliseconds()
{
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1'000'000'000 ||
        static_cast<quint64>(now.tv_sec) > (std::numeric_limits<quint64>::max() - 999U) / 1000U)
        return std::nullopt;
    return static_cast<quint64>(now.tv_sec) * 1000U +
           static_cast<quint64>(now.tv_nsec) / 1'000'000U;
}
} // namespace

bool NativeLockObservationWire::freshAtBootMs(quint64 now) const
{
    return NativeLockIdentity::parse(resource).has_value() && sampledBootMs != 0 &&
           now >= sampledBootMs && now - sampledBootMs < 2'000U;
}

bool NativePowerPermissionWire::freshAtBootMs(quint64 now) const
{
    const auto transition = NativeTransitionIdentity::parse(resource);
    return transition && transition->powerPermissionAction() &&
           (availability == QLatin1String("yes") || availability == QLatin1String("challenge") ||
            availability == QLatin1String("no")) &&
           sampledBootMs != 0 && now >= sampledBootMs && now - sampledBootMs < 2'000U;
}

QDBusArgument &operator<<(QDBusArgument &wire, const NativePowerPermissionWire &observation)
{
    wire.beginStructure();
    wire << observation.resource << observation.availability << observation.sampledBootMs;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, NativePowerPermissionWire &observation)
{
    wire.beginStructure();
    wire >> observation.resource >> observation.availability >> observation.sampledBootMs;
    wire.endStructure();
    return wire;
}

std::optional<NativeApprovalScope> NativeApprovalWire::scope() const
{
    if (purpose > 7)
        return std::nullopt;
    const bool power = purpose >= 2 && purpose <= 5;
    const auto transition = power ? NativeTransitionIdentity::parse(resource) : std::nullopt;
    const auto lock =
        transition ? std::optional(transition->lock) : NativeLockIdentity::parse(resource);
    if (!lock || (power && !transition))
        return std::nullopt;
    NativeApprovalScope candidate{
        *lock,         principal,         request,      plan,
        requestDigest, observationDigest, reviewDigest, static_cast<ApprovalPurpose>(purpose),
        transition};
    if (!candidate.valid())
        return std::nullopt;
    return candidate;
}
QDBusArgument &operator<<(QDBusArgument &wire, const NativeApprovalWire &scope)
{
    wire.beginStructure();
    wire << scope.resource << scope.principal << scope.request << scope.plan << scope.requestDigest
         << scope.observationDigest << scope.reviewDigest << scope.purpose;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, NativeApprovalWire &scope)
{
    wire.beginStructure();
    wire >> scope.resource >> scope.principal >> scope.request >> scope.plan >>
        scope.requestDigest >> scope.observationDigest >> scope.reviewDigest >> scope.purpose;
    wire.endStructure();
    return wire;
}
QDBusArgument &operator<<(QDBusArgument &wire, const NativeLockObservationWire &observation)
{
    wire.beginStructure();
    wire << observation.resource << observation.secure << observation.sampledBootMs;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, NativeLockObservationWire &observation)
{
    wire.beginStructure();
    wire >> observation.resource >> observation.secure >> observation.sampledBootMs;
    wire.endStructure();
    return wire;
}

NativeEndpoint::NativeEndpoint(NativeRuntime &runtime) : QObject(&runtime), runtime_(runtime)
{
    connect(&runtime, &NativeRuntime::approvalInteractionCompleted, this,
            &NativeEndpoint::ApprovalInteractionCompleted);
}
QString NativeEndpoint::objectPath()
{
    return QStringLiteral("/org/linura/SecurityOwner1");
}
void NativeEndpoint::registerWireTypes()
{
    qDBusRegisterMetaType<NativeApprovalWire>();
    qDBusRegisterMetaType<NativeLockObservationWire>();
    qDBusRegisterMetaType<NativePowerPermissionWire>();
}
bool NativeEndpoint::ArmApproval(const NativeApprovalWire &wire)
{
    const auto scope = wire.scope();
    return calledFromDBus() && scope && runtime_.armApproval(message(), *scope);
}
bool NativeEndpoint::ConsumeApproval(const NativeApprovalWire &wire)
{
    const auto scope = wire.scope();
    return calledFromDBus() && scope && runtime_.consumeApproval(message(), *scope);
}
void NativeEndpoint::CancelApproval()
{
    if (calledFromDBus())
        runtime_.cancelApproval(message());
}
NativeLockObservationWire NativeEndpoint::ObserveLock()
{
    if (calledFromDBus()) {
        // Never stamp completion time onto an earlier native fact. Peer/session
        // attestation and the independent compositor probe consume this same
        // conservative freshness window, including suspend and event-loop delay.
        const auto sampled = bootMilliseconds();
        const auto state = runtime_.observe(message());
        const auto completed = bootMilliseconds();
        if (sampled && state && completed) {
            NativeLockObservationWire observation{
                runtime_.identity().resource, *state == NativeObservedLockState::Secure, *sampled};
            if (observation.freshAtBootMs(*completed)) {
                if (*state == NativeObservedLockState::Acquiring ||
                    *state == NativeObservedLockState::Releasing) {
                    sendErrorReply(QStringLiteral("org.linura.Private.NativeTransitionPending"),
                                   QStringLiteral("Native lock transition is pending"));
                    return {}; // Never encode a transitional state as secure=false.
                }
                return observation;
            }
        }
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native lock evidence unavailable"));
    }
    return {}; // Invalid identity/time, never an unlocked observation.
}
bool NativeEndpoint::DispatchPreparedLock(const QString &resource, bool secure)
{
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && lock && runtime_.dispatchPrepared(message(), *lock, secure);
}

NativePowerPermissionWire NativeEndpoint::ObservePowerPermission(const QString &resource)
{
    const auto transition = NativeTransitionIdentity::parse(resource);
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto permission =
            transition ? runtime_.observePowerPermission(message(), *transition) : std::nullopt;
        const auto completed = bootMilliseconds();
        if (sampled && permission && completed) {
            NativePowerPermissionWire observation{resource, *permission, *sampled};
            if (observation.freshAtBootMs(*completed))
                return observation;
        }
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native power permission unavailable"));
    }
    return {}; // Invalid identity/time, never positive permission.
}
bool NativeEndpoint::VerifyReleased(const QString &resource)
{
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && lock && runtime_.verifyReleased(message(), *lock);
}
bool NativeEndpoint::RetainedVerifiedRelease(const QString &resource)
{
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && lock && runtime_.retainedVerifiedRelease(message(), *lock);
}
bool NativeEndpoint::FencePreparedTransition(const QString &resource)
{
    const auto target = NativeTransitionIdentity::parse(resource);
    return calledFromDBus() && target && runtime_.fencePreparedTransition(message(), *target);
}
bool NativeEndpoint::CancelUndispatchedTransition(const QString &resource)
{
    const auto target = NativeTransitionIdentity::parse(resource);
    return calledFromDBus() && target && runtime_.cancelUndispatchedTransition(message(), *target);
}
bool NativeEndpoint::CommitVerifiedTransition(const QString &resource)
{
    const auto target = NativeTransitionIdentity::parse(resource);
    return calledFromDBus() && target && runtime_.commitVerifiedTransition(message(), *target);
}
bool NativeEndpoint::FenceSleepEntry(const QString &event, const QString &resource)
{
    const auto entry = NativeSleepEntryIdentity::parse(event);
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && entry && lock && runtime_.fenceSleepEntry(message(), *entry, *lock);
}
bool NativeEndpoint::CommitVerifiedRelease(const QString &resource)
{
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && lock && runtime_.commitVerifiedRelease(message(), *lock);
}

} // namespace Linura::SecurityOwner
