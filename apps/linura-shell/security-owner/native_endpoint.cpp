#include "native_endpoint.h"
#include "native_display_restoration.h"
#include "native_display_finalization.h"
#include "native_runtime.h"
#include "native_display_flow.h"

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
std::optional<NativeApprovalScope> NativeApprovalWire::displayScope(const QString &material,
                                                                    const QString &reason,
                                                                    quint64 deadlineUnixMs,
                                                                    quint64 deadlineBootMs) const
{
    const auto maximum = purpose == 12 ? 14 * 1024 : purpose == 11 ? 12 * 1024 : 4096;
    if ((purpose != 8 && purpose != 11 && purpose != 12) || material.size() > maximum ||
        reason.size() > 2048 || principal.size() > 64 || request.size() > 128 || plan.size() > 128)
        return std::nullopt;
    const auto lock = NativeLockIdentity::parse(resource);
    if (!lock)
        return std::nullopt;
    NativeApprovalScope candidate{
        *lock,
        principal,
        request,
        plan,
        requestDigest,
        observationDigest,
        reviewDigest,
        static_cast<ApprovalPurpose>(purpose),
        std::nullopt,
        NativeDisplayApprovalBinding{material, {}, deadlineUnixMs, reason, deadlineBootMs}};
    return candidate.valid() ? std::optional(candidate) : std::nullopt;
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
QDBusArgument &operator<<(QDBusArgument &wire, const NativeDisplayObservationWire &observation)
{
    wire.beginStructure();
    wire << observation.resource << observation.compositor << observation.seat
         << observation.sampledBootMs << observation.topology << observation.monitors
         << observation.secure;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire,
                                NativeDisplayObservationWire &observation)
{
    wire.beginStructure();
    wire >> observation.resource >> observation.compositor >> observation.seat >>
        observation.sampledBootMs >> observation.topology >> observation.monitors >>
        observation.secure;
    wire.endStructure();
    return wire;
}

QDBusArgument &operator<<(QDBusArgument &wire,
                          const NativePreparedDisplayObservationWire &observation)
{
    wire.beginStructure();
    wire << observation.sample << observation.sampleDigest << observation.recoveryPreimage;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire,
                                NativePreparedDisplayObservationWire &observation)
{
    wire.beginStructure();
    wire >> observation.sample >> observation.sampleDigest >> observation.recoveryPreimage;
    wire.endStructure();
    return wire;
}

NativeEndpoint::NativeEndpoint(NativeRuntime &runtime) : QObject(&runtime), runtime_(runtime)
{
    connect(&runtime, &NativeRuntime::approvalInteractionCompleted, this,
            &NativeEndpoint::ApprovalInteractionCompleted);
}
QDBusArgument &operator<<(QDBusArgument &wire, const NativeDisplayAttemptQueryWire &query)
{
    wire.beginStructure();
    wire << query.intent << query.transaction << query.effectDigest << query.dispatchDigest
         << query.deadlineUnixMs;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, NativeDisplayAttemptQueryWire &query)
{
    wire.beginStructure();
    wire >> query.intent >> query.transaction >> query.effectDigest >> query.dispatchDigest >>
        query.deadlineUnixMs;
    wire.endStructure();
    return wire;
}
QDBusArgument &operator<<(QDBusArgument &wire, const NativeDisplayAttemptObservationWire &sample)
{
    wire.beginStructure();
    wire << sample.lock << sample.topology << sample.transaction << sample.deadlineUnixMs
         << sample.sampledBootMs << sample.phase << sample.secure;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire,
                                NativeDisplayAttemptObservationWire &sample)
{
    wire.beginStructure();
    wire >> sample.lock >> sample.topology >> sample.transaction >> sample.deadlineUnixMs >>
        sample.sampledBootMs >> sample.phase >> sample.secure;
    wire.endStructure();
    return wire;
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
    qDBusRegisterMetaType<NativeDisplayObservationWire>();
    qDBusRegisterMetaType<NativePreparedDisplayObservationWire>();
    qDBusRegisterMetaType<NativeDisplayAttemptQueryWire>();
    qDBusRegisterMetaType<NativeDisplayAttemptObservationWire>();
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
bool NativeEndpoint::RetireDisplayForSecurity(const QString &resource)
{
    const auto lock = NativeLockIdentity::parse(resource);
    return calledFromDBus() && lock && runtime_.retireDisplayForSecurity(message(), *lock);
}
bool NativeEndpoint::ArmDisplayApproval(const NativeApprovalWire &wire, const QString &material,
                                        const QString &reason, quint64 deadline,
                                        quint64 deadlineBootMs)
{
    const auto scope = wire.displayScope(material, reason, deadline, deadlineBootMs);
    return calledFromDBus() && scope && runtime_.armDisplayApproval(message(), *scope);
}
bool NativeEndpoint::DisplayApprovalReady(const NativeApprovalWire &wire, const QString &material,
                                          const QString &reason, quint64 deadline,
                                          quint64 deadlineBootMs)
{
    const auto scope = wire.displayScope(material, reason, deadline, deadlineBootMs);
    const auto ready =
        calledFromDBus() && scope ? runtime_.displayApprovalReady(message(), *scope) : std::nullopt;
    if (!ready) {
        if (calledFromDBus())
            sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                           QStringLiteral("Native display interaction unavailable"));
        return false;
    }
    return *ready;
}
bool NativeEndpoint::ConsumeDisplayApproval(const NativeApprovalWire &wire, const QString &material,
                                            const QString &reason, quint64 deadline,
                                            quint64 deadlineBootMs)
{
    const auto scope = wire.displayScope(material, reason, deadline, deadlineBootMs);
    return calledFromDBus() && scope && runtime_.consumeDisplayApproval(message(), *scope);
}
bool NativeEndpoint::CancelDisplayApproval(const NativeApprovalWire &wire, const QString &material,
                                           const QString &reason, quint64 deadlineUnixMs,
                                           quint64 deadlineBootMs)
{
    const auto scope = wire.displayScope(material, reason, deadlineUnixMs, deadlineBootMs);
    return calledFromDBus() && scope && runtime_.cancelDisplayApproval(message(), *scope);
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
NativeDisplayObservationWire NativeEndpoint::ObserveDisplay()
{
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto state = runtime_.observeDisplay(message());
        const auto completed = bootMilliseconds();
        if (sampled && completed && state &&
            NativeLockObservationWire{state->resource, state->secure, *sampled}.freshAtBootMs(
                *completed))
            return {state->resource, state->compositor, state->seat,  *sampled,
                    state->topology, state->monitors,   state->secure};
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native display evidence unavailable"));
    }
    return {};
}
NativePreparedDisplayObservationWire NativeEndpoint::ObservePreparedDisplay()
{
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto state = runtime_.observePreparedDisplay(message());
        const auto completed = bootMilliseconds();
        if (sampled && completed && state && !state->recoveryPreimage.isEmpty() &&
            state->topology.toUtf8().size() + state->monitors.toUtf8().size() +
                    state->recoveryPreimage.toUtf8().size() <=
                383 * 1024 &&
            NativeLockObservationWire{state->resource, state->secure, *sampled}.freshAtBootMs(
                *completed))
            return {{state->resource, state->compositor, state->seat, *sampled, state->topology,
                     state->monitors, state->secure},
                    state->correlationDigest(),
                    state->recoveryPreimage};
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native prepared display evidence unavailable"));
    }
    return {};
}

QString NativeEndpoint::ObserveOriginalDisplayPresentation()
{
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto result = runtime_.observeOriginalDisplayPresentation(message());
        const auto completed = bootMilliseconds();
        if (sampled && completed && result &&
            NativeLockObservationWire{runtime_.identity().resource, false, *sampled}.freshAtBootMs(
                *completed))
            return *result;
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native restoration presentation evidence unavailable"));
    }
    return {};
}

QString NativeEndpoint::ObserveNativeDisplayHandoff()
{
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto result = runtime_.observeNativeDisplayHandoff(message());
        const auto completed = bootMilliseconds();
        if (sampled && completed && result &&
            NativeLockObservationWire{runtime_.identity().resource, false, *sampled}.freshAtBootMs(
                *completed))
            return *result;
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native first ordinary-frame evidence unavailable"));
    }
    return {};
}

QString NativeEndpoint::ObserveNativeDisplayCurrent()
{
    if (calledFromDBus()) {
        const auto sampled = bootMilliseconds();
        const auto result = runtime_.observeNativeDisplayCurrent(message());
        const auto completed = bootMilliseconds();
        if (sampled && completed && result &&
            NativeLockObservationWire{runtime_.identity().resource, false, *sampled}.freshAtBootMs(
                *completed))
            return *result;
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native current display evidence unavailable"));
    }
    return {};
}

NativeDisplayAttemptObservationWire
NativeEndpoint::ObserveDisplayAttempt(const NativeDisplayAttemptQueryWire &query)
{
    if (calledFromDBus() && query.intent.size() <= 4096 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64) {
        const auto intent = NativeDisplayIntent::parse(query.intent);
        const NativeDisplayCorrelation correlation{query.transaction, query.effectDigest,
                                                   query.dispatchDigest, query.deadlineUnixMs};
        const auto sampled = bootMilliseconds();
        const auto result = intent && correlation.valid()
                                ? runtime_.observeDisplayAttempt(message(), *intent, correlation)
                                : std::nullopt;
        const auto completed = bootMilliseconds();
        if (sampled && completed && result &&
            NativeLockObservationWire{result->lock, result->secure, *sampled}.freshAtBootMs(
                *completed))
            return {result->lock, result->topology, result->transaction, result->deadlineUnixMs,
                    *sampled,     result->phase,    result->secure};
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native display attempt evidence unavailable"));
    return {};
}

quint32 NativeEndpoint::DispatchPreparedDisplay(const NativeDisplayAttemptQueryWire &query,
                                                const QString &sampleDigest, quint64 sampledBootMs,
                                                const QString &nativeBaselineGuard)
{
    if (calledFromDBus() && query.intent.size() <= 4096 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        sampleDigest.size() == 64 && nativeBaselineGuard.size() == 64) {
        const auto intent = NativeDisplayIntent::parse(query.intent);
        const NativeDisplayCorrelation correlation{query.transaction, query.effectDigest,
                                                   query.dispatchDigest, query.deadlineUnixMs};
        const auto result =
            intent ? runtime_.dispatchPreparedDisplay(message(), *intent, correlation, sampleDigest,
                                                      sampledBootMs, nativeBaselineGuard)
                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native prepared display dispatch unavailable"));
    return 7; // Unknown, never a no-dispatch acknowledgement.
}

quint32 NativeEndpoint::DispatchPreparedSuccessorDisplay(const NativeDisplayAttemptQueryWire &query,
                                                const QString &sampleDigest, quint64 sampledBootMs,
                                                const QString &nativeBaselineGuard, const QByteArray &preparation)
{
    if (calledFromDBus() && !preparation.isEmpty() && preparation.size() <= 64 * 1024 && query.intent.size() <= 4096 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        sampleDigest.size() == 64 && nativeBaselineGuard.size() == 64) {
        const auto intent = NativeDisplayIntent::parse(query.intent);
        const NativeDisplayCorrelation correlation{query.transaction, query.effectDigest,
                                                   query.dispatchDigest, query.deadlineUnixMs};
        const auto result =
            intent ? runtime_.dispatchPreparedSuccessorDisplay(message(), *intent, correlation, sampleDigest,
                                                      sampledBootMs, nativeBaselineGuard, preparation)
                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native prepared display dispatch unavailable"));
    return 7; // Unknown, never a no-dispatch acknowledgement.
}

quint32 NativeEndpoint::RestoreOriginalDisplay(const NativeDisplayAttemptQueryWire &query,
                                               const QString &sampleDigest, quint64 sampledBootMs,
                                               const QDBusUnixFileDescriptor &originalGrant)
{
    if (calledFromDBus() && query.intent.size() <= 12 * 1024 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        sampleDigest.size() == 64 && originalGrant.isValid()) {
        const auto intent = NativeDisplayRestorationIntent::parse(query.intent);
        const NativeDisplayCorrelation correlation{query.transaction, query.effectDigest,
                                                   query.dispatchDigest, query.deadlineUnixMs};
        const auto result =
            intent ? runtime_.restoreOriginalDisplay(message(), *intent, correlation, sampleDigest,
                                                     sampledBootMs, originalGrant.fileDescriptor())
                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native original display restoration unavailable"));
    return 7; // Ambiguity never creates another grant or dispatch right.
}

quint32 NativeEndpoint::QuiesceOriginalDisplayFinalization(
    const NativeDisplayAttemptQueryWire &query, const QString &sampleDigest, quint64 sampledBootMs,
    const QDBusUnixFileDescriptor &terminalGrant)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        sampleDigest.size() == 64 && terminalGrant.isValid()) {
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const NativeDisplayCorrelation correlation{query.transaction, query.effectDigest,
                                                   query.dispatchDigest, query.deadlineUnixMs};
        const auto result = intent ? runtime_.quiesceOriginalDisplayFinalization(
                                         message(), *intent, correlation, sampleDigest,
                                         sampledBootMs, terminalGrant.fileDescriptor())
                                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native original display terminal quiescence unavailable"));
    return 7; // Neither rejection nor lost acknowledgement permits another attempt.
}

quint32 NativeEndpoint::SpendOriginalDisplayNativeRelease(
    const NativeDisplayAttemptQueryWire &query, const QString &sampleDigest, quint64 sampledBootMs,
    quint64 controlVersion, const QString &controlBinding, const QString &controlObservation,
    const QDBusUnixFileDescriptor &nativeGrant)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        sampleDigest.size() == 64 && controlVersion != 0 && controlBinding.size() == 64 &&
        controlObservation.size() == 64 && nativeGrant.isValid()) {
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const NativeDisplayCorrelation bound{query.transaction, query.effectDigest,
                                             query.dispatchDigest, query.deadlineUnixMs};
        const auto result =
            intent ? runtime_.spendOriginalDisplayNativeRelease(
                         message(), *intent, bound, sampleDigest, sampledBootMs, controlVersion,
                         controlBinding, controlObservation, nativeGrant.fileDescriptor())
                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Original native Root release-spend unavailable"));
    return 7; // No retry or physical release on missing Root ACK.
}

quint32 NativeEndpoint::RetireOriginalDisplayCurrent(const NativeDisplayAttemptQueryWire &query,
                                                     const QString &digest,
                                                     const QByteArray &preparation)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        digest.size() == 64 && !preparation.isEmpty() && preparation.size() <= 57 * 1024) {
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const NativeDisplayCorrelation bound{query.transaction, query.effectDigest,
                                             query.dispatchDigest, query.deadlineUnixMs};
        const auto result = intent ? runtime_.retireOriginalDisplayCurrent(
                                         message(), *intent, bound, digest, preparation)
                                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Original final display retirement unavailable"));
    return 7;
}

quint32 NativeEndpoint::CommitOriginalDisplayCurrent(const NativeDisplayAttemptQueryWire &query,
                                                     const QString &digest,
                                                     const QByteArray &preparation)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        digest.size() == 64 && !preparation.isEmpty() && preparation.size() <= 49 * 1024) {
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const NativeDisplayCorrelation bound{query.transaction, query.effectDigest,
                                             query.dispatchDigest, query.deadlineUnixMs};
        const auto result = intent ? runtime_.commitOriginalDisplayCurrent(
                                         message(), *intent, bound, digest, preparation)
                                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Original committed-current handoff unavailable"));
    return 7;
}

quint32 NativeEndpoint::RetireOriginalDisplayPower(const NativeDisplayAttemptQueryWire &query,
                                                   const QString &digest,
                                                   const QByteArray &preparation)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        digest.size() == 64 && !preparation.isEmpty() && preparation.size() <= 33 * 1024) {
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const NativeDisplayCorrelation bound{query.transaction, query.effectDigest,
                                             query.dispatchDigest, query.deadlineUnixMs};
        const auto result = intent ? runtime_.retireOriginalDisplayPower(message(), *intent, bound,
                                                                         digest, preparation)
                                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Original display power retirement unavailable"));
    return 7;
}

quint32
NativeEndpoint::TransferOriginalDisplayCompletion(const NativeDisplayAttemptQueryWire &query,
                                                  const QString &digest,
                                                  const QDBusUnixFileDescriptor &grant)
{
    if (calledFromDBus() && query.intent.size() <= 14 * 1024 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        digest.size() == 64 && grant.isValid()) {
        const NativeDisplayCorrelation bound{query.transaction, query.effectDigest,
                                             query.dispatchDigest, query.deadlineUnixMs};
        const auto intent = NativeDisplayFinalizationIntent::parse(query.intent);
        const auto result = intent ? runtime_.transferOriginalDisplayCompletion(
                                         message(), *intent, bound, digest, grant.fileDescriptor())
                                   : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Original display completion transfer unavailable"));
    return 7;
}

quint32 NativeEndpoint::ContinuePreparedDisplay(const NativeDisplayAttemptQueryWire &query,
                                                const QString &decisionDigest,
                                                const QString &protectedDecisionDigest,
                                                bool confirm)
{
    if (calledFromDBus() && query.intent.size() <= 4096 && query.transaction.size() <= 256 &&
        query.effectDigest.size() == 64 && query.dispatchDigest.size() == 64 &&
        decisionDigest.size() == 64 && protectedDecisionDigest.size() == 64) {
        const auto intent = NativeDisplayIntent::parse(query.intent);
        const NativeDisplayDecision decision{
            {query.transaction, query.effectDigest, query.dispatchDigest, query.deadlineUnixMs},
            decisionDigest,
            protectedDecisionDigest,
            confirm};
        const auto result = intent && decision.valid()
                                ? runtime_.continuePreparedDisplay(message(), *intent, decision)
                                : std::nullopt;
        if (result)
            return *result;
    }
    if (calledFromDBus())
        sendErrorReply(QStringLiteral("org.linura.Private.NativeUnavailable"),
                       QStringLiteral("Native prepared display decision unavailable"));
    return 7; // No success, independent verification or retry authority.
}

bool NativeEndpoint::ArmDisplayDecision(const QString &principal, const QString &request,
                                        const NativeDisplayAttemptQueryWire &query,
                                        const QString &decisionDigest, bool confirm)
{
    if (!calledFromDBus() || principal.size() > 256 || request.size() > 256 ||
        query.intent.size() > 4096 || query.transaction.size() > 256 ||
        query.effectDigest.size() != 64 || query.dispatchDigest.size() != 64 ||
        decisionDigest.size() != 64)
        return false;
    const NativeDisplayChoiceChallenge challenge{
        {query.transaction, query.effectDigest, query.dispatchDigest, query.deadlineUnixMs},
        principal,
        request,
        query.intent,
        decisionDigest,
        confirm};
    return challenge.correlation.valid() && runtime_.armDisplayDecision(message(), challenge);
}
bool NativeEndpoint::DisplayDecisionReady(const QString &principal, const QString &request,
                                          const NativeDisplayAttemptQueryWire &query,
                                          const QString &decisionDigest, bool confirm)
{
    if (!calledFromDBus() || principal.size() > 256 || request.size() > 256 ||
        query.intent.size() > 4096 || query.transaction.size() > 256 ||
        query.effectDigest.size() != 64 || query.dispatchDigest.size() != 64 ||
        decisionDigest.size() != 64)
        return false;
    const NativeDisplayChoiceChallenge challenge{
        {query.transaction, query.effectDigest, query.dispatchDigest, query.deadlineUnixMs},
        principal,
        request,
        query.intent,
        decisionDigest,
        confirm};
    return challenge.correlation.valid() &&
           runtime_.displayDecisionReady(message(), challenge).value_or(false);
}
bool NativeEndpoint::ConsumeDisplayDecision(const QString &principal, const QString &request,
                                            const NativeDisplayAttemptQueryWire &query,
                                            const QString &decisionDigest, bool confirm)
{
    if (!calledFromDBus() || principal.size() > 256 || request.size() > 256 ||
        query.intent.size() > 4096 || query.transaction.size() > 256 ||
        query.effectDigest.size() != 64 || query.dispatchDigest.size() != 64 ||
        decisionDigest.size() != 64)
        return false;
    const NativeDisplayChoiceChallenge challenge{
        {query.transaction, query.effectDigest, query.dispatchDigest, query.deadlineUnixMs},
        principal,
        request,
        query.intent,
        decisionDigest,
        confirm};
    return challenge.correlation.valid() && runtime_.consumeDisplayDecision(message(), challenge);
}
bool NativeEndpoint::CancelDisplayDecision(const QString &principal, const QString &request,
                                           const NativeDisplayAttemptQueryWire &query,
                                           const QString &decisionDigest, bool confirm)
{
    if (!calledFromDBus() || principal.size() > 256 || request.size() > 256 ||
        query.intent.size() > 4096 || query.transaction.size() > 256 ||
        query.effectDigest.size() != 64 || query.dispatchDigest.size() != 64 ||
        decisionDigest.size() != 64)
        return false;
    const NativeDisplayChoiceChallenge challenge{
        {query.transaction, query.effectDigest, query.dispatchDigest, query.deadlineUnixMs},
        principal,
        request,
        query.intent,
        decisionDigest,
        confirm};
    return challenge.correlation.valid() && runtime_.cancelDisplayDecision(message(), challenge);
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
