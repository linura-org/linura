#pragma once

#include "native_scope.h"
#include <QDBusArgument>
#include <QDBusContext>
#include <QObject>
#include <optional>

namespace Linura::SecurityOwner {
class NativeRuntime;

struct NativeApprovalWire final
{
    QString resource, principal, request, plan, requestDigest, observationDigest, reviewDigest;
    quint32 purpose = 0;
    [[nodiscard]] std::optional<NativeApprovalScope> scope() const;
};
QDBusArgument &operator<<(QDBusArgument &wire, const NativeApprovalWire &scope);
const QDBusArgument &operator>>(const QDBusArgument &wire, NativeApprovalWire &scope);

struct NativeLockObservationWire final
{
    QString resource;
    bool secure = false;
    quint64 sampledBootMs = 0;
    // The native sample is conservative (probe start), suspend-inclusive and
    // exclusive at two seconds. Transport clients must preserve this deadline.
    [[nodiscard]] bool freshAtBootMs(quint64 now) const;
};
QDBusArgument &operator<<(QDBusArgument &wire, const NativeLockObservationWire &observation);
const QDBusArgument &operator>>(const QDBusArgument &wire, NativeLockObservationWire &observation);

struct NativePowerPermissionWire final
{
    QString resource, availability;
    quint64 sampledBootMs = 0;
    [[nodiscard]] bool freshAtBootMs(quint64 now) const;
};
QDBusArgument &operator<<(QDBusArgument &wire, const NativePowerPermissionWire &observation);
const QDBusArgument &operator>>(const QDBusArgument &wire, NativePowerPermissionWire &observation);

struct NativeDisplayObservationWire final
{
    QString resource, compositor, seat;
    quint64 sampledBootMs = 0;
    QString topology, monitors;
    bool secure = false;
};
QDBusArgument &operator<<(QDBusArgument &wire, const NativeDisplayObservationWire &observation);
const QDBusArgument &operator>>(const QDBusArgument &wire,
                                NativeDisplayObservationWire &observation);

struct NativePreparedDisplayObservationWire final
{
    NativeDisplayObservationWire sample;
    QString sampleDigest;
};
QDBusArgument &operator<<(QDBusArgument &wire,
                          const NativePreparedDisplayObservationWire &observation);
const QDBusArgument &operator>>(const QDBusArgument &wire,
                                NativePreparedDisplayObservationWire &observation);

struct NativeDisplayAttemptQueryWire final
{
    QString intent, transaction, effectDigest, dispatchDigest;
    quint64 deadlineUnixMs = 0;
};
QDBusArgument &operator<<(QDBusArgument &, const NativeDisplayAttemptQueryWire &);
const QDBusArgument &operator>>(const QDBusArgument &, NativeDisplayAttemptQueryWire &);
struct NativeDisplayAttemptObservationWire final
{
    QString lock, topology, transaction;
    quint64 deadlineUnixMs = 0, sampledBootMs = 0;
    quint32 phase = 7;
    bool secure = false;
};
QDBusArgument &operator<<(QDBusArgument &, const NativeDisplayAttemptObservationWire &);
const QDBusArgument &operator>>(const QDBusArgument &, NativeDisplayAttemptObservationWire &);

// Adapter only, on the owner's authenticated canonical system-bus connection.
// It owns no planner/policy/prepare logic. The runtime checks the actual message
// sender against the independently supervised Control or session executor.
class NativeEndpoint final : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.linura.SecurityOwner1")
    Q_CLASSINFO(
        "D-Bus Introspection",
        ""
        "<interface name=\"org.linura.SecurityOwner1\">"
        "<annotation name=\"org.linura.ContractId\" value=\"dbus.org.linura.SecurityOwner1\"/>"
        "<annotation name=\"org.linura.ContractVersion\" value=\"1\"/>"
        "<annotation name=\"org.linura.Stability\" value=\"experimental\"/>"
        "<method name=\"ArmApproval\"><arg name=\"scope\" type=\"(sssssssu)\" direction=\"in\"/>"
        "<arg name=\"armed\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"ConsumeApproval\"><arg name=\"scope\" type=\"(sssssssu)\" "
        "direction=\"in\"/>"
        "<arg name=\"consumed\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"CancelApproval\"/>"
        "<method name=\"ObserveLock\"><arg name=\"observation\" type=\"(sbt)\" "
        "direction=\"out\"/></method>"
        "<method name=\"ObserveDisplay\"><arg name=\"observation\" type=\"(ssstssb)\" "
        "direction=\"out\"/></method>"
        "<method name=\"ObservePreparedDisplay\"><arg name=\"observation\" type=\"((ssstssb)s)\" "
        "direction=\"out\"/></method>"
        "<method name=\"ObserveDisplayAttempt\"><arg name=\"query\" type=\"(sssst)\" "
        "direction=\"in\"/><arg name=\"observation\" type=\"(sssttub)\" "
        "direction=\"out\"/></method>"
        "<method name=\"DispatchPreparedDisplay\"><arg name=\"query\" type=\"(sssst)\" "
        "direction=\"in\"/><arg name=\"sample_digest\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"sampled_boot_ms\" type=\"t\" direction=\"in\"/>"
        "<arg name=\"native_baseline_guard\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"phase\" type=\"u\" direction=\"out\"/></method>"
        "<method name=\"ContinuePreparedDisplay\"><arg name=\"query\" type=\"(sssst)\" "
        "direction=\"in\"/><arg name=\"decision_digest\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"protected_decision_digest\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"confirm\" type=\"b\" direction=\"in\"/>"
        "<arg name=\"phase\" type=\"u\" direction=\"out\"/></method>"
        "<method name=\"ObservePowerPermission\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"observation\" type=\"(sst)\" direction=\"out\"/></method>"
        "<method name=\"FencePreparedTransition\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"fenced\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"CancelUndispatchedTransition\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"cancelled\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"CommitVerifiedTransition\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"committed\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"FenceSleepEntry\"><arg name=\"event\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"lock\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"fenced\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"DispatchPreparedLock\"><arg name=\"resource\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"secure\" type=\"b\" direction=\"in\"/><arg name=\"dispatched\" type=\"b\" "
        "direction=\"out\"/></method>"
        "<method name=\"VerifyReleased\"><arg name=\"resource\" type=\"s\" direction=\"in\"/>"
        "<arg name=\"verified\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"RetainedVerifiedRelease\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"retained\" type=\"b\" direction=\"out\"/></method>"
        "<method name=\"CommitVerifiedRelease\"><arg name=\"resource\" type=\"s\" "
        "direction=\"in\"/>"
        "<arg name=\"committed\" type=\"b\" direction=\"out\"/></method>"
        "<signal name=\"ApprovalInteractionCompleted\"/>"
        "</interface>")
  public:
    explicit NativeEndpoint(NativeRuntime &runtime);
    [[nodiscard]] static QString objectPath();
    static void registerWireTypes();

  public Q_SLOTS:
    bool ArmApproval(const NativeApprovalWire &scope);
    bool ConsumeApproval(const NativeApprovalWire &scope);
    void CancelApproval();
    NativeLockObservationWire ObserveLock();
    NativeDisplayObservationWire ObserveDisplay();
    NativePreparedDisplayObservationWire ObservePreparedDisplay();
    NativeDisplayAttemptObservationWire
    ObserveDisplayAttempt(const NativeDisplayAttemptQueryWire &);
    quint32 DispatchPreparedDisplay(const NativeDisplayAttemptQueryWire &,
                                    const QString &sample_digest, quint64 sampled_boot_ms,
                                    const QString &native_baseline_guard);
    quint32 ContinuePreparedDisplay(const NativeDisplayAttemptQueryWire &,
                                    const QString &decision_digest,
                                    const QString &protected_decision_digest, bool confirm);
    NativePowerPermissionWire ObservePowerPermission(const QString &resource);
    bool FencePreparedTransition(const QString &resource);
    bool CancelUndispatchedTransition(const QString &resource);
    bool CommitVerifiedTransition(const QString &resource);
    bool FenceSleepEntry(const QString &event, const QString &lock);
    bool DispatchPreparedLock(const QString &resource, bool secure);
    bool VerifyReleased(const QString &resource);
    bool RetainedVerifiedRelease(const QString &resource);
    bool CommitVerifiedRelease(const QString &resource);

  Q_SIGNALS:
    void ApprovalInteractionCompleted();

  private:
    NativeRuntime &runtime_;
};

} // namespace Linura::SecurityOwner

Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeApprovalWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeLockObservationWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativePowerPermissionWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeDisplayObservationWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativePreparedDisplayObservationWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeDisplayAttemptQueryWire)
Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeDisplayAttemptObservationWire)
