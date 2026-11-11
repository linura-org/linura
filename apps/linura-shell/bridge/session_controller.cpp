#include "session_controller.h"
#include "session_receipt.h"

#include <QDBusArgument>
#include <QDBusPendingCallWatcher>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTimer>
#include <QUuid>
#include <algorithm>
#include <unistd.h>

namespace {
constexpr auto service = "org.linura.Authority1";
constexpr auto endpoint = "/org/linura/Authority1";
constexpr auto interface = "org.linura.Authority1";

QString sessionTrackingPath()
{
    const QString directory = qEnvironmentVariable("STATE_DIRECTORY");
    if (directory.isEmpty() || directory.contains(QLatin1Char(':')) ||
        !QDir::isAbsolutePath(directory) || QDir::cleanPath(directory) != directory)
        return {};
    const QFileInfo state(directory);
    if (!state.isDir() || state.isSymLink() || state.canonicalFilePath() != directory ||
        state.ownerId() != uint(geteuid()))
        return {};
    const auto permissions = state.permissions();
    auto required = QFileDevice::ReadOwner | QFileDevice::WriteOwner;
    required |= QFileDevice::ExeOwner;
    auto forbidden = QFileDevice::ReadGroup | QFileDevice::WriteGroup;
    forbidden |= QFileDevice::ExeGroup;
    forbidden |= QFileDevice::ReadOther;
    forbidden |= QFileDevice::WriteOther;
    forbidden |= QFileDevice::ExeOther;
    if ((permissions & required) != required || (permissions & forbidden))
        return {};
    return directory + QStringLiteral("/session-request.json");
}

bool slug(const QString &value)
{
    static const QRegularExpression expression(QStringLiteral("^[a-z0-9]+(?:-[a-z0-9]+)*$"));
    return value.size() <= 64 && expression.match(value).hasMatch();
}

bool bounded(const QString &value, qsizetype maximum)
{
    return !value.isEmpty() && value.size() <= maximum &&
           std::none_of(value.cbegin(), value.cend(),
                        [](QChar c) { return c.isSpace() || c.isNull(); });
}

QString replyString(const QDBusMessage &message)
{
    if (message.type() != QDBusMessage::ReplyMessage ||
        message.signature() != QStringLiteral("s") || message.arguments().size() != 1)
        return {};
    const auto result = message.arguments().front().toString();
    return bounded(result, 512) ? result : QString{};
}
} // namespace

SessionController::SessionController(QObject *parent)
    : QObject(parent),
      bus_(QDBusConnection::connectToBus(QStringLiteral("unix:path=/run/dbus/system_bus_socket"),
                                         QStringLiteral("linura-shell-session-client"))),
      trackingPath_(sessionTrackingPath()),
      status_(tr("Session controls require Linura Control. Authentication appears only in the "
                 "secure locker."))
{
    loadTracking();
    nativeSleepStatus_ = tr("Sleep protection is not verified. Checking read-only diagnostics…");
    nativeIdleStatus_ = tr("Native logind idle hint unavailable. No activity is inferred.");
    idlePreferenceStatus_ = tr("Idle advisory preference is unavailable.");
    auto *timer = new QTimer(this);
    timer->setInterval(5000);
    // The native diagnostics and the own-user preference share Authority1's
    // fail-fast handler. Sequence our own reads; never add a server-side queue.
    connect(timer, &QTimer::timeout, this, &SessionController::refreshNativeSleepStatus);
    timer->start();
    QTimer::singleShot(0, this, &SessionController::refreshNativeSleepStatus);
}

void SessionController::refreshNativeSleepStatus()
{
    if (nativeSleepQueryPending_ || nativeIdleQueryPending_ || idlePreferenceQueryPending_ ||
        idlePreferenceBusy_)
        return;
    nativeSleepQueryPending_ = true;
    call(
        QStringLiteral("GetOwnNativeSleepGateStatus"), {},
        [this](const QDBusMessage &reply) {
            nativeSleepQueryPending_ = false;
            QString text = tr("Sleep diagnostics are unavailable. Do not assume this computer is "
                              "asleep or protected. Keep a closed laptop ventilated.");
            if (reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("(ss)") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>()) {
                const auto wire = reply.arguments().front().value<QDBusArgument>();
                QString epoch, state;
                wire.beginStructure();
                wire >> epoch >> state;
                const bool end = wire.atEnd();
                wire.endStructure();
                if (end && Linura::ShellClient::validNativeSleepGateStatus(epoch, state)) {
                    if (state == QStringLiteral("denied"))
                        text = tr("Sleep protection failed at the last observed native entry. This "
                                  "computer may still be running. Keep a closed laptop ventilated; "
                                  "resolve the problem before relying on lid-close sleep.");
                    else if (state == QStringLiteral("checking"))
                        text = tr("The observed native sleep entry is checking session coverage. "
                                  "Sleep and current protection are not verified.");
                    else if (state == QStringLiteral("coverage-fenced"))
                        text = tr("Coverage was fenced at the last observed native entry. This is "
                                  "not proof of successful sleep or current protection.");
                    else
                        text = tr("No native sleep entry has been observed by this Control "
                                  "process. Sleep protection is not verified.");
                }
            }
            if (nativeSleepStatus_ != text) {
                nativeSleepStatus_ = text;
                emit nativeSleepStatusChanged();
            }
            // The native handler uses try_lock(): begin the next advisory
            // read only after the sleep reply completed. Never auto-dispatch.
            refreshNativeIdleStatus();
        },
        2000);
}

void SessionController::refreshIdleAdvisoryPreference()
{
    if (idlePreferenceBusy_ || idlePreferenceQueryPending_)
        return;
    if (nativeSleepQueryPending_ || nativeIdleQueryPending_) {
        // Coalesce explicit refreshes behind the already-running read-only
        // diagnostic chain. No managed action or preference write is queued.
        idlePreferenceRefreshRequested_ = true;
        return;
    }
    idlePreferenceRefreshRequested_ = false;
    idlePreferenceQueryPending_ = true;
    call(
        QStringLiteral("GetOwnIdleAdvisoryPreference"), {},
        [this](const QDBusMessage &reply) {
            idlePreferenceQueryPending_ = false;
            bool valid = false;
            quint32 seconds = 0;
            quint64 revision = 0;
            if (reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("(ut)") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>()) {
                const auto wire = reply.arguments().front().value<QDBusArgument>();
                wire.beginStructure();
                wire >> seconds >> revision;
                valid = wire.atEnd();
                wire.endStructure();
                valid = valid && seconds >= 60 && seconds <= 3600 && seconds % 60 == 0;
            }
            idlePreferenceReady_ = valid;
            idleAdvisorySeconds_ = valid ? int(seconds) : 0;
            idlePreferenceRevision_ = valid ? revision : 0;
            if (valid) {
                const auto label = tr("Idle notification threshold: %1 minutes. Advisory only.");
                idlePreferenceStatus_ = label.arg(seconds / 60);
            } else {
                idlePreferenceStatus_ = tr("Idle advisory preference unavailable. No inactivity "
                                           "state is assumed.");
            }
            emit idlePreferenceChanged();
        },
        2000);
}

void SessionController::setIdleAdvisorySeconds(int seconds)
{
    if (idlePreferenceBusy_ || idlePreferenceQueryPending_ || !idlePreferenceReady_ ||
        seconds < 60 || seconds > 3600 || seconds % 60 != 0)
        return;
    if (seconds == idleAdvisorySeconds_)
        return;
    if (nativeSleepQueryPending_ || nativeIdleQueryPending_) {
        idlePreferenceStatus_ = tr("Diagnostics in progress; no advisory setting saved. Retry.");
        emit idlePreferenceChanged();
        return;
    }
    idlePreferenceBusy_ = true;
    idlePreferenceStatus_ = tr("Saving advisory preference; no lock or power request.");
    emit idlePreferenceChanged();
    const quint64 expectedRevision = idlePreferenceRevision_;
    call(
        QStringLiteral("SetOwnIdleAdvisoryPreference"), {quint32(seconds), expectedRevision},
        [this, seconds, expectedRevision](const QDBusMessage &reply) {
            idlePreferenceBusy_ = false;
            // Never claim a new setting was committed solely from a response.
            // A revision conflict or lost reply requires an explicit fresh read;
            // no configuration write is retried automatically.
            bool valid = false;
            quint32 observedSeconds = 0;
            quint64 observedRevision = 0;
            if (reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("(ut)") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>()) {
                const auto wire = reply.arguments().front().value<QDBusArgument>();
                wire.beginStructure();
                wire >> observedSeconds >> observedRevision;
                valid = wire.atEnd();
                wire.endStructure();
                valid = valid && observedSeconds == quint32(seconds) &&
                        observedRevision == expectedRevision + 1;
            }
            idlePreferenceReady_ = false;
            idleAdvisorySeconds_ = 0;
            idlePreferenceStatus_ = valid
                                        ? tr("Advisory preference acknowledged; refresh to verify.")
                                        : tr("Preference result uncertain or rejected. Refresh "
                                             "before attempting another change.");
            emit idlePreferenceChanged();
            // An authoritative post-write read only. Never replay the write.
            if (valid)
                refreshIdleAdvisoryPreference();
        },
        5000);
}

void SessionController::refreshNativeIdleStatus()
{
    if (nativeIdleQueryPending_ || nativeSleepQueryPending_ || idlePreferenceQueryPending_ ||
        idlePreferenceBusy_)
        return;
    nativeIdleQueryPending_ = true;
    call(
        QStringLiteral("GetOwnNativeIdleStatus"), {},
        [this](const QDBusMessage &reply) {
            nativeIdleQueryPending_ = false;
            QString text = tr("Native logind idle hint unavailable. No activity is inferred.");
            if (reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("(ssbt)") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>()) {
                const auto wire = reply.arguments().front().value<QDBusArgument>();
                QString epoch, seat;
                bool idle = false;
                quint64 since = 0;
                wire.beginStructure();
                wire >> epoch >> seat >> idle >> since;
                const bool end = wire.atEnd();
                wire.endStructure();
                if (end && Linura::ShellClient::validNativeIdleStatus(epoch, seat, idle, since)) {
                    if (idle) {
                        text = tr("Logind reported an idle hint for this login at the last check. "
                                  "This is not proof of secure lock or permission to suspend.");
                    } else {
                        text = tr("Logind did not report an idle hint at the last check. "
                                  "This does not prove user activity or power protection.");
                    }
                }
            }
            if (nativeIdleStatus_ != text) {
                nativeIdleStatus_ = text;
                emit nativeIdleStatusChanged();
            }
            // Deliver at most one pending own-user preference read, including
            // the initial startup read. Never replay a write or queue behind
            // any managed operation.
            if (idlePreferenceRefreshRequested_)
                refreshIdleAdvisoryPreference();
        },
        2000);
}

QString SessionController::requestId() const
{
    if (operation_.isEmpty())
        return {};
    return (kind_ == ProtectiveSettingRequest
                ? QStringLiteral("request:v010:protective-lock-setting:")
            : kind_ == TransitionRequest ? QStringLiteral("request:v010:session-transition:")
                                         : QStringLiteral("request:v010:session-lock:")) +
           operation_;
}

QString SessionController::actionName(Action action)
{
    switch (action) {
    case Suspend:
        return QStringLiteral("suspend");
    case Logout:
        return QStringLiteral("logout");
    case Reboot:
        return QStringLiteral("reboot");
    case PowerOff:
        return QStringLiteral("power-off");
    case Lock:
    case EnableProtectiveLock:
    case RevokeProtectiveLock:
        return {};
    }
    return {};
}

void SessionController::loadTracking()
{
    if (trackingPath_.isEmpty())
        return;
    QFile file(trackingPath_);
    if (!QFileInfo::exists(trackingPath_))
        return;
    invalidRecord_ = true;
    status_ = tr("Unresolved local request tracking. Recovery never replays an effect.");
    if (QFileInfo(trackingPath_).isSymLink() || !file.open(QIODevice::ReadOnly) ||
        file.size() > 1024)
        return;
    const auto document = QJsonDocument::fromJson(file.read(1025));
    if (!document.isObject())
        return;
    const auto record = document.object();
    if (record.value("version") != QJsonValue(2) || !record.value("kind").isString() ||
        !record.value("operation").isString() || !slug(record.value("operation").toString()))
        return;
    const auto kind = record.value("kind").toString();
    if (kind == QStringLiteral("protective-setting")) {
        if (record.size() != 5 || !record.value("resource").isString() ||
            !record.value("enabled").isBool() ||
            !Linura::ShellClient::validSessionLockResource(record.value("resource").toString()))
            return;
        kind_ = ProtectiveSettingRequest;
        protectiveResource_ = record.value("resource").toString();
        protectiveEnabled_ = record.value("enabled").toBool();
    } else {
        if (record.size() != 3 ||
            (kind != QStringLiteral("lock") && kind != QStringLiteral("transition")))
            return;
        kind_ = kind == QStringLiteral("transition") ? TransitionRequest : LockRequest;
    }
    operation_ = record.value("operation").toString();
    invalidRecord_ = false;
    // Do not restart any workflow, prompt, lock or power effect on reload.
}

bool SessionController::retain(const QString &operation, RequestKind kind, const QString &resource,
                               bool enabled)
{
    if (!slug(operation) || trackingPath_.isEmpty() ||
        (kind == ProtectiveSettingRequest &&
         !Linura::ShellClient::validSessionLockResource(resource)))
        return false;
    const QFileInfo stateDirectory(QFileInfo(trackingPath_).absolutePath());
    if (!stateDirectory.isDir() || stateDirectory.isSymLink() ||
        QFileInfo(trackingPath_).isSymLink())
        return false;
    QSaveFile file(trackingPath_);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) ||
        !file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner))
        return false;
    QJsonObject record{{"version", 2},
                       {"operation", operation},
                       {"kind", kind == ProtectiveSettingRequest ? "protective-setting"
                                : kind == TransitionRequest      ? "transition"
                                                                 : "lock"}};
    if (kind == ProtectiveSettingRequest) {
        record.insert("resource", resource);
        record.insert("enabled", enabled);
    }
    const auto bytes = QJsonDocument(record).toJson(QJsonDocument::Compact);
    if (file.write(bytes) != bytes.size() || !file.commit())
        return false;
    operation_ = operation;
    kind_ = kind;
    protectiveResource_ = kind == ProtectiveSettingRequest ? resource : QString{};
    protectiveEnabled_ = kind == ProtectiveSettingRequest && enabled;
    invalidRecord_ = false;
    emit changed();
    return true;
}

void SessionController::call(const QString &method, const QVariantList &arguments,
                             std::function<void(const QDBusMessage &)> finished, int timeoutMs)
{
    auto message =
        QDBusMessage::createMethodCall(QString::fromLatin1(service), QString::fromLatin1(endpoint),
                                       QString::fromLatin1(interface), method);
    message.setArguments(arguments);
    auto *watcher = new QDBusPendingCallWatcher(bus_.asyncCall(message, timeoutMs), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [watcher, finished = std::move(finished)] {
                const auto reply = watcher->reply();
                watcher->deleteLater();
                finished(reply);
            });
}

void SessionController::finish(const QString &message, bool clear)
{
    busy_ = false;
    status_ = message;
    if (clear && !trackingPath_.isEmpty()) {
        if (QFile::remove(trackingPath_) || !QFileInfo::exists(trackingPath_)) {
            operation_.clear();
            protectiveResource_.clear();
            protectiveEnabled_ = false;
            kind_ = LockRequest;
            invalidRecord_ = false;
        } else {
            status_ += tr(" Local tracking could not be cleared; use observe-only recovery.");
        }
    }
    emit changed();
}

void SessionController::consumeReceipt(const QDBusMessage &message, const QString &expectedResource,
                                       std::function<void()> success)
{
    // This is presentation validation of the public typed completion report,
    // never execution authority or authoritative current machine state.
    if (message.type() != QDBusMessage::ReplyMessage ||
        message.signature() != QStringLiteral("(sssssssssbas)") ||
        message.arguments().size() != 1 ||
        !message.arguments().front().canConvert<QDBusArgument>()) {
        finish(tr("Result unavailable or uncertain. Keep the request ID and check recovery; do not "
                  "repeat the action."),
               false);
        return;
    }
    const auto wire = message.arguments().front().value<QDBusArgument>();
    Linura::ShellClient::SessionReceipt receipt;
    wire.beginStructure();
    wire >> receipt.transaction >> receipt.request >> receipt.resource >> receipt.desired >>
        receipt.effect >> receipt.dispatch >> receipt.disposition >> receipt.verification >>
        receipt.state >> receipt.recovered >> receipt.stages;
    const bool end = wire.atEnd();
    wire.endStructure();
    if (!end || !Linura::ShellClient::validSessionReceipt(receipt, requestId(), expectedResource,
                                                          kind_ == TransitionRequest)) {
        finish(tr("Control returned an invalid or incomplete receipt. No completion is claimed; "
                  "check recovery."),
               false);
        return;
    }
    success();
}

void SessionController::request(Action action)
{
    if (busy_ || hasPending() ||
        (action != Lock && action != EnableProtectiveLock && action != RevokeProtectiveLock &&
         actionName(action).isEmpty()))
        return;
    busy_ = true;
    status_ = tr("Preparing a secure lock. Confirm the exact request in the native locker; no "
                 "credentials belong in this panel.");
    emit changed();
    convergeLock(action);
}

void SessionController::convergeLock(Action action)
{
    call(QStringLiteral("GetOwnSessionLock"), {}, [this, action](const QDBusMessage &reply) {
        const auto resource = replyString(reply);
        if (!Linura::ShellClient::validSessionLockResource(resource)) {
            finish(tr("The native own-session locker is unavailable. No action was dispatched."),
                   false);
            return;
        }
        const auto operation =
            QStringLiteral("shell-lock-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (!retain(operation, LockRequest)) {
            finish(tr("Cannot preserve the request ID. No action was dispatched."), false);
            return;
        }
        call(QStringLiteral("ConvergeSessionLock"),
             {operation, resource, true,
              QStringLiteral("Linura Shell session controls: secure the own session")},
             [this, action, resource](const QDBusMessage &result) {
                 consumeReceipt(result, resource, [this, action, resource] {
                     if (action == Lock) {
                         finish(tr("Secure lock completion was verified and durably committed."),
                                true);
                     } else if (action == EnableProtectiveLock || action == RevokeProtectiveLock) {
                         configureProtectiveLock(action == EnableProtectiveLock, resource);
                     } else {
                         convergeTransition(action);
                     }
                 });
             });
    });
}

void SessionController::convergeTransition(Action action)
{
    const auto name = actionName(action);
    if (name.isEmpty()) {
        finish(tr("Unsupported power action."), false);
        return;
    }
    status_ = tr("The session is secured. The native locker will display the exact power action "
                 "and administrator authentication.");
    emit changed();
    call(QStringLiteral("GetOwnSessionTransition"), {name},
         [this, name](const QDBusMessage &reply) {
             const auto resource = replyString(reply);
             if (!Linura::ShellClient::validSessionTransitionResource(resource, name)) {
                 finish(tr("The power target is unavailable. The session remains secured; no power "
                           "effect was dispatched."),
                        false);
                 return;
             }
             const auto operation = QStringLiteral("shell-power-") +
                                    QUuid::createUuid().toString(QUuid::WithoutBraces);
             if (!retain(operation, TransitionRequest)) {
                 finish(tr("Cannot preserve the power request ID. The session remains secured; no "
                           "power effect was dispatched."),
                        false);
                 return;
             }
             call(QStringLiteral("ConvergeSessionTransition"),
                  {operation, resource, QStringLiteral("Linura Shell session controls: ") + name},
                  [this, resource](const QDBusMessage &result) {
                      consumeReceipt(result, resource, [this] {
                          finish(
                              tr("The requested postcondition was verified and durably committed. "
                                 "This is not a claim about current machine power or causation."),
                              true);
                      });
                  });
         });
}

void SessionController::recover()
{
    if (busy_ || operation_.isEmpty() || invalidRecord_)
        return;
    busy_ = true;
    status_ = tr(
        "Checking durable recovery without replaying, reauthorizing, or starting another action.");
    emit changed();
    if (kind_ == ProtectiveSettingRequest) {
        // Lookup history only: never repeat a configuration write or enroll a
        // newer generation after losing a reply or restarting the shell.
        call(QStringLiteral("GetProtectiveLockSettingRequestStatus"), {requestId()},
             [this](const QDBusMessage &reply) { consumeProtectiveReceipt(reply, true); });
        return;
    }
    call(kind_ == TransitionRequest ? QStringLiteral("RecoverSessionTransition")
                                    : QStringLiteral("RecoverSessionLock"),
         {requestId()}, [this](const QDBusMessage &reply) {
             consumeReceipt(reply, {}, [this] {
                 // A recovered lock never resumes the abandoned power workflow.
                 finish(tr("Recovered completion was verified. No effect was replayed and no "
                           "subsequent action was started."),
                        true);
             });
         });
}

void SessionController::configureProtectiveLock(bool enabled, const QString &resource)
{
    const auto operation =
        QStringLiteral("shell-protection-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    if (!retain(operation, ProtectiveSettingRequest, resource, enabled)) {
        finish(tr("Cannot preserve the exact consent request. The session stays locked; no policy "
                  "change was sent."),
               false);
        return;
    }
    status_ = enabled
                  ? tr("Authenticate as the owner in the secure locker to allow protective "
                       "pre-sleep locking for this login. This never unlocks or authorizes sleep; "
                       "failure may leave a closed laptop running.")
                  : tr("Authenticate as the owner in the secure locker to revoke protective "
                       "pre-sleep locking for this login. This never unlocks or authorizes sleep.");
    emit changed();
    call(QStringLiteral("ConfigureProtectiveLock"), {operation, resource, enabled},
         [this](const QDBusMessage &reply) { consumeProtectiveReceipt(reply, false); });
}

void SessionController::consumeProtectiveReceipt(const QDBusMessage &message, bool recovering)
{
    if (kind_ != ProtectiveSettingRequest || message.type() != QDBusMessage::ReplyMessage ||
        message.signature() != QStringLiteral("(ssbsstb)") || message.arguments().size() != 1 ||
        !message.arguments().front().canConvert<QDBusArgument>()) {
        finish(tr("Consent result unavailable or uncertain. Keep the request ID and inspect "
                  "history; do not repeat the write."),
               false);
        return;
    }
    const auto wire = message.arguments().front().value<QDBusArgument>();
    Linura::ShellClient::ProtectiveLockSettingReceipt receipt;
    wire.beginStructure();
    wire >> receipt.request >> receipt.resource >> receipt.enabled >> receipt.intent >>
        receipt.revision >> receipt.confirmedAt >> receipt.latest;
    const bool end = wire.atEnd();
    wire.endStructure();
    if (!end || !Linura::ShellClient::validProtectiveLockSettingReceipt(
                    receipt, requestId(), protectiveResource_, protectiveEnabled_)) {
        finish(tr("Invalid or substituted consent history. No policy completion or protection is "
                  "claimed; keep the request ID."),
               false);
        return;
    }
    QString text;
    if (!receipt.latest)
        text = tr("This consent request exists in history but was superseded. It was not "
                  "reapplied; current protection is not verified.");
    else if (receipt.enabled)
        text = tr("Protective-lock permission was enabled for this login. This is not evidence of "
                  "current lock coverage, sleep protection or successful sleep. This "
                  "configuration did not request an unlock or sleep.");
    else
        text =
            tr("Protective-lock permission was revoked for this login. This configuration did "
               "not request an unlock or authorize sleep. Current lock coverage is not claimed.");
    if (recovering)
        text += tr(" History lookup did not authenticate, change policy or replay any effect.");
    finish(text, true);
}

void SessionController::forgetTracking()
{
    if (busy_)
        return;
    finish(tr("Local tracking forgotten only. This does not cancel any durable request, unlock the "
              "session, or retire a native power fence."),
           true);
}
