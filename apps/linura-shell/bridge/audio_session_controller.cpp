#include "audio_session_controller.h"

#include <QDateTime>
#include <QDBusArgument>
#include <QDBusInterface>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QMap>
#include <QStringList>
#include <QUuid>
#include <QVariant>

#include <algorithm>
#include <limits>

namespace {

constexpr auto kServiceName = "org.linura.Control1";
constexpr auto kControlPath = "/org/linura/Control1";
constexpr auto kControlInterface = "org.linura.Control1";
constexpr auto kSessionPath = "/org/linura/Session1";
constexpr auto kSessionInterface = "org.linura.Session1";
constexpr auto kPipeWireProvider = "pipewire";
constexpr auto kAudioCapability = "audio.session.observe";
constexpr auto kDefaultOutputResource = "audio:session:default-output";
constexpr auto kAudioOperation = "operation:audio.output.set-session-volume";
constexpr auto kReason = "Linura Shell Control Center audio quick setting";
constexpr qint64 kFutureSkewMs = 1'000;
constexpr quint64 kMaximumObservationValidityMs = 10'000;
constexpr int kObserveTimeoutMs = 3'000;
constexpr int kEffectTimeoutMs = 5'000;
constexpr int kRetryInitialMs = 1'000;
constexpr int kRetryMaximumMs = 10'000;
constexpr qsizetype kMaximumDisplayText = 1'024;
constexpr qsizetype kMaximumDiagnosticText = 512;

bool parseCanonicalUnsigned(const QString &text, quint64 maximum, quint64 *value)
{
    if (text.isEmpty() || text.size() > 20) {
        return false;
    }
    if (text.size() > 1 && text.startsWith(QLatin1Char('0'))) {
        return false;
    }
    for (const QChar character : text) {
        if (character < QLatin1Char('0') || character > QLatin1Char('9')) {
            return false;
        }
    }

    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 10);
    if (!ok || parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

bool parseCanonicalBool(const QString &text, bool *value)
{
    if (text == QStringLiteral("true")) {
        *value = true;
        return true;
    }
    if (text == QStringLiteral("false")) {
        *value = false;
        return true;
    }
    return false;
}

bool isControlCharacter(QChar character)
{
    return character.category() == QChar::Other_Control;
}

bool isBoundedControlFree(
    const QString &text,
    qsizetype maximum,
    bool allowEmpty = false)
{
    if ((!allowEmpty && text.isEmpty()) || text.size() > maximum) {
        return false;
    }
    return std::none_of(text.cbegin(), text.cend(), [](QChar character) {
        return isControlCharacter(character);
    });
}

bool isServiceUnavailableError(const QString &errorName)
{
    return errorName == QStringLiteral("org.freedesktop.DBus.Error.ServiceUnknown")
        || errorName == QStringLiteral("org.freedesktop.DBus.Error.NameHasNoOwner")
        || errorName == QStringLiteral("org.freedesktop.DBus.Error.Disconnected")
        || errorName == QStringLiteral("org.freedesktop.DBus.Error.NoReply");
}

QString sanitizedDiagnostic(QString text)
{
    if (text.size() > kMaximumDiagnosticText) {
        text.truncate(kMaximumDiagnosticText);
        text.append(QStringLiteral("…"));
    }
    for (qsizetype index = 0; index < text.size(); ++index) {
        if (isControlCharacter(text.at(index))) {
            text[index] = QLatin1Char(' ');
        }
    }
    return text;
}

bool decodeStringMap(const QVariant &value, QMap<QString, QString> *result)
{
    if (!value.canConvert<QDBusArgument>()) {
        return false;
    }

    QDBusArgument argument = qvariant_cast<QDBusArgument>(value);
    QMap<QString, QString> decoded;
    argument.beginArray();
    while (!argument.atEnd()) {
        QString key;
        QString item;
        argument.beginStructure();
        argument >> key >> item;
        argument.endStructure();
        if (key.isEmpty() || decoded.contains(key)) {
            argument.endArray();
            return false;
        }
        decoded.insert(key, item);
    }
    argument.endArray();
    *result = decoded;
    return true;
}

} // namespace

bool AudioSessionController::sameIdentity(
    const SinkSnapshot &left,
    const SinkSnapshot &right)
{
    return left.nodeId == right.nodeId
        && left.objectSerial == right.objectSerial
        && left.nodeName == right.nodeName;
}

bool AudioSessionController::samePrecondition(
    const SinkSnapshot &left,
    const SinkSnapshot &right)
{
    return sameIdentity(left, right)
        && left.volumePercent == right.volumePercent
        && left.muted == right.muted;
}

AudioSessionController::AudioSessionController(QObject *parent)
    : QObject(parent),
      sessionBus_(QDBusConnection::sessionBus())
{
    freshnessTimer_.setSingleShot(true);
    connect(&freshnessTimer_, &QTimer::timeout, this, [this] {
        if (!active_ || !current_.has_value() || busy()) {
            return;
        }
        freshness_ = QStringLiteral("stale");
        emit snapshotChanged();
        setState(
            QStringLiteral("stale"),
            QStringLiteral("Authoritative audio state expired; refreshing before mutation."));
        refresh();
    });

    retryTimer_.setSingleShot(true);
    connect(&retryTimer_, &QTimer::timeout, this, [this] {
        if (!active_ || pending_.has_value() || busy()) {
            return;
        }
        refresh();
    });
}

QString AudioSessionController::state() const { return state_; }
QString AudioSessionController::statusText() const { return statusText_; }

QString AudioSessionController::sinkName() const
{
    return current_.has_value()
        ? current_->displayName
        : QStringLiteral("Unknown output");
}

quint32 AudioSessionController::nodeId() const
{
    return current_.has_value() ? current_->nodeId : 0;
}

int AudioSessionController::volumePercent() const
{
    return current_.has_value() ? current_->volumePercent : 0;
}

bool AudioSessionController::muted() const
{
    return current_.has_value() && current_->muted;
}

QString AudioSessionController::authority() const { return authority_; }
QString AudioSessionController::freshness() const { return freshness_; }

QString AudioSessionController::observationDetail() const
{
    if (!current_.has_value()) {
        return QStringLiteral("No authoritative observation");
    }
    return QStringLiteral("node %1 · serial %2 · sequence %3")
        .arg(current_->nodeId)
        .arg(current_->objectSerial)
        .arg(current_->sequence);
}

bool AudioSessionController::canApply() const
{
    return active_
        && state_ == QStringLiteral("ready")
        && current_.has_value()
        && current_->volumePercent <= 100;
}

bool AudioSessionController::busy() const
{
    return state_ == QStringLiteral("loading")
        || state_ == QStringLiteral("applying");
}

QString AudioSessionController::lastReceiptStatus() const
{
    return lastReceiptStatus_;
}

QString AudioSessionController::lastEvidenceId() const
{
    return lastEvidenceId_;
}

bool AudioSessionController::active() const
{
    return active_;
}

void AudioSessionController::setActive(bool active)
{
    if (active_ == active) {
        return;
    }

    active_ = active;
    emit activeChanged();
    emit availabilityChanged();

    if (!active_) {
        freshnessTimer_.stop();
        retryTimer_.stop();
        resetRetryBackoff();
        draftBase_.reset();
        if (pending_.has_value() && !pending_->dispatched) {
            pending_.reset();
        }
        if (!pending_.has_value()) {
            ++observationGeneration_;
            freshness_ = QStringLiteral("unknown");
            emit snapshotChanged();
            setState(
                QStringLiteral("inactive"),
                QStringLiteral("Control Center is closed."));
        }
        return;
    }

    retryTimer_.stop();
    resetRetryBackoff();
    freshness_ = QStringLiteral("unknown");
    emit snapshotChanged();
    if (!pending_.has_value()) {
        setState(
            QStringLiteral("loading"),
            QStringLiteral("Reading authoritative PipeWire state…"));
        observe(ObservePurpose::Refresh);
    }
}

void AudioSessionController::refresh()
{
    if (!active_ || busy()) {
        return;
    }
    if (!current_.has_value()) {
        setState(
            QStringLiteral("loading"),
            QStringLiteral("Reading authoritative PipeWire state…"));
    }
    observe(ObservePurpose::Refresh);
}

void AudioSessionController::beginVolumeDraft()
{
    if (!draftBase_.has_value() && canApply() && current_.has_value()) {
        draftBase_ = *current_;
    }
}

void AudioSessionController::cancelVolumeDraft()
{
    draftBase_.reset();
}

void AudioSessionController::setVolume(int requestedVolume)
{
    if (requestedVolume < 0 || requestedVolume > 100) {
        setState(
            QStringLiteral("error"),
            QStringLiteral("Volume must be between 0% and 100%."));
        return;
    }
    if (!canApply() || !current_.has_value()) {
        setState(
            QStringLiteral("stale"),
            QStringLiteral("A fresh qualified audio observation is required before applying."));
        return;
    }

    const SinkSnapshot displayed = draftBase_.value_or(*current_);
    draftBase_.reset();
    freshnessTimer_.stop();
    pending_ = PendingEffect {
        .displayed = displayed,
        .requestedVolume = requestedVolume,
        .requestId = QStringLiteral("request:linura-shell:audio:")
            + QUuid::createUuid().toString(QUuid::WithoutBraces),
    };
    setState(
        QStringLiteral("applying"),
        QStringLiteral("Revalidating the current audio state before dispatch…"));
    observe(ObservePurpose::PreApply);
}

void AudioSessionController::setState(
    const QString &state,
    const QString &message)
{
    state_ = state;
    statusText_ = message;
    emit stateChanged();
    emit availabilityChanged();
}

void AudioSessionController::applySnapshot(
    const SinkSnapshot &snapshot,
    bool armExpiry)
{
    current_ = snapshot;
    authority_ = QStringLiteral("native-api");
    freshness_ = QStringLiteral("fresh");
    if (armExpiry && active_) {
        armFreshnessExpiry(snapshot);
    } else {
        freshnessTimer_.stop();
    }
    emit snapshotChanged();
    emit availabilityChanged();
}

void AudioSessionController::armFreshnessExpiry(const SinkSnapshot &snapshot)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 expiry = snapshot.observedAtUnixMs + qint64(snapshot.validForMs);
    const qint64 remaining = std::max<qint64>(0, expiry - now);
    freshnessTimer_.start(int(std::min<qint64>(
        remaining,
        std::numeric_limits<int>::max())));
}

void AudioSessionController::scheduleActiveRetry()
{
    if (!active_ || pending_.has_value()) {
        retryTimer_.stop();
        return;
    }

    const int delay = retryDelayMs_ == 0
        ? kRetryInitialMs
        : std::min(retryDelayMs_ * 2, kRetryMaximumMs);
    retryDelayMs_ = delay;
    retryTimer_.start(delay);
}

void AudioSessionController::resetRetryBackoff()
{
    retryDelayMs_ = 0;
}

void AudioSessionController::observe(ObservePurpose purpose)
{
    const quint64 generation = ++observationGeneration_;
    if (!sessionBus_.isConnected()) {
        handleObservationFailure(
            purpose,
            QStringLiteral("Linura session bus is unavailable."),
            true);
        return;
    }

    QDBusInterface control(
        QString::fromLatin1(kServiceName),
        QString::fromLatin1(kControlPath),
        QString::fromLatin1(kControlInterface),
        sessionBus_);
    control.setTimeout(kObserveTimeoutMs);
    if (!control.isValid()) {
        handleObservationFailure(
            purpose,
            QStringLiteral("Linura Control1 is unavailable on the session bus."),
            true);
        return;
    }

    QDBusPendingCall call = control.asyncCall(
        QStringLiteral("Observe"),
        QString::fromLatin1(kPipeWireProvider),
        QString::fromLatin1(kDefaultOutputResource),
        QString::fromLatin1(kAudioCapability));
    auto *watcher = new QDBusPendingCallWatcher(call, this);
    connect(
        watcher,
        &QDBusPendingCallWatcher::finished,
        this,
        [this, purpose, generation](QDBusPendingCallWatcher *finished) {
            const QDBusMessage reply = finished->reply();
            finished->deleteLater();
            if (generation != observationGeneration_) {
                return;
            }
            if (reply.type() == QDBusMessage::ErrorMessage) {
                handleObservationFailure(
                    purpose,
                    QStringLiteral("Authoritative audio observation failed: %1")
                        .arg(sanitizedDiagnostic(reply.errorMessage())),
                    isServiceUnavailableError(reply.errorName()));
                return;
            }

            QString error;
            const auto snapshot = parseObservation(reply, &error);
            if (!snapshot.has_value()) {
                handleObservationFailure(purpose, error);
                return;
            }
            handleObservation(purpose, *snapshot);
        });
}

std::optional<AudioSessionController::SinkSnapshot>
AudioSessionController::parseObservation(
    const QDBusMessage &message,
    QString *error) const
{
    const QList<QVariant> arguments = message.arguments();
    if (arguments.size() != 9) {
        *error = QStringLiteral("Control1 returned an unexpected Observe reply shape.");
        return std::nullopt;
    }

    const QString provider = arguments.at(0).toString();
    const QString resource = arguments.at(1).toString();
    const QString capability = arguments.at(2).toString();
    const QString authority = arguments.at(3).toString();
    const QString freshness = arguments.at(4).toString();

    bool observedAtOk = false;
    const quint64 observedAt = arguments.at(5).toULongLong(&observedAtOk);
    bool validForOk = false;
    const quint64 validFor = arguments.at(6).toULongLong(&validForOk);
    bool sequenceOk = false;
    const quint64 sequence = arguments.at(7).toULongLong(&sequenceOk);

    if (provider != QString::fromLatin1(kPipeWireProvider)
        || resource != QString::fromLatin1(kDefaultOutputResource)
        || capability != QString::fromLatin1(kAudioCapability)
        || authority != QStringLiteral("native-api")) {
        *error = QStringLiteral("Control1 audio observation identity/authority mismatch.");
        return std::nullopt;
    }
    if (freshness != QStringLiteral("fresh")) {
        *error = QStringLiteral("Audio state is stale or unknown; mutation remains disabled.");
        return std::nullopt;
    }
    if (!observedAtOk
        || !validForOk
        || !sequenceOk
        || observedAt > quint64(std::numeric_limits<qint64>::max())
        || validFor == 0
        || validFor > kMaximumObservationValidityMs
        || sequence == 0) {
        *error = QStringLiteral("Control1 returned invalid audio freshness metadata.");
        return std::nullopt;
    }

    const qint64 observedAtSigned = qint64(observedAt);
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (observedAtSigned > now + kFutureSkewMs
        || validFor > quint64(std::numeric_limits<qint64>::max() - observedAtSigned)
        || now > observedAtSigned + qint64(validFor)) {
        *error = QStringLiteral("Authoritative audio observation expired before use.");
        return std::nullopt;
    }

    QMap<QString, QString> attributes;
    if (!decodeStringMap(arguments.at(8), &attributes)) {
        *error = QStringLiteral("Control1 returned malformed audio attributes.");
        return std::nullopt;
    }

    const QStringList required {
        QStringLiteral("node_id"),
        QStringLiteral("object_serial"),
        QStringLiteral("node_name"),
        QStringLiteral("media_class"),
        QStringLiteral("is_default"),
        QStringLiteral("volume_percent"),
        QStringLiteral("muted"),
    };
    for (const QString &key : required) {
        if (!attributes.contains(key)) {
            *error = QStringLiteral("Authoritative audio state is missing %1.").arg(key);
            return std::nullopt;
        }
    }

    quint64 nodeId = 0;
    quint64 objectSerial = 0;
    quint64 volume = 0;
    bool isDefault = false;
    bool isMuted = false;
    if (!parseCanonicalUnsigned(
            attributes.value(QStringLiteral("node_id")),
            std::numeric_limits<quint32>::max() - 1ULL,
            &nodeId)
        || !parseCanonicalUnsigned(
            attributes.value(QStringLiteral("object_serial")),
            std::numeric_limits<quint64>::max(),
            &objectSerial)
        || !parseCanonicalUnsigned(
            attributes.value(QStringLiteral("volume_percent")),
            1'000,
            &volume)
        || !parseCanonicalBool(
            attributes.value(QStringLiteral("is_default")),
            &isDefault)
        || !parseCanonicalBool(
            attributes.value(QStringLiteral("muted")),
            &isMuted)
        || !isDefault
        || attributes.value(QStringLiteral("media_class"))
            != QStringLiteral("Audio/Sink")) {
        *error = QStringLiteral("Authoritative default-output attributes failed validation.");
        return std::nullopt;
    }

    const QString nodeName = attributes.value(QStringLiteral("node_name"));
    if (!isBoundedControlFree(nodeName, kMaximumDisplayText)) {
        *error = QStringLiteral("Authoritative audio node name is invalid.");
        return std::nullopt;
    }

    QString displayName = attributes.value(QStringLiteral("name"), nodeName);
    if (displayName.isEmpty()) {
        displayName = nodeName;
    }
    if (!isBoundedControlFree(displayName, kMaximumDisplayText)) {
        *error = QStringLiteral("Authoritative audio display name is invalid.");
        return std::nullopt;
    }

    return SinkSnapshot {
        .nodeId = quint32(nodeId),
        .objectSerial = objectSerial,
        .nodeName = nodeName,
        .displayName = displayName,
        .volumePercent = int(volume),
        .muted = isMuted,
        .observedAtUnixMs = observedAtSigned,
        .validForMs = validFor,
        .sequence = sequence,
    };
}

void AudioSessionController::handleObservation(
    ObservePurpose purpose,
    const SinkSnapshot &snapshot)
{
    retryTimer_.stop();
    resetRetryBackoff();

    switch (purpose) {
    case ObservePurpose::Refresh:
        applySnapshot(snapshot, true);
        if (snapshot.volumePercent > 100) {
            setState(
                QStringLiteral("stale"),
                QStringLiteral(
                    "The current output is amplified above the qualified 0–100% mutation range."));
        } else {
            setState(
                QStringLiteral("ready"),
                QStringLiteral("Authoritative PipeWire state is current."));
        }
        return;

    case ObservePurpose::PreApply:
        if (!pending_.has_value()) {
            setState(
                QStringLiteral("error"),
                QStringLiteral("Pending audio request was lost."));
            return;
        }
        if (!samePrecondition(pending_->displayed, snapshot)) {
            applySnapshot(snapshot, true);
            pending_.reset();
            setState(
                snapshot.volumePercent <= 100
                    ? QStringLiteral("ready")
                    : QStringLiteral("stale"),
                QStringLiteral(
                    "Audio state changed concurrently. Review the refreshed state before applying."));
            return;
        }
        applySnapshot(snapshot, false);
        dispatchEffect();
        return;

    case ObservePurpose::PostApply:
        if (!pending_.has_value()) {
            setState(
                QStringLiteral("error"),
                QStringLiteral("Pending audio verification was lost."));
            return;
        }
        {
            const PendingEffect pending = *pending_;
            pending_.reset();
            applySnapshot(snapshot, true);
            if (!sameIdentity(pending.displayed, snapshot)) {
                setState(
                    snapshot.volumePercent <= 100
                        ? QStringLiteral("ready")
                        : QStringLiteral("stale"),
                    QStringLiteral(
                        "The default audio output changed after dispatch; showing the new authoritative output."));
                return;
            }
            if (snapshot.volumePercent != pending.requestedVolume) {
                setState(
                    QStringLiteral("error"),
                    QStringLiteral(
                        "Independent post-effect observation did not match the requested volume."));
                return;
            }
            setState(
                QStringLiteral("ready"),
                lastReceiptStatus_ == QStringLiteral("no-change")
                    ? QStringLiteral("Volume already matched the requested state.")
                    : QStringLiteral("Volume change independently verified."));
        }
        return;
    }
}

void AudioSessionController::handleObservationFailure(
    ObservePurpose purpose,
    const QString &message,
    bool serviceUnavailable)
{
    freshnessTimer_.stop();
    freshness_ = QStringLiteral("unknown");
    emit snapshotChanged();

    const bool unavailable = serviceUnavailable || !sessionBus_.isConnected();

    if (purpose == ObservePurpose::PostApply) {
        pending_.reset();
        setState(
            unavailable
                ? QStringLiteral("unavailable")
                : QStringLiteral("error"),
            QStringLiteral(
                "An effect receipt exists, but final success is withheld because authoritative "
                "post-effect observation failed: %1")
                .arg(sanitizedDiagnostic(message)));
        scheduleActiveRetry();
        return;
    }
    if (purpose == ObservePurpose::PreApply) {
        pending_.reset();
    }
    setState(
        unavailable
            ? QStringLiteral("unavailable")
            : QStringLiteral("stale"),
        sanitizedDiagnostic(message));
    scheduleActiveRetry();
}

void AudioSessionController::dispatchEffect()
{
    if (!pending_.has_value()) {
        setState(
            QStringLiteral("error"),
            QStringLiteral("No pending audio request exists."));
        return;
    }

    QDBusInterface session(
        QString::fromLatin1(kServiceName),
        QString::fromLatin1(kSessionPath),
        QString::fromLatin1(kSessionInterface),
        sessionBus_);
    session.setTimeout(kEffectTimeoutMs);
    if (!session.isValid()) {
        pending_.reset();
        setState(
            QStringLiteral("unavailable"),
            QStringLiteral("Linura Session1 is unavailable; no effect was dispatched."));
        scheduleActiveRetry();
        return;
    }

    pending_->dispatched = true;
    const PendingEffect pending = *pending_;
    setState(
        QStringLiteral("applying"),
        QStringLiteral("Dispatching the exact-node Session1 transient effect…"));

    QDBusPendingCall call = session.asyncCall(
        QStringLiteral("SetAudioOutputVolume"),
        pending.requestId,
        QVariant::fromValue(pending.displayed.nodeId),
        QVariant::fromValue(quint16(pending.requestedVolume)),
        QString::fromLatin1(kReason));
    auto *watcher = new QDBusPendingCallWatcher(call, this);
    connect(
        watcher,
        &QDBusPendingCallWatcher::finished,
        this,
        [this, requestId = pending.requestId](QDBusPendingCallWatcher *finished) {
            const QDBusMessage reply = finished->reply();
            finished->deleteLater();
            if (reply.type() == QDBusMessage::ErrorMessage) {
                pending_.reset();
                const bool unavailable = isServiceUnavailableError(reply.errorName());
                setState(
                    unavailable
                        ? QStringLiteral("unavailable")
                        : QStringLiteral("error"),
                    QStringLiteral("Session1 rejected the audio effect: %1")
                        .arg(sanitizedDiagnostic(reply.errorMessage())));
                if (unavailable) {
                    scheduleActiveRetry();
                }
                return;
            }

            QString error;
            const auto receipt = parseReceipt(reply, requestId, &error);
            if (!receipt.has_value()) {
                pending_.reset();
                setState(QStringLiteral("error"), error);
                return;
            }

            lastReceiptStatus_ = receipt->status;
            lastEvidenceId_ = receipt->postEffectEvidenceId.isEmpty()
                ? receipt->preEffectEvidenceId
                : receipt->postEffectEvidenceId;
            emit receiptChanged();
            setState(
                QStringLiteral("applying"),
                QStringLiteral(
                    "Effect returned; waiting for independent authoritative verification…"));
            observe(ObservePurpose::PostApply);
        });
}

std::optional<AudioSessionController::EffectReceipt>
AudioSessionController::parseReceipt(
    const QDBusMessage &message,
    const QString &expectedRequestId,
    QString *error) const
{
    const QList<QVariant> arguments = message.arguments();
    if (arguments.size() != 1
        || !arguments.at(0).canConvert<QDBusArgument>()) {
        *error = QStringLiteral("Session1 returned an unexpected effect receipt shape.");
        return std::nullopt;
    }

    QDBusArgument wire = qvariant_cast<QDBusArgument>(arguments.at(0));
    EffectReceipt receipt;
    wire.beginStructure();
    wire >> receipt.operationId
         >> receipt.planId
         >> receipt.requestId
         >> receipt.risk
         >> receipt.preEffectEvidenceId
         >> receipt.postEffectEvidenceId
         >> receipt.status;
    wire.endStructure();

    if (receipt.operationId != QString::fromLatin1(kAudioOperation)
        || receipt.requestId != expectedRequestId
        || !isBoundedControlFree(receipt.planId, 256)
        || receipt.risk != QStringLiteral("user-state")
        || !isBoundedControlFree(receipt.preEffectEvidenceId, kMaximumDisplayText)
        || !isBoundedControlFree(
            receipt.postEffectEvidenceId,
            kMaximumDisplayText,
            true)
        || (receipt.status != QStringLiteral("verified")
            && receipt.status != QStringLiteral("no-change"))
        || (receipt.status == QStringLiteral("verified")
            && receipt.postEffectEvidenceId.isEmpty())
        || (receipt.status == QStringLiteral("no-change")
            && !receipt.postEffectEvidenceId.isEmpty())) {
        *error = QStringLiteral(
            "Session1 effect receipt failed authority/correlation validation.");
        return std::nullopt;
    }
    return receipt;
}
