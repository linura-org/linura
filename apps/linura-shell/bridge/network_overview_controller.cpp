#include "network_overview_controller.h"
#include "network_observation_contract.h"

#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDateTime>
#include <QMetaType>
#include <QTimer>
#include <QVariant>

namespace {
constexpr int ReplyDeadlineMs = 2000;

QString sourceText(Linura::ShellClient::NetworkObservationState state)
{
    using State = Linura::ShellClient::NetworkObservationState;
    switch (state) {
    case State::ObservedOnly:
        return QStringLiteral("Current native observation only — connectivity not verified");
    case State::Stale:
        return QStringLiteral("Network observation stale or expired — connectivity unknown");
    case State::Untrusted:
        return QStringLiteral("Network source identity untrusted — connectivity unknown");
    case State::Unavailable:
        return QStringLiteral("Network observation unavailable — connectivity unknown");
    }
    return QStringLiteral("Network observation unavailable — connectivity unknown");
}
} // namespace

NetworkOverviewController::NetworkOverviewController(QObject *parent)
    : QObject(parent),
      bus_(QDBusConnection::connectToBus(QStringLiteral("unix:path=/run/dbus/system_bus_socket"),
                                         QStringLiteral("linura-shell-network-observation"))),
      statusText_(sourceText(Linura::ShellClient::NetworkObservationState::Unavailable))
{}

void NetworkOverviewController::markUnavailable()
{
    sourceStatus_ = QStringLiteral("unavailable");
    statusText_ = sourceText(Linura::ShellClient::NetworkObservationState::Unavailable);
    busy_ = false;
    emit changed();
}

void NetworkOverviewController::markStale()
{
    sourceStatus_ = QStringLiteral("stale");
    statusText_ = sourceText(Linura::ShellClient::NetworkObservationState::Stale);
    emit changed();
}

void NetworkOverviewController::setActive(bool enabled)
{
    if (active_ == enabled)
        return;
    active_ = enabled;
    ++generation_;
    if (!active_) {
        markUnavailable();
    } else {
        refresh();
    }
}

void NetworkOverviewController::refresh()
{
    if (!active_ || busy_)
        return;
    const quint64 generation = ++generation_;
    if (!bus_.isConnected()) {
        markUnavailable();
        return;
    }

    busy_ = true;
    sourceStatus_ = QStringLiteral("checking");
    statusText_ = QStringLiteral("Checking Control1 observations — connectivity unknown");
    emit changed();

    QDBusMessage call = QDBusMessage::createMethodCall(
        QStringLiteral("org.linura.Control1"), QStringLiteral("/org/linura/Control1"),
        QStringLiteral("org.linura.Control1"), QStringLiteral("Observe"));
    call.setAutoStartService(false);
    call.setArguments({
        QStringLiteral("networkmanager"),
        QStringLiteral("networkmanager:connections"),
        QStringLiteral("networkmanager.connections.observe"),
    });

    auto *watcher = new QDBusPendingCallWatcher(bus_.asyncCall(call, ReplyDeadlineMs), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, watcher, generation](QDBusPendingCallWatcher *) {
                const QDBusMessage reply = watcher->reply();
                watcher->deleteLater();
                if (!active_ || generation != generation_)
                    return;
                busy_ = false;
                const auto values = reply.arguments();
                const auto stringType = QMetaType::fromType<QString>();
                const auto integerType = QMetaType::fromType<qulonglong>();
                if (reply.type() != QDBusMessage::ReplyMessage || values.size() != 9 ||
                    reply.signature() != QLatin1String("sssssttta(ss)") ||
                    values[0].metaType() != stringType || values[1].metaType() != stringType ||
                    values[2].metaType() != stringType || values[3].metaType() != stringType ||
                    values[4].metaType() != stringType || values[5].metaType() != integerType ||
                    values[6].metaType() != integerType || values[7].metaType() != integerType) {
                    markUnavailable();
                    return;
                }
                const quint64 observedAt = values[5].toULongLong();
                const quint64 validFor = values[6].toULongLong();
                Linura::ShellClient::NetworkObservationFields source;
                source.provider = values[0].toString();
                source.resource = values[1].toString();
                source.capability = values[2].toString();
                source.authority = values[3].toString();
                source.freshness = values[4].toString();
                source.observedAtMs = observedAt;
                source.validForMs = validFor;
                source.sequence = values[7].toULongLong();
                source.currentUnixMs = QDateTime::currentMSecsSinceEpoch();
                const auto state = Linura::ShellClient::classifyNetworkObservation(source);
                using State = Linura::ShellClient::NetworkObservationState;
                switch (state) {
                case State::ObservedOnly:
                    sourceStatus_ = QStringLiteral("observed-only");
                    break;
                case State::Stale:
                    sourceStatus_ = QStringLiteral("stale");
                    break;
                case State::Untrusted:
                    sourceStatus_ = QStringLiteral("untrusted");
                    break;
                case State::Unavailable:
                    sourceStatus_ = QStringLiteral("unavailable");
                    break;
                }
                statusText_ = sourceText(state);
                emit changed();

                if (state != State::ObservedOnly)
                    return;
                const quint64 now = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
                const quint64 age = now >= observedAt ? now - observedAt : validFor;
                const int remaining = age < validFor ? static_cast<int>(validFor - age) : 0;
                QTimer::singleShot(remaining, this, [this, generation] {
                    if (active_ && generation_ == generation &&
                        sourceStatus_ == QLatin1String("observed-only"))
                        markStale();
                });
            });
}
