#pragma once

#include <QDBusConnection>
#include <QDBusMessage>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

#include <optional>

class AudioSessionController : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY stateChanged)
    Q_PROPERTY(QString sinkName READ sinkName NOTIFY snapshotChanged)
    Q_PROPERTY(quint32 nodeId READ nodeId NOTIFY snapshotChanged)
    Q_PROPERTY(int volumePercent READ volumePercent NOTIFY snapshotChanged)
    Q_PROPERTY(bool muted READ muted NOTIFY snapshotChanged)
    Q_PROPERTY(QString authority READ authority NOTIFY snapshotChanged)
    Q_PROPERTY(QString freshness READ freshness NOTIFY snapshotChanged)
    Q_PROPERTY(QString observationDetail READ observationDetail NOTIFY snapshotChanged)
    Q_PROPERTY(bool canApply READ canApply NOTIFY availabilityChanged)
    Q_PROPERTY(bool canCommitDraft READ canCommitDraft NOTIFY availabilityChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY availabilityChanged)
    Q_PROPERTY(QString lastReceiptStatus READ lastReceiptStatus NOTIFY receiptChanged)
    Q_PROPERTY(QString lastEvidenceId READ lastEvidenceId NOTIFY receiptChanged)
    Q_PROPERTY(bool active READ active WRITE setActive NOTIFY activeChanged)

public:
    explicit AudioSessionController(QObject *parent = nullptr);

    [[nodiscard]] QString state() const;
    [[nodiscard]] QString statusText() const;
    [[nodiscard]] QString sinkName() const;
    [[nodiscard]] quint32 nodeId() const;
    [[nodiscard]] int volumePercent() const;
    [[nodiscard]] bool muted() const;
    [[nodiscard]] QString authority() const;
    [[nodiscard]] QString freshness() const;
    [[nodiscard]] QString observationDetail() const;
    [[nodiscard]] bool canApply() const;
    [[nodiscard]] bool canCommitDraft() const;
    [[nodiscard]] bool busy() const;
    [[nodiscard]] QString lastReceiptStatus() const;
    [[nodiscard]] QString lastEvidenceId() const;
    [[nodiscard]] bool active() const;

    Q_INVOKABLE void setActive(bool active);
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void beginVolumeDraft();
    Q_INVOKABLE void cancelVolumeDraft();
    Q_INVOKABLE void setVolume(int requestedVolume);

signals:
    void stateChanged();
    void snapshotChanged();
    void availabilityChanged();
    void receiptChanged();
    void activeChanged();

private:
    struct SinkSnapshot {
        quint32 nodeId = 0;
        quint64 objectSerial = 0;
        QString nodeName;
        QString displayName;
        int volumePercent = 0;
        bool muted = false;
        qint64 observedAtUnixMs = 0;
        quint64 validForMs = 0;
        quint64 sequence = 0;
    };

    struct EffectReceipt {
        QString operationId;
        QString planId;
        QString requestId;
        QString risk;
        QString preEffectEvidenceId;
        QString postEffectEvidenceId;
        QString status;
    };

    struct PendingEffect {
        SinkSnapshot displayed;
        int requestedVolume = 0;
        QString requestId;
        bool dispatched = false;
    };

    enum class ObservePurpose {
        Refresh,
        PreApply,
        PostApply,
    };

    [[nodiscard]] static bool sameIdentity(
        const SinkSnapshot &left,
        const SinkSnapshot &right);
    [[nodiscard]] static bool samePrecondition(
        const SinkSnapshot &left,
        const SinkSnapshot &right);
    void setState(const QString &state, const QString &message);
    void applySnapshot(const SinkSnapshot &snapshot, bool armExpiry);
    void armFreshnessExpiry(const SinkSnapshot &snapshot);
    void scheduleActiveRetry();
    void resetRetryBackoff();
    void observe(ObservePurpose purpose);
    [[nodiscard]] std::optional<SinkSnapshot> parseObservation(
        const QDBusMessage &message,
        QString *error) const;
    void handleObservation(ObservePurpose purpose, const SinkSnapshot &snapshot);
    void handleObservationFailure(
        ObservePurpose purpose,
        const QString &message,
        bool serviceUnavailable = false);
    void dispatchEffect();
    [[nodiscard]] std::optional<EffectReceipt> parseReceipt(
        const QDBusMessage &message,
        const QString &expectedRequestId,
        QString *error) const;

    QDBusConnection sessionBus_;
    QTimer freshnessTimer_;
    QTimer retryTimer_;
    std::optional<SinkSnapshot> current_;
    std::optional<SinkSnapshot> draftBase_;
    std::optional<PendingEffect> pending_;
    QString state_ = QStringLiteral("inactive");
    QString statusText_ = QStringLiteral("Control Center is closed.");
    QString authority_ = QStringLiteral("unknown");
    QString freshness_ = QStringLiteral("unknown");
    QString lastReceiptStatus_;
    QString lastEvidenceId_;
    quint64 observationGeneration_ = 0;
    int retryDelayMs_ = 0;
    bool active_ = false;
};
