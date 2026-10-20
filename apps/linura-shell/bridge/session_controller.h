#pragma once

#include <QDBusConnection>
#include <QDBusMessage>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

#include <functional>

// Ordinary client only. No native provider, Polkit, password input, policy,
// executable plan, executor or operation-class selection is exposed to QML.
class SessionController : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(bool hasPending READ hasPending NOTIFY changed)
    Q_PROPERTY(QString statusText READ statusText NOTIFY changed)
    Q_PROPERTY(QString requestId READ requestId NOTIFY changed)
    Q_PROPERTY(
        QString nativeSleepStatusText READ nativeSleepStatusText NOTIFY nativeSleepStatusChanged)

  public:
    enum Action {
        Lock,
        Suspend,
        Logout,
        Reboot,
        PowerOff,
        EnableProtectiveLock,
        RevokeProtectiveLock
    };
    Q_ENUM(Action)
    explicit SessionController(QObject *parent = nullptr);
    [[nodiscard]] bool busy() const
    {
        return busy_;
    }
    [[nodiscard]] bool hasPending() const
    {
        return !operation_.isEmpty() || invalidRecord_;
    }
    [[nodiscard]] QString statusText() const
    {
        return status_;
    }
    [[nodiscard]] QString requestId() const;
    [[nodiscard]] QString nativeSleepStatusText() const
    {
        return nativeSleepStatus_;
    }
    // Read-only, bounded and coalesced. Never locks, enrolls, retries or sleeps.
    Q_INVOKABLE void refreshNativeSleepStatus();
    Q_INVOKABLE void request(Action action);
    Q_INVOKABLE void recover();
    // Explicitly forget CLIENT tracking, never cancel a transaction or lift a
    // native fence. Loading/recovering this file can never dispatch an effect.
    Q_INVOKABLE void forgetTracking();

  signals:
    void changed();
    void nativeSleepStatusChanged();

  private:
#ifdef LINURA_SESSION_TRACKING_TESTS
    friend struct SessionTrackingTestAccess;
#endif
    enum RequestKind { LockRequest, TransitionRequest, ProtectiveSettingRequest };
    void call(const QString &method, const QVariantList &arguments,
              std::function<void(const QDBusMessage &)> finished, int timeoutMs = 100'000);
    void convergeLock(Action action);
    void convergeTransition(Action action);
    void configureProtectiveLock(bool enabled, const QString &resource);
    void consumeProtectiveReceipt(const QDBusMessage &message, bool recovering);
    bool retain(const QString &operation, RequestKind kind, const QString &resource = {},
                bool enabled = false);
    void finish(const QString &message, bool clear);
    void consumeReceipt(const QDBusMessage &message, const QString &expectedResource,
                        std::function<void()> success);
    void loadTracking();
    [[nodiscard]] static QString actionName(Action action);

    QDBusConnection bus_;
    QString trackingPath_;
    QString operation_;
    QString status_;
    QString nativeSleepStatus_;
    bool nativeSleepQueryPending_ = false;
    RequestKind kind_ = LockRequest;
    QString protectiveResource_;
    bool protectiveEnabled_ = false;
    bool invalidRecord_ = false;
    bool busy_ = false;
};
