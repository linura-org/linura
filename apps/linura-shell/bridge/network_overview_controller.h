#pragma once

#include <QDBusConnection>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

// Passive Control1 client: no native sender, NM command, security prompt,
// risk selection, execution method, public mutation endpoint or secret data.
class NetworkOverviewController : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(bool active READ active WRITE setActive NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString sourceStatus READ sourceStatus NOTIFY changed)
    Q_PROPERTY(QString statusText READ statusText NOTIFY changed)

  public:
    explicit NetworkOverviewController(QObject *parent = nullptr);

    [[nodiscard]] bool active() const noexcept
    {
        return active_;
    }
    [[nodiscard]] bool busy() const noexcept
    {
        return busy_;
    }
    [[nodiscard]] QString sourceStatus() const
    {
        return sourceStatus_;
    }
    [[nodiscard]] QString statusText() const
    {
        return statusText_;
    }

    void setActive(bool enabled);
    Q_INVOKABLE void refresh();

  signals:
    void changed();

  private:
    void markUnavailable();
    void markStale();

    QDBusConnection bus_;
    QString sourceStatus_ = QStringLiteral("unavailable");
    QString statusText_;
    quint64 generation_ = 0;
    bool active_ = false;
    bool busy_ = false;
};
