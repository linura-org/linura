// CPU/QML read-only S18-9 surface fixture. Not a Wayland, network,
// accessibility-service, physical workstation or connectivity qualification.
#include <QAccessible>
#include <QGuiApplication>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QString>

#include <memory>

class NetworkFixture : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool active MEMBER active NOTIFY changed)
    Q_PROPERTY(bool busy MEMBER busy NOTIFY changed)
    Q_PROPERTY(QString sourceStatus MEMBER sourceStatus NOTIFY changed)
    Q_PROPERTY(QString statusText MEMBER statusText NOTIFY changed)
  public:
    bool active = false;
    bool busy = false;
    QString sourceStatus = QStringLiteral("unavailable");
    QString statusText = QStringLiteral("Network observation unavailable — connectivity unknown");
    int refreshes = 0;
    Q_INVOKABLE void refresh()
    {
        ++refreshes;
    }
  signals:
    void changed();
};

QList<QQuickItem *> allChildren(QQuickItem *item)
{
    QList<QQuickItem *> out;
    for (QQuickItem *child : item->childItems()) {
        out.append(child);
        out.append(allChildren(child));
    }
    return out;
}

int main(int argc, char **argv)
{
    QQuickWindow::setSceneGraphBackend(QStringLiteral("software"));
    QGuiApplication app(argc, argv);
    if (argc != 2)
        return 1;
    QQmlEngine engine;
    QQmlComponent component(&engine, QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1])));
    if (component.status() != QQmlComponent::Ready)
        return 2;
    NetworkFixture observer;
    std::unique_ptr<QObject> root(component.createWithInitialProperties({
        {QStringLiteral("controller"), QVariant::fromValue(&observer)},
    }));
    if (!root || component.isError())
        return 3;
    auto *item = qobject_cast<QQuickItem *>(root.get());
    if (!item || observer.refreshes != 0)
        return 4;
    QQuickWindow window;
    item->setParentItem(window.contentItem());
    item->setWidth(360);
    window.resize(360, 360);
    window.show();
    QCoreApplication::processEvents();

    QQuickItem *refresh = nullptr;
    bool foundUnknown = false;
    bool foundDisclosure = false;
    for (auto *child : allChildren(item)) {
        const QString value = child->property("text").toString();
        auto *accessible = QAccessible::queryAccessibleInterface(child);
        if (value == observer.statusText && accessible &&
            accessible->text(QAccessible::Name) == observer.statusText)
            foundUnknown = true;
        if (value.contains(QStringLiteral("Network changes remain disabled")) && accessible)
            foundDisclosure = true;
        if (child->inherits("QQuickAbstractButton") && value == QLatin1String("Refresh"))
            refresh = child;
    }
    if (!foundUnknown || !foundDisclosure || !refresh || refresh->property("enabled").toBool() ||
        observer.refreshes != 0)
        return 5;
    observer.active = true;
    emit observer.changed();
    QCoreApplication::processEvents();
    if (!refresh->property("enabled").toBool())
        return 6;
    if (!QMetaObject::invokeMethod(refresh, "clicked") || observer.refreshes != 1)
        return 7;
    observer.sourceStatus = QStringLiteral("observed-only");
    observer.statusText =
        QStringLiteral("Current native observation only — connectivity not verified");
    emit observer.changed();
    QCoreApplication::processEvents();
    bool showsUnverified = false;
    for (auto *child : allChildren(item)) {
        if (child->property("text").toString() == observer.statusText)
            showsUnverified = true;
    }
    if (!showsUnverified || observer.refreshes != 1)
        return 8;
    return 0;
}

#include "network_surface.moc"
