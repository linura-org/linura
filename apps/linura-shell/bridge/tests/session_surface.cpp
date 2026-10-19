// CPU/QML component fixture only. No native input, PAM, policy, executor,
// compositor, pixel baseline or real assistive-technology claim.
#include <QAccessible>
#include <QGuiApplication>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QSet>
#include <iostream>
#include <memory>

class ClientFixture : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy MEMBER busy NOTIFY changed)
    Q_PROPERTY(bool hasPending MEMBER pending NOTIFY changed)
    Q_PROPERTY(QString statusText MEMBER status NOTIFY changed)
    Q_PROPERTY(QString requestId MEMBER requestId NOTIFY changed)
    Q_PROPERTY(QString nativeSleepStatusText MEMBER sleepStatus NOTIFY changed)
  public:
    bool busy = false;
    bool pending = false;
    QString status = QStringLiteral("Component fixture; not authoritative native evidence.");
    QString requestId;
    QString sleepStatus = QStringLiteral(
        "Sleep protection failed; this computer may still be running. Keep it ventilated.");
    QSet<int> actions;
    Q_INVOKABLE void request(int action)
    {
        actions.insert(action);
    }
    Q_INVOKABLE void recover() {}
    Q_INVOKABLE void forgetTracking() {}
  signals:
    void changed();
};

int failure(int code, const char *detail)
{
    std::cerr << "session surface component failed: " << detail << " (" << code << ")\n";
    return code;
}

QList<QQuickItem *> visualDescendants(QQuickItem *root)
{
    QList<QQuickItem *> result;
    // Repeater delegates belong to a QQml context, not necessarily the parent's
    // QObject ownership tree. Inspect the actual visual tree, without weakening
    // the requirement that all five visible controls exist and are accessible.
    for (auto *child : root->childItems()) {
        result.append(child);
        result.append(visualDescendants(child));
    }
    return result;
}

int main(int argc, char **argv)
{
    QQuickWindow::setSceneGraphBackend(QStringLiteral("software"));
    QGuiApplication app(argc, argv);
    if (argc != 2)
        return 1;
    QQmlEngine engine;
    QQmlComponent component(&engine, QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1])));
    if (component.status() != QQmlComponent::Ready) {
        std::cerr << component.errorString().toStdString();
        return failure(2, "the real QML component or its required imports are unavailable");
    }
    ClientFixture controller;
    std::unique_ptr<QObject> root(component.createWithInitialProperties({
        {QStringLiteral("controller"), QVariant::fromValue(&controller)},
    }));
    if (!root || component.isError()) {
        std::cerr << component.errorString().toStdString();
        return 2;
    }
    auto *item = qobject_cast<QQuickItem *>(root.get());
    if (!item || !controller.actions.empty())
        return failure(3, "creation started an action or omitted its item");
    QQuickWindow window;
    item->setParentItem(window.contentItem());
    item->setWidth(320);
    window.resize(320, 900);
    window.show();
    QCoreApplication::processEvents();
    auto *diagnostic = root->findChild<QObject *>(QStringLiteral("nativeSleepDiagnostic"));
    auto *diagnosticAccessible =
        diagnostic ? QAccessible::queryAccessibleInterface(diagnostic) : nullptr;
    if (!diagnostic || diagnostic->property("text").toString() != controller.sleepStatus ||
        !diagnosticAccessible ||
        diagnosticAccessible->text(QAccessible::Name) != controller.sleepStatus)
        return failure(11, "sleep-failure warning or accessible label is missing");
    controller.sleepStatus = QStringLiteral("Diagnostics unavailable; protection not verified.");
    emit controller.changed();
    QCoreApplication::processEvents();
    if (diagnostic->property("text").toString() != controller.sleepStatus ||
        !controller.actions.empty())
        return failure(12, "diagnostic refresh started an effect or retained a stale warning");
    QList<QObject *> actions;
    for (auto *object : visualDescendants(item)) {
        if (!object->inherits("QQuickAbstractButton") || !object->property("visible").toBool())
            continue;
        auto *accessible = QAccessible::queryAccessibleInterface(object);
        if (!accessible || accessible->text(QAccessible::Name).isEmpty())
            return failure(4, "visible button has no accessible name");
        if (!object->property("activeFocusOnTab").toBool())
            return failure(5, "visible button is not keyboard eligible");
        actions.append(object);
        if (!QMetaObject::invokeMethod(object, "clicked"))
            return failure(6, "component click signal failed");
    }
    if (actions.size() != 7 || controller.actions != QSet<int>{0, 1, 2, 3, 4, 5, 6}) {
        std::cerr << "visible actions=" << actions.size()
                  << " typed actions=" << controller.actions.size() << '\n';
        return failure(
            7, "the five exact session/power actions and two consent controls were not presented");
    }
    controller.busy = true;
    emit controller.changed();
    QCoreApplication::processEvents();
    for (const auto *button : actions) {
        if (button->property("enabled").toBool())
            return 8;
    }
    controller.busy = false;
    controller.pending = true;
    controller.requestId = QStringLiteral("request:v010:session-lock:fixture");
    emit controller.changed();
    QCoreApplication::processEvents();
    for (const auto *button : actions) {
        if (button->property("enabled").toBool())
            return 9;
    }
    // Destroy/recreate presentation without starting a request.
    controller.actions.clear();
    root.reset();
    root.reset(component.createWithInitialProperties({
        {QStringLiteral("controller"), QVariant::fromValue(&controller)},
    }));
    if (!root || !controller.actions.empty())
        return 10;
    std::cout << "session surface component actions, labels, keyboard eligibility and "
                 "pending-state checks passed\n";
}

#include "session_surface.moc"
