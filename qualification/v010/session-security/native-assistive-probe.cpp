// Read-only real AT-SPI discovery/protocol probe, not a product authority.
#include "native-assistive-denial.h"
#include "native-assistive-discovery.h"
#include "native-assistive-prompt.h"
#include <QCoreApplication>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusVariant>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QThread>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <vector>

namespace {
constexpr auto Root = "/org/a11y/atspi/accessible/root";
constexpr auto Frame = "/org/a11y/atspi/accessible/session";
constexpr auto Input = "/org/a11y/atspi/accessible/response";
constexpr auto Accessible = "org.a11y.atspi.Accessible";
void require(bool condition)
{
    if (!condition)
        throw std::runtime_error("native assistive assertion failed");
}
void suppress(QtMsgType, const QMessageLogContext &, const QString &) {}

class Probe final
{
  public:
    QElapsedTimer budget;
    explicit Probe()
    {
        budget.start();
    }
    QDBusMessage call(const QDBusConnection &bus, const QString &owner, const char *path,
                      const char *interface, const char *member, const QVariantList &arguments = {})
    {
        require(budget.elapsed() < 8'000);
        require(!owner.isEmpty() && owner.size() <= 128);
        if (owner.startsWith(QLatin1Char(':'))) {
            // Unique bus destinations are authenticated by the bus. Qt 6
            // intentionally exposes no reply sender via QDBusMessage::service().
            static const QRegularExpression unique(
                QStringLiteral("^:[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)+$"));
            require(unique.match(owner).hasMatch());
        }
        auto request = QDBusMessage::createMethodCall(owner, QString::fromLatin1(path),
                                                      QString::fromLatin1(interface),
                                                      QString::fromLatin1(member));
        require(request.type() == QDBusMessage::MethodCallMessage && request.service() == owner);
        request.setArguments(arguments);
        const auto reply = bus.call(request, QDBus::Block, 500);
        require(budget.elapsed() < 8'000);
        // Replies are correlated by the bus to the serial and the unique
        // destination. Sender identity is independently checked with registry
        // owner stability and the supervised application's actual PID below.
        // An actual typed remote error can prove unsupported API. A transport
        // timeout/disconnect or local synthesized error is never that evidence.
        require(reply.type() == QDBusMessage::ReplyMessage ||
                reply.type() == QDBusMessage::ErrorMessage);
        if (reply.type() == QDBusMessage::ErrorMessage) {
            const auto failure = nativeAssistiveCallFailure(reply.errorName());
            if (failure != NativeAssistiveCallFailure::None)
                throw failure;
        }
        return reply;
    }
    static QString string(const QDBusMessage &reply)
    {
        require(reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("s") && reply.arguments().size() == 1);
        const auto value = reply.arguments().front().toString();
        require(value.size() <= 256);
        return value;
    }
    static quint32 number(const QDBusMessage &reply)
    {
        require(reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("u") && reply.arguments().size() == 1);
        return reply.arguments().front().toUInt();
    }
    static QStringList strings(const QDBusMessage &reply)
    {
        require(reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("as") && reply.arguments().size() == 1);
        const auto values = reply.arguments().front().toStringList();
        require(values.size() <= 64);
        for (const auto &value : values)
            require(value.size() <= 128);
        return values;
    }
    static std::vector<quint32> states(const QDBusMessage &reply)
    {
        require(reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("au") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>());
        const auto wire = reply.arguments().front().value<QDBusArgument>();
        std::vector<quint32> result;
        wire.beginArray();
        while (!wire.atEnd()) {
            require(result.size() < 4);
            quint32 value = 0;
            wire >> value;
            result.push_back(value);
        }
        wire.endArray();
        return result;
    }
    static std::vector<std::pair<QString, QString>> children(const QDBusMessage &reply)
    {
        require(reply.type() == QDBusMessage::ReplyMessage &&
                reply.signature() == QStringLiteral("a(so)") && reply.arguments().size() == 1 &&
                reply.arguments().front().canConvert<QDBusArgument>());
        const auto wire = reply.arguments().front().value<QDBusArgument>();
        std::vector<std::pair<QString, QString>> result;
        wire.beginArray();
        while (!wire.atEnd()) {
            require(result.size() < 32);
            QString name;
            QDBusObjectPath path;
            wire.beginStructure();
            wire >> name >> path;
            require(wire.atEnd() && name.size() <= 128 && path.path().size() <= 128);
            wire.endStructure();
            result.emplace_back(name, path.path());
        }
        wire.endArray();
        return result;
    }
};
} // namespace

int main(int argc, char **argv)
{
    qInstallMessageHandler(suppress);
    QCoreApplication application(argc, argv);
    int failure = 10;
    try {
        require(argc == 3 && getuid() != 0 && getuid() == geteuid());
        const QString pidText = QString::fromLatin1(argv[1]);
        require(QRegularExpression(QStringLiteral("^[1-9][0-9]{0,9}$")).match(pidText).hasMatch());
        bool valid = false;
        const auto ownerPid = pidText.toUInt(&valid);
        require(valid && ownerPid > 1 && ownerPid < 0x80000000U);
        const QString phase = QString::fromLatin1(argv[2]);
        const bool locked = phase == QStringLiteral("locked");
        const bool unlock = phase == QStringLiteral("unlock-prompt");
        const bool suspend = phase == QStringLiteral("suspend-prompt");
        const bool logout = phase == QStringLiteral("logout-prompt");
        const bool reboot = phase == QStringLiteral("reboot-prompt");
        const bool powerOff = phase == QStringLiteral("power-off-prompt");
        require(locked || unlock || suspend || logout || reboot || powerOff);
        Probe probe;
        failure = 11;
        auto session = QDBusConnection::connectToBus(
            QStringLiteral("unix:path=/run/user/%1/bus").arg(getuid()),
            QStringLiteral("s17-assistive-session"));
        require(session.isConnected());
        const auto address =
            Probe::string(probe.call(session, QStringLiteral("org.a11y.Bus"), "/org/a11y/bus",
                                     "org.a11y.Bus", "GetAddress"));
        const auto pattern =
            QStringLiteral(
                "^unix:path=/run/user/%1/at-spi/bus(?:_[0-9]{1,2})?(?:,guid=[0-9a-f]{32})?$")
                .arg(getuid());
        require(QRegularExpression(pattern).match(address).hasMatch());
        failure = 12;
        auto bus = QDBusConnection::connectToBus(address, QStringLiteral("s17-assistive-native"));
        require(bus.isConnected());
        failure = 14;
        const auto registry = Probe::string(probe.call(
            bus, QStringLiteral("org.freedesktop.DBus"), "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetNameOwner", {QStringLiteral("org.a11y.atspi.Registry")}));
        require(registry.startsWith(QLatin1Char(':')));
        failure = 13;
        QString owner;
        while (probe.budget.elapsed() < 8'000) {
            const auto references =
                Probe::children(probe.call(bus, registry, Root, Accessible, "GetChildren"));
            std::vector<NativeAssistiveApplication> applications;
            for (const auto &[name, path] : references) {
                require(name.startsWith(QLatin1Char(':')));
                const auto pid = Probe::number(
                    probe.call(bus, QStringLiteral("org.freedesktop.DBus"), "/org/freedesktop/DBus",
                               "org.freedesktop.DBus", "GetConnectionUnixProcessID", {name}));
                applications.push_back({name, path, pid});
            }
            const auto discovery = nativeAssistiveApplication(applications, ownerPid);
            require(discovery.valid);
            owner = discovery.owner;
            if (!owner.isEmpty())
                break;
            // Metadata registration is asynchronous. Only absence can be
            // observed again, within the SAME original eight-second budget.
            QThread::msleep(20);
        }
        require(!owner.isEmpty());
        failure = 15;
        require(Probe::number(probe.call(bus, owner, Root, Accessible, "GetRole")) == 75);
        const auto frames =
            Probe::children(probe.call(bus, owner, Root, Accessible, "GetChildren"));
        require(frames ==
                std::vector<std::pair<QString, QString>>{{owner, QString::fromLatin1(Frame)}});
        require(Probe::number(probe.call(bus, owner, Frame, Accessible, "GetRole")) == 16);
        const auto properties = [&](const char *path, const char *key) {
            const auto reply =
                probe.call(bus, owner, path, "org.freedesktop.DBus.Properties", "Get",
                           {QString::fromLatin1(Accessible), QString::fromLatin1(key)});
            require(reply.type() == QDBusMessage::ReplyMessage &&
                    reply.signature() == QStringLiteral("v") && reply.arguments().size() == 1 &&
                    reply.arguments().front().canConvert<QDBusVariant>());
            const auto value = reply.arguments().front().value<QDBusVariant>().variant();
            require(value.metaType().id() == QMetaType::QString && value.toString().size() <= 256);
            return value.toString();
        };
        require(properties(Root, "Name") == QStringLiteral("Linura protected session"));
        failure = 16;
        const auto fields =
            Probe::children(probe.call(bus, owner, Frame, Accessible, "GetChildren"));
        std::optional<QJsonObject> nativePrompt;
        QString observedPrompt;
        if (locked) {
            require(fields.empty() &&
                    properties(Frame, "Name") == QStringLiteral("Session locked"));
        } else {
            require(fields ==
                    std::vector<std::pair<QString, QString>>{{owner, QString::fromLatin1(Input)}});
            require(Probe::number(probe.call(bus, owner, Input, Accessible, "GetRole")) == 40);
            QString expectedHeading;
            if (unlock)
                expectedHeading = QStringLiteral("Authenticate to unlock");
            else if (suspend)
                expectedHeading = QStringLiteral("Authorize suspend");
            else if (logout)
                expectedHeading = QStringLiteral("Authorize logout");
            else if (reboot)
                expectedHeading = QStringLiteral("Authorize restart");
            else
                expectedHeading = QStringLiteral("Authorize shutdown");
            require(properties(Frame, "Name") == expectedHeading);
            observedPrompt = properties(Input, "Name");
            nativePrompt = nativeAssistivePrompt(observedPrompt, unlock, getuid());
            require(nativePrompt.has_value());
            // Polkit supplies eligible administrator identities. A session owner
            // may itself be an administrator; UID inequality is not authority.
            const auto state = Probe::states(probe.call(bus, owner, Input, Accessible, "GetState"));
            // AT-SPI focused bit. The native model publishes it only while the
            // protected entry is both accepting and natively focused.
            require(state.size() == 2 && (state[0] & (1U << 12)) != 0);
        }
        failure = 17;
        const auto interfaces =
            Probe::strings(probe.call(bus, owner, Input, Accessible, "GetInterfaces"));
        require(interfaces == QStringList{QString::fromLatin1(Accessible)});
        const auto originalName = properties(Input, "Name");
        require(locked || originalName == observedPrompt);
        const auto unsupported = [&](const char *interface, const char *method,
                                     const QVariantList &arguments) {
            const auto reply = probe.call(bus, owner, Input, interface, method, arguments);
            // GIO 2.80 rejects a known read-only property with InvalidArgs
            // before its setter is called. Do not admit that error for action
            // or edit requests: it could only demonstrate malformed arguments.
            // The property exists (read above), this fixed request uses (ssv),
            // the destination is pinned to the supervised application's unique
            // connection, and its value must
            // remain unchanged below. No localized error text is trusted.
            const bool readOnlyProperty =
                std::strcmp(interface, "org.freedesktop.DBus.Properties") == 0 &&
                std::strcmp(method, "Set") == 0;
            require(reply.type() == QDBusMessage::ErrorMessage &&
                    nativeAssistiveDenial(reply.errorName(), readOnlyProperty));
        };
        failure = 18;
        unsupported("org.a11y.atspi.Action", "DoAction", {0});
        unsupported("org.a11y.atspi.EditableText", "SetTextContents",
                    {QStringLiteral("not-an-authentication-response")});
        unsupported(
            "org.freedesktop.DBus.Properties", "Set",
            {QString::fromLatin1(Accessible), QStringLiteral("Name"),
             QVariant::fromValue(QDBusVariant(QStringLiteral("cannot-relabel-protected-prompt")))});
        require(properties(Input, "Name") == originalName);
        failure = 19;
        require(Probe::string(probe.call(bus, QStringLiteral("org.freedesktop.DBus"),
                                         "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                         "GetNameOwner",
                                         {QStringLiteral("org.a11y.atspi.Registry")})) == registry);
        QJsonObject checks{{"registry-discovers-actual-native-owner", true},
                           {"typed-protected-presentation-tree", true},
                           {"no-text-value-editable-action-or-geometry-interface", true},
                           {"remote-input-and-relabel-methods-rejected", true}};
        QJsonObject report{{"schema_version", 1},
                           {"claim", "native-assistive-metadata-cases-only"},
                           {"phase", phase},
                           {"native_owner_pid", qint64(ownerPid)},
                           {"checks", checks},
                           {"s17_complete", false},
                           {"release_support_promotion", false}};
        if (!locked && !unlock)
            report.insert(QStringLiteral("native_prompt"), *nativePrompt);
        const auto output = QJsonDocument(report).toJson(QJsonDocument::Compact);
        require(std::fwrite(output.constData(), 1, static_cast<std::size_t>(output.size()),
                            stdout) == static_cast<std::size_t>(output.size()));
        return 0;
    } catch (NativeAssistiveCallFailure callFailure) {
        failure = static_cast<int>(callFailure);
    } catch (...) {
    }
    std::fputs("native assistive qualification failed; no positive evidence\n", stderr);
    return failure;
}
