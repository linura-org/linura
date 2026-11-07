#include "native_display_startup_reply.h"
#include <QCoreApplication>
#include <QDBusVirtualObject>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <array>
#include <cassert>
#include <utility>
#include <vector>
#include <unistd.h>

using namespace Linura::SecurityOwner;
namespace {
const QString Service = QStringLiteral("org.linura.Private.ComponentStartup");
const QString Path = QStringLiteral("/org/linura/DisplayProtection1");
const QString Interface = QStringLiteral("org.linura.DisplayProtection1");
class Child final
{
  public:
    QProcess process;
    ~Child()
    {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            (void)process.waitForFinished(2000);
        }
    }
    QString start(const QString &image, const QStringList &arguments)
    {
        process.start(image, arguments);
        assert(process.waitForStarted(2000));
        assert(process.waitForReadyRead(2000));
        const auto output = process.readAllStandardOutput();
        assert(output.size() <= 4096 && output.endsWith('\n') && output.count('\n') == 1);
        return QString::fromUtf8(output).trimmed();
    }
};

class Startup final : public QDBusVirtualObject
{
  public:
    explicit Startup(QDBusConnection attacker) : attacker_(std::move(attacker)) {}
    ~Startup() override
    {
        for (const int value : held_)
            close(value);
    }
    QString introspect(const QString &) const override
    {
        return {};
    }
    bool handleMessage(const QDBusMessage &request, const QDBusConnection &connection) override
    {
        if (request.interface() != Interface)
            return false;
        const auto method = request.member();
        if (method == QLatin1String("Timeout"))
            return true;
        if (method == QLatin1String("Refuse"))
            return connection.send(request.createErrorReply(
                QStringLiteral("org.freedesktop.DBus.Error.Failed"), QString{}));
        if (method == QLatin1String("WrongShape"))
            return connection.send(request.createReply(QList<QVariant>{true}));
        std::array<int, 2> pair{};
        assert((method == QLatin1String("Pipe")
                    ? pipe(pair.data())
                    : socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair.data())) == 0);
        held_.push_back(pair[0]);
        const QDBusUnixFileDescriptor descriptor(pair[1]);
        assert(close(pair[1]) == 0);
        if (method == QLatin1String("Forged")) {
            // Same pending serial, destination and socket credentials, but a
            // foreign bus connection. Only requested replies may be delivered.
            assert(attacker_.send(
                request.createReply(QList<QVariant>{QVariant::fromValue(descriptor), false})));
            const auto barrier = QDBusMessage::createMethodCall(
                QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetId"));
            assert(attacker_.call(barrier, QDBus::Block, 500).type() == QDBusMessage::ReplyMessage);
        }
        return connection.send(
            request.createReply(QList<QVariant>{QVariant::fromValue(descriptor), true}));
    }

  private:
    QDBusConnection attacker_;
    std::vector<int> held_;
};
int serve(QCoreApplication &application, const QString &address)
{
    auto service = QDBusConnection::connectToBus(address, QStringLiteral("startup-service"));
    const auto attacker =
        QDBusConnection::connectToBus(address, QStringLiteral("startup-attacker"));
    assert(service.isConnected() && attacker.isConnected());
    Startup object(attacker);
    assert(service.registerVirtualObject(Path, &object, QDBusConnection::SubPath));
    assert(service.registerService(Service));
    const auto ready = service.baseService().toUtf8() + '\n';
    assert(::write(STDOUT_FILENO, ready.constData(), size_t(ready.size())) == ready.size());
    return application.exec();
}
} // namespace
int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const auto arguments = application.arguments();
    if (arguments.size() == 3 && arguments[1] == QLatin1String("--component-service"))
        return serve(application, arguments[2]);
    assert(arguments.size() == 1);
    QTemporaryDir directory;
    assert(directory.isValid());
    QFile config(directory.path() + QStringLiteral("/bus.conf"));
    assert(config.open(QIODevice::WriteOnly));
    // Match the system bus's requested-reply restriction. Do not include the
    // permissive session policy or host configuration, even when run as root.
    const auto policy =
        (QStringLiteral("<busconfig><type>session</type><auth>EXTERNAL</auth>"
                        "<listen>unix:path=") +
         directory.path().toHtmlEscaped() +
         QStringLiteral("/bus</listen><policy context=\"default\">"
                        "<allow user=\"*\"/><allow own=\"*\"/>"
                        "<allow send_type=\"method_call\"/>"
                        "<allow send_type=\"signal\"/>"
                        "<allow send_requested_reply=\"true\" send_type=\"method_return\"/>"
                        "<allow send_requested_reply=\"true\" send_type=\"error\"/>"
                        "<allow receive_type=\"method_call\"/>"
                        "<allow receive_type=\"method_return\"/>"
                        "<allow receive_type=\"error\"/><allow receive_type=\"signal\"/>"
                        "</policy></busconfig>"))
            .toUtf8();
    assert(config.write(policy) == policy.size());
    config.close();
    Child bus;
    const auto address =
        bus.start(QStringLiteral(LINURA_TEST_DBUS_DAEMON),
                  {QStringLiteral("--nofork"), QStringLiteral("--nopidfile"),
                   QStringLiteral("--nosyslog"), QStringLiteral("--print-address=1"),
                   QStringLiteral("--config-file=") + config.fileName()});
    assert(address.startsWith(QLatin1String("unix:path=")));

    Child service;
    const auto original = service.start(QCoreApplication::applicationFilePath(),
                                        {QStringLiteral("--component-service"), address});
    const auto client = QDBusConnection::connectToBus(address, QStringLiteral("startup-client"));
    assert(client.isConnected());
    const NativePeerIdentity peer{original, 0, static_cast<quint32>(service.process.processId()),
                                  QStringLiteral("component-only")};
    const auto call = [&](const QString &method) {
        return client.call(QDBusMessage::createMethodCall(original, Path, Interface, method),
                           QDBus::Block, 500);
    };
    for (const auto &method : {QStringLiteral("NativeStartup"), QStringLiteral("Forged")}) {
        const auto reply = call(method);
        assert(reply.type() == QDBusMessage::ReplyMessage);
        assert(reply.signature() == QLatin1String("hb"));
        assert(reply.arguments()[1].toBool()); // The forgery supplied false.
        assert(inspectNativeDisplayStartupReply(reply, peer) ==
               (getuid() == 0 ? NativeDisplayStartupReplyFault::None
                              : NativeDisplayStartupReplyFault::KernelPeer));
        auto wrong = peer;
        wrong.uniqueOwner.clear();
        assert(inspectNativeDisplayStartupReply(reply, wrong) ==
               NativeDisplayStartupReplyFault::Sender);
        wrong = peer;
        wrong.uniqueOwner = Service;
        assert(inspectNativeDisplayStartupReply(reply, wrong) ==
               NativeDisplayStartupReplyFault::Sender);
        wrong = peer;
        wrong.pid = 0;
        assert(inspectNativeDisplayStartupReply(reply, wrong) ==
               NativeDisplayStartupReplyFault::KernelPeer);
        wrong = peer;
        wrong.pid = static_cast<quint32>(getpid());
        assert(inspectNativeDisplayStartupReply(reply, wrong) ==
               NativeDisplayStartupReplyFault::KernelPeer);
        wrong = peer;
        wrong.uid = 1000;
        assert(inspectNativeDisplayStartupReply(reply, wrong) ==
               NativeDisplayStartupReplyFault::KernelPeer);
        if (!reply.service().isEmpty()) {
            wrong = peer;
            wrong.uniqueOwner = QStringLiteral(":9.999");
            assert(inspectNativeDisplayStartupReply(reply, wrong) ==
                   NativeDisplayStartupReplyFault::Sender);
        }
        const auto originalLease = reply.arguments()[0];
        auto malformed = reply;
        malformed.setArguments({QStringLiteral("not-a-descriptor"), true});
        assert(inspectNativeDisplayStartupReply(malformed, peer) ==
               NativeDisplayStartupReplyFault::ArgumentTypes);
        malformed.setArguments({originalLease, QStringLiteral("true")});
        assert(inspectNativeDisplayStartupReply(malformed, peer) ==
               NativeDisplayStartupReplyFault::ArgumentTypes);
        malformed.setArguments({originalLease});
        assert(inspectNativeDisplayStartupReply(malformed, peer) ==
               NativeDisplayStartupReplyFault::ArgumentTypes);
    }
    assert(inspectNativeDisplayStartupReply(call(QStringLiteral("Pipe")), peer) ==
           NativeDisplayStartupReplyFault::KernelPeer);
    assert(inspectNativeDisplayStartupReply(call(QStringLiteral("WrongShape")), peer) ==
           NativeDisplayStartupReplyFault::Signature);
    for (const auto &method : {QStringLiteral("Refuse"), QStringLiteral("Timeout")})
        assert(inspectNativeDisplayStartupReply(call(method), peer) ==
               NativeDisplayStartupReplyFault::Sender);
    service.process.kill();
    assert(service.process.waitForFinished(2000));
    Child replacement;
    const auto replaced = replacement.start(QCoreApplication::applicationFilePath(),
                                            {QStringLiteral("--component-service"), address});
    assert(replaced != original);
    // Never follow a well-known service to its replacement for an old lease.
    assert(inspectNativeDisplayStartupReply(call(QStringLiteral("NativeStartup")), peer) ==
           NativeDisplayStartupReplyFault::Sender);
    QDBusConnection::disconnectFromBus(QStringLiteral("startup-client"));
}
