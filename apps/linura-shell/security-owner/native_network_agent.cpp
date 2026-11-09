#include "native_network_agent.h"

#include "native_approval.h"
#include "secret_entry.h"
#include "session_bootstrap.h"

#include <QCryptographicHash>
#include <QDBusArgument>
#include <QDBusMetaType>
#include <QDBusReply>
#include <QDBusVariant>
#include <QFile>
#include <QThread>

#include <sys/stat.h>

#include <utility>

namespace Linura::SecurityOwner {
namespace {

constexpr int BusDeadlineMs = 500;
const QString AgentError = QStringLiteral("org.freedesktop.NetworkManager.SecretAgent.Error.");
const QString Setting = QStringLiteral("802-11-wireless-security");

QDBusMessage nativeCall(const QDBusConnection &bus, const QString &owner, const QString &path,
                        const QString &interface, const QString &method,
                        const QList<QVariant> &arguments = {})
{
    auto request = QDBusMessage::createMethodCall(owner, path, interface, method);
    request.setAutoStartService(false);
    request.setArguments(arguments);
    return bus.call(request, QDBus::Block, BusDeadlineMs);
}

QVariant unwrapped(const QVariant &value)
{
    if (value.metaType() == QMetaType::fromType<QDBusVariant>())
        return value.value<QDBusVariant>().variant();
    return value;
}

std::optional<QString> stringSetting(const QVariantMap &fields, const QString &key)
{
    if (!fields.contains(key))
        return std::nullopt;
    const auto value = unwrapped(fields.value(key));
    if (value.metaType() != QMetaType::fromType<QString>() ||
        value.toString().toUtf8().size() > 512)
        return std::nullopt;
    return value.toString();
}

std::optional<quint32> flagSetting(const QVariantMap &fields, const QString &key)
{
    if (!fields.contains(key))
        return std::nullopt;
    const auto value = unwrapped(fields.value(key));
    if (value.metaType() != QMetaType::fromType<quint32>())
        return std::nullopt;
    return value.toUInt();
}

std::optional<QByteArray> bytesSetting(const QVariantMap &fields, const QString &key)
{
    if (!fields.contains(key))
        return std::nullopt;
    const auto value = unwrapped(fields.value(key));
    if (value.metaType() != QMetaType::fromType<QByteArray>())
        return std::nullopt;
    return value.toByteArray();
}

bool bounded(const NativeNmSettings &settings)
{
    if (settings.isEmpty() || settings.size() > 48)
        return false;
    for (auto section = settings.cbegin(); section != settings.cend(); ++section) {
        if (section.key().isEmpty() || section.key().size() > 96)
            return false;
        if (section.value().size() > 64)
            return false;
        const auto sectionName = section.key().toLatin1();
        if (sectionName.size() != section.key().size())
            return false;
        for (const char ch : sectionName)
            if (!(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
                !(ch >= '0' && ch <= '9') && ch != '-')
                return false;
        for (auto field = section.value().cbegin(); field != section.value().cend(); ++field) {
            if (field.key().isEmpty() || field.key().size() > 96)
                return false;
            const auto name = field.key().toLatin1();
            if (name.size() != field.key().size())
                return false;
            for (const char ch : name)
                if (!(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
                    !(ch >= '0' && ch <= '9') && ch != '-')
                    return false;
        }
    }
    return true;
}

void addSize(QCryptographicHash &hash, quint32 count)
{
    char bytes[4];
    for (int shift = 0; shift < 4; ++shift)
        bytes[shift] = static_cast<char>((count >> (shift * 8)) & 0xff);
    hash.addData(QByteArrayView(bytes, 4));
}

// Identical normalization and domain separation to S18-2's read-only Rust
// profile_fingerprint. Only nonsecret allowlisted fields enter this digest.
std::optional<QString> fingerprint(const NativeNmSettings &settings, const QString &expectedUuid)
{
    if (!bounded(settings) || !settings.contains(QStringLiteral("connection")))
        return std::nullopt;
    const auto &connection = settings.value(QStringLiteral("connection"));
    const auto uuid = stringSetting(connection, QStringLiteral("uuid"));
    const auto type = stringSetting(connection, QStringLiteral("type"));
    if (!uuid || !type)
        return std::nullopt;
    if (*uuid != expectedUuid || *type != QStringLiteral("802-11-wireless"))
        return std::nullopt;
    QMap<QString, QByteArray> projection;
    projection.insert(QStringLiteral("connection.uuid"), uuid->toUtf8());
    projection.insert(QStringLiteral("connection.type"), type->toUtf8());
    const auto includeText = [&](const QString &sectionName, const QString &fieldName) {
        const auto section = settings.constFind(sectionName);
        if (section == settings.cend() || !section.value().contains(fieldName))
            return true;
        const auto value = stringSetting(section.value(), fieldName);
        if (!value)
            return false;
        if (sectionName == QLatin1String("connection") &&
            fieldName == QLatin1String("interface-name")) {
            if (value->isEmpty() || value->size() > 15)
                return false;
            if (*value == QLatin1String(".") || *value == QLatin1String(".."))
                return false;
            for (const QChar letter : *value) {
                const ushort ch = letter.unicode();
                const bool lower = ch >= 'a' && ch <= 'z';
                const bool upper = ch >= 'A' && ch <= 'Z';
                const bool digit = ch >= '0' && ch <= '9';
                if (!lower && !upper && !digit && ch != '_' && ch != '-' && ch != '.')
                    return false;
            }
        }
        projection.insert(sectionName + QLatin1Char('.') + fieldName, value->toUtf8());
        return true;
    };
    if (!includeText(QStringLiteral("connection"), QStringLiteral("interface-name")))
        return std::nullopt;
    if (!includeText(QStringLiteral("ipv4"), QStringLiteral("method")))
        return std::nullopt;
    if (!includeText(QStringLiteral("ipv6"), QStringLiteral("method")))
        return std::nullopt;
    if (!includeText(QStringLiteral("802-11-wireless"), QStringLiteral("mode")))
        return std::nullopt;
    if (connection.contains(QStringLiteral("autoconnect"))) {
        const auto value = unwrapped(connection.value(QStringLiteral("autoconnect")));
        if (value.metaType() != QMetaType::fromType<bool>())
            return std::nullopt;
        projection.insert(QStringLiteral("connection.autoconnect"),
                          QByteArray(1, value.toBool() ? '\x01' : '\x00'));
    }
    const auto wifi = settings.constFind(QStringLiteral("802-11-wireless"));
    if (wifi != settings.cend() && wifi.value().contains(QStringLiteral("ssid"))) {
        const auto ssid = bytesSetting(wifi.value(), QStringLiteral("ssid"));
        if (!ssid || ssid->isEmpty() || ssid->size() > 32)
            return std::nullopt;
        projection.insert(QStringLiteral("802-11-wireless.ssid"), *ssid);
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    constexpr char domain[] = "linura-s18-profile-projection-v1";
    hash.addData(QByteArrayView(domain, sizeof(domain))); // NUL-terminated.
    for (auto it = projection.cbegin(); it != projection.cend(); ++it) {
        const auto name = it.key().toUtf8();
        addSize(hash, static_cast<quint32>(name.size()));
        hash.addData(name);
        addSize(hash, static_cast<quint32>(it.value().size()));
        hash.addData(it.value());
    }
    return QString::fromLatin1(hash.result().toHex());
}

bool isNotSavedWpa(const NativeNmSettings &settings)
{
    const auto security = settings.constFind(Setting);
    if (security == settings.cend() || security.value().contains(QStringLiteral("psk")))
        return false;
    const auto management = stringSetting(security.value(), QStringLiteral("key-mgmt"));
    const auto flags = flagSetting(security.value(), QStringLiteral("psk-flags"));
    return management == QStringLiteral("wpa-psk") && flags == 2U;
}

std::optional<quint64> propertyVersion(const QDBusConnection &bus, const QString &owner)
{
    const QString path = QStringLiteral("/org/freedesktop/NetworkManager/Settings");
    const QString interface = QStringLiteral("org.freedesktop.DBus.Properties");
    const QString method = QStringLiteral("Get");
    const QList<QVariant> arguments = {QStringLiteral("org.freedesktop.NetworkManager.Settings"),
                                       QStringLiteral("VersionId")};
    const QDBusReply<QDBusVariant> result(
        nativeCall(bus, owner, path, interface, method, arguments));
    if (!result.isValid())
        return std::nullopt;
    if (result.value().variant().metaType() != QMetaType::fromType<quint64>())
        return std::nullopt;
    return result.value().variant().toULongLong();
}

bool containsNativePath(const QDBusMessage &reply, const QString &wanted)
{
    if (reply.type() != QDBusMessage::ReplyMessage || reply.signature() != QLatin1String("ao") ||
        reply.arguments().size() != 1)
        return false;
    const auto paths = qdbus_cast<QList<QDBusObjectPath>>(reply.arguments().front());
    if (paths.size() > 128)
        return false;
    int matches = 0;
    for (const auto &path : paths)
        matches += path.path() == wanted;
    return matches == 1;
}

} // namespace

std::optional<QString> nativeProfileFingerprint(const NativeNmSettings &settings,
                                                const QString &profileUuid)
{
    return fingerprint(settings, profileUuid);
}

bool nativeOneTimeWpaProfile(const NativeNmSettings &settings, const QString &profileUuid,
                             const QString &expectedFingerprint)
{
    return isNotSavedWpa(settings) && fingerprint(settings, profileUuid) == expectedFingerprint;
}

void NativeNetworkSecretAgent::registerWireTypes()
{
    qDBusRegisterMetaType<NativeNmSettings>();
    qDBusRegisterMetaType<QList<QDBusObjectPath>>();
}

QString NativeNetworkSecretAgent::objectPath()
{
    return QStringLiteral("/org/freedesktop/NetworkManager/SecretAgent");
}

NativeNetworkSecretAgent::NativeNetworkSecretAgent(PeerGuard &peers, SecretEntry &entry,
                                                   Witness witness, Presentation presentation,
                                                   QObject *parent)
    : QObject(parent), peers_(peers), entry_(entry), witness_(std::move(witness)),
      presentation_(std::move(presentation))
{
    // Listen on the actual root-controlled system bus, not an ambient user
    // session bus. A daemon name replacement invalidates every armed prompt.
    // Slot connection is required; an unobserved replacement must not pass.
    expiry_.setSingleShot(true);
    expiry_.setInterval(30'000);
    connect(&expiry_, &QTimer::timeout, this, [this] { retire(QStringLiteral("AgentCanceled")); });
    connect(&entry_, &SecretEntry::submissionRequested, this, &NativeNetworkSecretAgent::deliver);
    connect(&entry_, &SecretEntry::cancellationRequested, this, [this] {
        if (pending_)
            retire(QStringLiteral("UserCanceled"));
    });
}

NativeNetworkSecretAgent::~NativeNetworkSecretAgent()
{
    cancel();
}

bool NativeNetworkSecretAgent::active() const noexcept
{
    return registered_ && scope_.has_value() && manager_.has_value();
}

void NativeNetworkSecretAgent::nativeNameOwnerChanged(const QString &name, const QString &oldOwner,
                                                      const QString &newOwner)
{
    if (!scope_ || retiring_)
        return;
    if (name == QLatin1String("org.freedesktop.NetworkManager") &&
        (oldOwner != scope_->networkManagerOwner || newOwner != oldOwner))
        retire(QStringLiteral("AgentCanceled"));
    else if (name == QLatin1String("org.freedesktop.login1"))
        retire(QStringLiteral("AgentCanceled"));
}

bool NativeNetworkSecretAgent::arm(const NativeNetworkCredentialScope &scope,
                                   const NativePeerIdentity &manager)
{
    if (QThread::currentThread() != thread() || active() || registered_ || pending_ ||
        !scope.valid() || !witness_ || !presentation_ || manager.uid != 0 ||
        manager.uniqueOwner != scope.networkManagerOwner ||
        !peers_.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, manager))
        return false;
    scope_ = scope;
    manager_ = manager;
    auto bus = peers_.nativeConnection(); // Mutable shared connection handle.
    const bool watching =
        bus.connect(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                    QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameOwnerChanged"),
                    this, SLOT(nativeNameOwnerChanged(QString, QString, QString)));
    if (!watching) {
        cancel();
        return false;
    }
    session_ =
        std::make_unique<NativeNetworkCredentialSession>(NativeApproval::nativeBootTimeClock());
    if (!live() || !bus.registerObject(objectPath(), this, QDBusConnection::ExportAllSlots)) {
        cancel();
        return false;
    }
    const QDBusMessage result =
        nativeCall(peers_.nativeConnection(), manager.uniqueOwner,
                   QStringLiteral("/org/freedesktop/NetworkManager/AgentManager"),
                   QStringLiteral("org.freedesktop.NetworkManager.AgentManager"),
                   QStringLiteral("RegisterWithCapabilities"),
                   {QStringLiteral("org.linura.protected-network"), quint32(0)});
    if (result.type() != QDBusMessage::ReplyMessage || !result.arguments().isEmpty()) {
        cancel();
        return false;
    }
    registered_ = true;
    if (!live()) {
        cancel();
        return false;
    }
    expiry_.start();
    return true;
}

bool NativeNetworkSecretAgent::originalSessionSeat() const
{
    if (!scope_)
        return false;
    const auto &bus = peers_.nativeConnection();
    const QDBusReply<QString> owner(
        nativeCall(bus, QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("GetNameOwner"), {QStringLiteral("org.freedesktop.login1")}));
    if (!owner.isValid())
        return false;
    const QDBusReply<quint32> uid(
        nativeCall(bus, QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("GetConnectionUnixUser"), {owner.value()}));
    if (!uid.isValid() || uid.value() != 0)
        return false;
    const QDBusReply<QDBusObjectPath> session(
        nativeCall(bus, owner.value(), QStringLiteral("/org/freedesktop/login1"),
                   QStringLiteral("org.freedesktop.login1.Manager"), QStringLiteral("GetSession"),
                   {scope_->lock.session}));
    if (!session.isValid() ||
        !session.value().path().startsWith(QLatin1String("/org/freedesktop/login1/session/")))
        return false;
    const QDBusReply<QDBusVariant> seat(
        nativeCall(bus, owner.value(), session.value().path(),
                   QStringLiteral("org.freedesktop.DBus.Properties"), QStringLiteral("Get"),
                   {QStringLiteral("org.freedesktop.login1.Session"), QStringLiteral("Seat")}));
    const auto identity =
        seat.isValid() ? decodeNativeLogindSeat(seat.value().variant()) : std::nullopt;
    const QDBusReply<QString> fresh(
        nativeCall(bus, QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
                   QStringLiteral("GetNameOwner"), {QStringLiteral("org.freedesktop.login1")}));
    return identity && identity->name == scope_->seat && fresh.isValid() &&
           fresh.value() == owner.value();
}

bool NativeNetworkSecretAgent::profileMatches() const
{
    if (!scope_ || !manager_)
        return false;
    const auto &bus = peers_.nativeConnection();
    const auto &owner = manager_->uniqueOwner;
    const QDBusReply<QString> busId(nativeCall(
        bus, QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
        QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetId")));
    const auto before = propertyVersion(bus, owner);
    if (!busId.isValid() || busId.value() != scope_->systemBusId || !before ||
        *before != scope_->settingsVersion)
        return false;
    if (!containsNativePath(nativeCall(bus, owner,
                                       QStringLiteral("/org/freedesktop/NetworkManager"),
                                       QStringLiteral("org.freedesktop.NetworkManager"),
                                       QStringLiteral("GetDevices")),
                            scope_->deviceObject) ||
        !containsNativePath(nativeCall(bus, owner,
                                       QStringLiteral("/org/freedesktop/NetworkManager/Settings"),
                                       QStringLiteral("org.freedesktop.NetworkManager.Settings"),
                                       QStringLiteral("ListConnections")),
                            scope_->profileObject))
        return false;
    const QDBusReply<QDBusVariant> device(nativeCall(
        bus, owner, scope_->deviceObject, QStringLiteral("org.freedesktop.DBus.Properties"),
        QStringLiteral("Get"),
        {QStringLiteral("org.freedesktop.NetworkManager.Device"), QStringLiteral("Interface")}));
    if (!device.isValid() ||
        device.value().variant().metaType() != QMetaType::fromType<QString>() ||
        device.value().variant().toString() != scope_->deviceInterface)
        return false;
    const QDBusReply<QDBusVariant> deviceType(nativeCall(
        bus, owner, scope_->deviceObject, QStringLiteral("org.freedesktop.DBus.Properties"),
        QStringLiteral("Get"),
        {QStringLiteral("org.freedesktop.NetworkManager.Device"), QStringLiteral("DeviceType")}));
    if (!deviceType.isValid() ||
        deviceType.value().variant().metaType() != QMetaType::fromType<quint32>() ||
        deviceType.value().variant().toUInt() != 2U) // NM_DEVICE_TYPE_WIFI
        return false;
    struct stat namespaceFacts
    {};
    if (stat("/proc/self/ns/net", &namespaceFacts) != 0 ||
        static_cast<quint64>(namespaceFacts.st_ino) != scope_->networkNamespace)
        return false;
    QFile indexFile(QStringLiteral("/sys/class/net/%1/ifindex").arg(scope_->deviceInterface));
    if (!indexFile.open(QIODevice::ReadOnly))
        return false;
    const QByteArray ifindex = indexFile.read(32).trimmed();
    bool ok = false;
    const auto observed = ifindex.toUInt(&ok);
    if (!ok || observed != scope_->deviceIfindex)
        return false;
    const QDBusReply<NativeNmSettings> settings(
        nativeCall(bus, owner, scope_->profileObject,
                   QStringLiteral("org.freedesktop.NetworkManager.Settings.Connection"),
                   QStringLiteral("GetSettings")));
    if (!settings.isValid() ||
        !nativeOneTimeWpaProfile(settings.value(), scope_->profileUuid,
                                 scope_->profileFingerprint) ||
        propertyVersion(bus, owner) != before)
        return false;
    if (stat("/proc/self/ns/net", &namespaceFacts) != 0 ||
        static_cast<quint64>(namespaceFacts.st_ino) != scope_->networkNamespace)
        return false;
    return peers_.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, *manager_);
}

bool NativeNetworkSecretAgent::live() const
{
    if (!scope_ || !manager_ || !witness_ ||
        !peers_.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, *manager_))
        return false;
    const auto checked = witness_(*scope_);
    return checked && checked->matches(*scope_) && originalSessionSeat() && profileMatches();
}

bool NativeNetworkSecretAgent::requestSettingsSafe(const NativeNmSettings &connection) const
{
    if (!scope_ ||
        !nativeOneTimeWpaProfile(connection, scope_->profileUuid, scope_->profileFingerprint))
        return false;
    // The incoming GetSecrets settings map may include unrelated nonsecret
    // profile properties, but no inline PSK or EAP credential is ever admitted.
    for (auto section = connection.cbegin(); section != connection.cend(); ++section)
        for (auto field = section.value().cbegin(); field != section.value().cend(); ++field)
            if (field.key().contains(QLatin1String("password"), Qt::CaseInsensitive) ||
                field.key().contains(QLatin1String("secret"), Qt::CaseInsensitive) ||
                field.key() == QStringLiteral("psk"))
                return false;
    return true;
}

void NativeNetworkSecretAgent::GetSecrets(const NativeNmSettings &connection,
                                          const QDBusObjectPath &connectionPath,
                                          const QString &settingName, const QStringList &hints,
                                          quint32 flags)
{
    if (!calledFromDBus() || pending_ || !registered_ || !scope_ || !manager_ || !session_) {
        if (calledFromDBus())
            sendErrorReply(AgentError + QStringLiteral("NotAuthorized"));
        return;
    }
    const NativeNetworkSecretAgentCall call{message().service(), connectionPath.path(), settingName,
                                            hints, flags};
    const auto current = witness_(*scope_);
    if (!current || !call.admissible(*scope_, *current) || !requestSettingsSafe(connection) ||
        !live()) {
        sendErrorReply(AgentError + QStringLiteral("NotAuthorized"));
        retire(QStringLiteral("AgentCanceled"));
        return;
    }
    presentation_(true);
    if (!session_->begin(*scope_, *current, call, entry_)) {
        sendErrorReply(AgentError + QStringLiteral("AgentCanceled"));
        retire(QStringLiteral("AgentCanceled"));
        return;
    }
    call_ = call;
    pending_ = message();
    setDelayedReply(true);
}

void NativeNetworkSecretAgent::deliver()
{
    if (!pending_ || !scope_ || !call_ || !session_)
        return;
    const auto current = witness_(*scope_);
    if (!current || !live()) {
        retire(QStringLiteral("AgentCanceled"));
        return;
    }
    bool sent = false;
    const bool consumed = session_->submit(*scope_, *current, *call_, [&](const char *password) {
        // The actual D-Bus wire necessarily holds an ephemeral serialized
        // secret. It is never placed in QML, Control, persistent storage,
        // messages, diagnostics or a native reusable credential holder.
        NativeNmSettings response;
        QVariantMap security;
        security.insert(QStringLiteral("name"), Setting);
        security.insert(QStringLiteral("psk"), QString::fromLatin1(password));
        response.insert(Setting, security);
        sent = peers_.nativeConnection().send(pending_->createReply(QVariant::fromValue(response)));
    });
    if (consumed && sent)
        pending_.reset();
    retire(QStringLiteral("AgentCanceled"));
}

void NativeNetworkSecretAgent::CancelGetSecrets(const QDBusObjectPath &connectionPath,
                                                const QString &settingName)
{
    if (!calledFromDBus() || !scope_ || !manager_ || message().service() != manager_->uniqueOwner) {
        if (calledFromDBus())
            sendErrorReply(AgentError + QStringLiteral("NotAuthorized"));
        return;
    }
    if (pending_ && call_ && call_->profileObject == connectionPath.path() &&
        call_->settingName == settingName)
        retire(QStringLiteral("AgentCanceled"));
}

void NativeNetworkSecretAgent::SaveSecrets(const NativeNmSettings &, const QDBusObjectPath &)
{
    if (calledFromDBus())
        sendErrorReply(AgentError + QStringLiteral("NotAuthorized"));
}

void NativeNetworkSecretAgent::DeleteSecrets(const NativeNmSettings &, const QDBusObjectPath &)
{
    if (calledFromDBus())
        sendErrorReply(AgentError + QStringLiteral("NotAuthorized"));
}

void NativeNetworkSecretAgent::retire(const QString &error)
{
    if (retiring_)
        return;
    retiring_ = true;
    expiry_.stop();
    if (session_)
        session_->cancel();
    if (pending_) {
        (void)peers_.nativeConnection().send(
            pending_->createErrorReply(AgentError + error, QString()));
        pending_.reset();
    }
    call_.reset();
    if (registered_ && manager_) {
        auto request = QDBusMessage::createMethodCall(
            manager_->uniqueOwner, QStringLiteral("/org/freedesktop/NetworkManager/AgentManager"),
            QStringLiteral("org.freedesktop.NetworkManager.AgentManager"),
            QStringLiteral("Unregister"));
        request.setAutoStartService(false);
        (void)peers_.nativeConnection().asyncCall(request, BusDeadlineMs);
    }
    registered_ = false;
    auto bus = peers_.nativeConnection();
    bus.disconnect(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                   QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameOwnerChanged"), this,
                   SLOT(nativeNameOwnerChanged(QString, QString, QString)));
    bus.unregisterObject(objectPath());
    session_.reset();
    manager_.reset();
    scope_.reset();
    presentation_(false);
    retiring_ = false;
}

void NativeNetworkSecretAgent::cancel()
{
    retire(QStringLiteral("AgentCanceled"));
}

} // namespace Linura::SecurityOwner
