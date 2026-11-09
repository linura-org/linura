#include "native_network_credentials.h"
#include "secret_entry.h"

#include <QCoreApplication>
#include <QFocusEvent>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QString>

#include <cstring>
#include <iostream>
#include <stdexcept>

using namespace Linura::SecurityOwner;

namespace {

void check(bool condition)
{
    if (!condition)
        throw std::runtime_error("native S18 secret boundary assertion failed");
}

NativeLockIdentity lock()
{
    const auto value = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:1"));
    check(value.has_value());
    return *value;
}

NativeNetworkCredentialScope scope()
{
    NativeNetworkCredentialScope value;
    value.lock = lock();
    value.principal = QStringLiteral("unix:uid:1000");
    value.operation = QStringLiteral("operation:network.wifi.join");
    value.request = QStringLiteral("request:v010:network-credential:fixture");
    value.originalSender = QStringLiteral(":1.42");
    value.systemBusId = QStringLiteral("fedcba9876543210abcdef0123456789");
    value.networkManagerOwner = QStringLiteral(":1.48");
    value.deviceObject = QStringLiteral("/org/freedesktop/NetworkManager/Devices/3");
    value.deviceInterface = QStringLiteral("wlan0");
    value.deviceIfindex = 3;
    value.networkNamespace = 1024;
    value.profileObject = QStringLiteral("/org/freedesktop/NetworkManager/Settings/9");
    value.profileUuid = QStringLiteral("10203040-5060-7080-90ab-cdef12345678");
    value.profileFingerprint = QString(64, QLatin1Char('a'));
    value.requestDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('1'));
    value.reviewDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('2'));
    value.seat = QStringLiteral("seat0");
    value.settingsVersion = 17;
    return value;
}

NativeNetworkCredentialWitness witness(const NativeNetworkCredentialScope &value)
{
    NativeNetworkCredentialWitness current;
    current.lock = value.lock;
    current.originalSender = value.originalSender;
    current.operation = value.operation;
    current.request = value.request;
    current.systemBusId = value.systemBusId;
    current.networkManagerOwner = value.networkManagerOwner;
    current.deviceObject = value.deviceObject;
    current.deviceInterface = value.deviceInterface;
    current.deviceIfindex = value.deviceIfindex;
    current.networkNamespace = value.networkNamespace;
    current.profileObject = value.profileObject;
    current.profileUuid = value.profileUuid;
    current.profileFingerprint = value.profileFingerprint;
    current.seat = value.seat;
    current.settingsVersion = value.settingsVersion;
    current.activeLogindSession = true;
    current.exactPolkitSubject = true;
    current.protectedHumanConsent = true;
    current.secureCompositor = true;
    return current;
}

NativeNetworkSecretAgentCall call(const NativeNetworkCredentialScope &value)
{
    NativeNetworkSecretAgentCall result;
    result.sender = value.networkManagerOwner;
    result.profileObject = value.profileObject;
    result.settingName = QStringLiteral("802-11-wireless-security");
    result.flags = 0x5; // only user-requested interactive GetSecrets
    result.hints = {QStringLiteral("psk")};
    return result;
}

void secretAgentIngressAdversarial()
{
    const auto current = scope();
    const auto facts = witness(current);
    const auto original = call(current);
    check(original.admissible(current, facts));
    auto zeroOwner = current;
    zeroOwner.networkManagerOwner = QStringLiteral(":1.0");
    check(zeroOwner.valid());
    check(witness(zeroOwner).matches(zeroOwner));
    zeroOwner = current;
    zeroOwner.originalSender = QStringLiteral(":1.0");
    check(zeroOwner.valid());
    auto changed = original;
    changed.sender = QStringLiteral(":1.55");
    check(!changed.admissible(current, facts));
    changed = original;
    changed.sender = current.originalSender;
    check(!changed.admissible(current, facts));
    changed = original;
    changed.profileObject = current.deviceObject;
    check(!changed.admissible(current, facts));
    changed = original;
    changed.settingName = QStringLiteral("vpn");
    check(!changed.admissible(current, facts));
    changed = original;
    changed.flags = 0; // no interaction
    check(!changed.admissible(current, facts));
    changed.flags = 0x1; // no original user request
    check(!changed.admissible(current, facts));
    changed.flags = 0x7; // implicit REQUEST_NEW/replay
    check(!changed.admissible(current, facts));
    changed.flags = 0x85; // unknown flag bits
    check(!changed.admissible(current, facts));
    changed = original;
    changed.hints = {QStringLiteral("wep-key0")};
    check(!changed.admissible(current, facts));
    changed = original;
    changed.hints = {QStringLiteral("psk"), QStringLiteral("psk")};
    check(!changed.admissible(current, facts));
    changed = original;
    changed.hints.clear();
    check(changed.admissible(current, facts));
    auto changedWitness = facts;
    changedWitness.exactPolkitSubject = false;
    check(!original.admissible(current, changedWitness));
}

void scopeAdversarial()
{
    const auto valid = scope();
    check(valid.valid());
    check(witness(valid).matches(valid));
    auto changed = valid;
    changed.persistRequested = true;
    check(!changed.valid());
    changed = valid;
    changed.settingsVersion = 0;
    check(!changed.valid());
    changed = valid;
    changed.principal = QStringLiteral("unix:uid:0");
    check(!changed.valid());
    changed = valid;
    changed.operation = QStringLiteral("operation:network.profile.update");
    check(!changed.valid());
    changed = valid;
    changed.request = QStringLiteral("request:v010:network-credential:wrong--slug");
    check(!changed.valid());
    changed = valid;
    changed.deviceIfindex = 0;
    check(!changed.valid());
    changed = valid;
    changed.networkNamespace = 0;
    check(!changed.valid());
    changed = valid;
    changed.deviceInterface = QStringLiteral("../wlan0");
    check(!changed.valid());
    changed = valid;
    changed.profileUuid = QStringLiteral("00000000-0000-0000-0000-000000000000");
    check(!changed.valid());
    changed = valid;
    changed.originalSender = QStringLiteral("org.freedesktop.NetworkManager");
    check(!changed.valid());
    changed = valid;
    changed.originalSender = valid.networkManagerOwner;
    check(!changed.valid());
    changed = valid;
    changed.systemBusId = QString(32, QLatin1Char('0'));
    check(!changed.valid());
    changed = valid;
    changed.profileFingerprint = QString(64, QLatin1Char('A'));
    check(!changed.valid());
    changed = valid;
    changed.profileObject = QStringLiteral("/org/freedesktop/NetworkManager/Settings/03");
    check(!changed.valid());
    changed = valid;
    changed.deviceObject = QStringLiteral("/org/freedesktop/NetworkManager/AccessPoint/3");
    check(!changed.valid());
    changed = valid;
    changed.seat = QStringLiteral("seat/0");
    check(!changed.valid());
    changed = valid;
    changed.requestDigest = changed.reviewDigest;
    check(!changed.valid());

    auto observed = witness(valid);
    observed.networkManagerOwner = QStringLiteral(":1.49");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.originalSender = QStringLiteral(":1.50");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.settingsVersion += 1;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.deviceIfindex = 7;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.networkNamespace = 1200;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.request = QStringLiteral("request:v010:network-credential:wrong");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.deviceObject = QStringLiteral("/org/freedesktop/NetworkManager/Devices/4");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.profileObject = QStringLiteral("/org/freedesktop/NetworkManager/Settings/10");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.profileFingerprint = QString(64, QLatin1Char('b'));
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.exactPolkitSubject = false;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.protectedHumanConsent = false;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.operation = QStringLiteral("operation:network.wifi.scan");
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.activeLogindSession = false;
    check(!observed.matches(valid));
    observed = witness(valid);
    observed.secureCompositor = false;
    check(!observed.matches(valid));
    observed = witness(valid);
    auto replacement = lock();
    ++replacement.generation;
    observed.lock = replacement;
    check(!observed.matches(valid));
}

void wpaPskTransportAdversarial()
{
    quint64 now = 500;
    const auto current = scope();
    const auto facts = witness(current);
    const auto received = call(current);
    SecretEntry entry;

    const auto attempt = [&](const QString &candidate) {
        NativeNetworkCredentialSession session([&] { return now; });
        check(session.begin(current, facts, received, entry));
        QKeyEvent typed(QEvent::KeyPress, Qt::Key_A, Qt::NoModifier, candidate);
        QCoreApplication::sendEvent(&entry, &typed);
        bool delivered = false;
        const auto deliver = [&](const char *) { delivered = true; };
        const bool accepted = session.submit(current, facts, received, deliver);
        check(accepted == delivered);
        check(session.state() == NativeNetworkCredentialSession::State::Spent);
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        return accepted;
    };
    check(!attempt(QStringLiteral("short")));
    check(!attempt(QString(7, QLatin1Char('a'))));
    check(attempt(QString(8, QLatin1Char('a'))));
    check(attempt(QString(63, QLatin1Char('a'))));
    check(attempt(QString(64, QLatin1Char('a'))));
    check(!attempt(QString(64, QLatin1Char('g'))));
    check(!attempt(QString(65, QLatin1Char('a'))));
    check(!attempt(QString(8, QChar(0x00e9))));
    check(attempt(QStringLiteral("Correct Horse Battery Staple")));
}

void secretOneUse()
{
    quint64 now = 1000;
    NativeNetworkCredentialSession session([&] { return now; });
    SecretEntry entry;
    const auto current = scope();
    const auto facts = witness(current);
    const auto received = call(current);
    check(!session.submit(current, facts, received, [](const char *) {}));
    check(session.state() == NativeNetworkCredentialSession::State::Cancelled);
    // A cancelled instance cannot be resurrected by a new UI event or scope.
    check(!session.begin(current, facts, received, entry));

    NativeNetworkCredentialSession substitutedCall([&] { return now; });
    check(substitutedCall.begin(current, facts, received, entry));
    auto foreignCall = received;
    foreignCall.sender = QStringLiteral(":1.90");
    check(!substitutedCall.submit(current, facts, foreignCall, [](const char *) {}));
    check(!entry.acceptsInput());
    check(substitutedCall.state() == NativeNetworkCredentialSession::State::Cancelled);

    NativeNetworkCredentialSession oneTime([&] { return now; });
    check(oneTime.begin(current, facts, received, entry));
    check(entry.acceptsInput());
    QKeyEvent typed(QEvent::KeyPress, Qt::Key_A, Qt::NoModifier, QStringLiteral("abcdefgh"));
    QCoreApplication::sendEvent(&entry, &typed);
    check(entry.maskedLength() == 8);
    bool observed = false;
    check(oneTime.submit(current, facts, received, [&](const char *value) {
        observed = value && std::strcmp(value, "abcdefgh") == 0;
    }));
    check(observed);
    check(oneTime.state() == NativeNetworkCredentialSession::State::Spent);
    check(entry.maskedLength() == 0 && !entry.acceptsInput());
    check(!oneTime.submit(current, facts, received, [](const char *) {}));
    check(!oneTime.begin(current, facts, received, entry));
}

void noReplayAcrossDeadlineOrOwnerChange()
{
    quint64 now = 100;
    const auto current = scope();
    const auto facts = witness(current);
    const auto received = call(current);
    SecretEntry entry;
    NativeNetworkCredentialSession timed([&] { return now; });
    check(timed.begin(current, facts, received, entry));
    now += NativeNetworkCredentialSession::InputDeadlineMs;
    check(!timed.revalidate(facts));
    check(timed.state() == NativeNetworkCredentialSession::State::Cancelled);
    check(!entry.acceptsInput());
    bool invoked = false;
    check(!timed.submit(current, facts, received, [&](const char *) { invoked = true; }));
    check(!invoked);

    now = 100;
    NativeNetworkCredentialSession substituted([&] { return now; });
    check(substituted.begin(current, facts, received, entry));
    auto changed = facts;
    changed.networkManagerOwner = QStringLiteral(":1.90");
    check(!substituted.revalidate(changed));
    check(substituted.state() == NativeNetworkCredentialSession::State::Cancelled);
    check(!entry.acceptsInput());

    NativeNetworkCredentialSession focusLoss([&] { return now; });
    check(focusLoss.begin(current, facts, received, entry));
    QFocusEvent focusGone(QEvent::FocusOut, Qt::OtherFocusReason);
    QCoreApplication::sendEvent(&entry, &focusGone);
    check(focusLoss.state() == NativeNetworkCredentialSession::State::Cancelled);
    check(!entry.acceptsInput() && entry.maskedLength() == 0);

    NativeNetworkCredentialSession rollback([&] { return now; });
    check(rollback.begin(current, facts, received, entry));
    now = 99; // A monotonic clock rollback is permanently faulting.
    check(!rollback.revalidate(facts));
    check(rollback.state() == NativeNetworkCredentialSession::State::Faulted);
    check(!entry.acceptsInput());
}

} // namespace

int main(int argc, char **argv)
{
    QGuiApplication app(argc, argv);
    try {
        secretAgentIngressAdversarial();
        scopeAdversarial();
        wpaPskTransportAdversarial();
        secretOneUse();
        noReplayAcrossDeadlineOrOwnerChange();
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
