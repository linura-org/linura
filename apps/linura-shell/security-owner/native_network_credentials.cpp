#include "native_network_credentials.h"
#include "secret_entry.h"

#include <QObject>

#include <cstring>
#include <limits>
#include <utility>

namespace Linura::SecurityOwner {
using Scope = NativeNetworkCredentialScope;
using Witness = NativeNetworkCredentialWitness;

namespace {

bool lowerHex(const QString &value, int count) noexcept
{
    if (value.size() != count)
        return false;
    bool nonzero = false;
    for (const QChar ch : value) {
        const ushort c = ch.unicode();
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
        nonzero |= c != '0';
    }
    return nonzero;
}

bool positiveDecimal(const QString &value) noexcept
{
    if (value.isEmpty() || value.size() > 20 || value.front() == QLatin1Char('0'))
        return false;
    for (const QChar ch : value)
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9'))
            return false;
    bool ok = false;
    const quint64 number = value.toULongLong(&ok);
    return ok && number > 0;
}

bool uniqueName(const QString &value) noexcept
{
    if (!value.startsWith(QLatin1String(":1.")) || value.size() > 96)
        return false;
    const QString sequence = value.mid(3);
    if (sequence.isEmpty() || (sequence.size() > 1 && sequence.front() == QLatin1Char('0')))
        return false;
    for (const QChar ch : sequence)
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9'))
            return false;
    return true; // The D-Bus allocator may legitimately assign :1.0.
}

bool wpaPsk(const char *secret) noexcept
{
    if (!secret)
        return false;
    const std::size_t bytes = std::strlen(secret);
    if (bytes == 64) {
        for (std::size_t index = 0; index < bytes; ++index) {
            const unsigned char c = static_cast<unsigned char>(secret[index]);
            const bool digit = c >= '0' && c <= '9';
            const bool lower = c >= 'a' && c <= 'f';
            const bool upper = c >= 'A' && c <= 'F';
            if (!digit && !lower && !upper)
                return false;
        }
        return true;
    }
    if (bytes < 8 || bytes > 63)
        return false;
    for (std::size_t index = 0; index < bytes; ++index) {
        const unsigned char c = static_cast<unsigned char>(secret[index]);
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

bool nativeObject(const QString &path, const QString &family) noexcept
{
    const QString root = QStringLiteral("/org/freedesktop/NetworkManager/");
    const QString prefix = root + family + QLatin1Char('/');
    if (path.size() > 128 || !path.startsWith(prefix))
        return false;
    return positiveDecimal(path.mid(prefix.size()));
}

bool canonicalSeat(const QString &seat) noexcept
{
    if (!seat.startsWith(QLatin1String("seat")) || seat.size() > 32 || seat.size() < 5)
        return false;
    const auto suffix = seat.mid(4);
    if (suffix.size() > 1 && suffix.front() == QLatin1Char('0'))
        return false;
    for (const QChar ch : suffix)
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9'))
            return false;
    return true;
}

bool digest(const QString &value) noexcept
{
    return value.startsWith(QLatin1String("sha256:")) && lowerHex(value.mid(7), 64);
}

} // namespace

bool NativeNetworkCredentialScope::valid() const noexcept
{
    const auto parsed = NativeLockIdentity::parse(lock.resource);
    if (!parsed || *parsed != lock || lock.uid == 0)
        return false;
    if (principal != QStringLiteral("unix:uid:") + QString::number(lock.uid) ||
        operation != QStringLiteral("operation:network.wifi.join"))
        return false;
    if (!uniqueName(originalSender) || !uniqueName(networkManagerOwner) ||
        originalSender == networkManagerOwner || !lowerHex(systemBusId, 32))
        return false;
    if (!nativeObject(deviceObject, QStringLiteral("Devices")) ||
        !nativeObject(profileObject, QStringLiteral("Settings")))
        return false;
    if (!lowerHex(profileFingerprint, 64) || !digest(requestDigest) || !digest(reviewDigest) ||
        requestDigest == reviewDigest)
        return false;
    return canonicalSeat(seat) && settingsVersion > 0 && !persistRequested;
}

bool NativeNetworkCredentialWitness::matches(const Scope &scope) const noexcept
{
    if (!scope.valid() || lock != scope.lock)
        return false;
    if (originalSender != scope.originalSender || operation != scope.operation ||
        systemBusId != scope.systemBusId)
        return false;
    if (networkManagerOwner != scope.networkManagerOwner || seat != scope.seat)
        return false;
    if (deviceObject != scope.deviceObject || profileObject != scope.profileObject)
        return false;
    if (profileFingerprint != scope.profileFingerprint)
        return false;
    if (settingsVersion != scope.settingsVersion)
        return false;
    return activeLogindSession && exactPolkitSubject && protectedHumanConsent && secureCompositor;
}

bool NativeNetworkSecretAgentCall::admissible(const Scope &scope,
                                              const Witness &witness) const noexcept
{
    if (!witness.matches(scope) || sender != scope.networkManagerOwner ||
        profileObject != scope.profileObject)
        return false;
    // The NM SecretAgent wire contract uses these exact setting/flag names.
    // Requiring 0x1 (ALLOW_INTERACTION) + 0x4 (USER_REQUESTED)
    // refuses passive/system, unsolicited and REQUEST_NEW (0x2) prompts.
    if (settingName != QStringLiteral("802-11-wireless-security") || flags != 0x5)
        return false;
    if (hints.size() > 1)
        return false;
    return hints.isEmpty() || hints.front() == QStringLiteral("psk");
}

NativeNetworkCredentialSession::NativeNetworkCredentialSession(BootClock clock)
    : clock_(std::move(clock))
{
    if (!clock_)
        state_ = State::Faulted;
}

NativeNetworkCredentialSession::~NativeNetworkCredentialSession()
{
    cancel();
}

std::optional<quint64> NativeNetworkCredentialSession::currentTime()
{
    if (!clock_ || state_ == State::Faulted)
        return std::nullopt;
    const auto now = clock_();
    if (now < lastNow_ || now > std::numeric_limits<quint64>::max() - InputDeadlineMs) {
        cancel();
        state_ = State::Faulted;
        return std::nullopt;
    }
    lastNow_ = now;
    if (state_ == State::AwaitingProtectedInput && now >= deadline_) {
        cancel();
        return std::nullopt;
    }
    return now;
}

NativeNetworkCredentialSession::State NativeNetworkCredentialSession::state()
{
    (void)currentTime();
    return state_;
}

bool NativeNetworkCredentialSession::begin(const Scope &scope, const Witness &witness,
                                           const NativeNetworkSecretAgentCall &call,
                                           SecretEntry &entry)
{
    const auto now = currentTime();
    if (!now || state_ != State::Idle || !call.admissible(scope, witness) ||
        !entry.beginNativePrompt(NativePromptKind::Password, 1, scope.lock.uid))
        return false;
    scope_ = scope;
    call_ = call;
    entry_ = &entry;
    deadline_ = *now + InputDeadlineMs;
    state_ = State::AwaitingProtectedInput;
    const auto cancelled = [this] { cancel(); };
    cancellation_ = QObject::connect(&entry, &SecretEntry::cancellationRequested, cancelled);
    destroyed_ = QObject::connect(&entry, &QObject::destroyed, [this] { cancel(); });
    return true;
}

bool NativeNetworkCredentialSession::revalidate(const NativeNetworkCredentialWitness &witness)
{
    if (!currentTime() || state_ != State::AwaitingProtectedInput) {
        cancel();
        return false;
    }
    if (!scope_ || !witness.matches(*scope_) || !entry_) {
        cancel();
        return false;
    }
    return true;
}

bool NativeNetworkCredentialSession::submit(const Scope &scope, const Witness &witness,
                                            const NativeNetworkSecretAgentCall &call,
                                            const NativeConsumer &consumer)
{
    if (!consumer || !revalidate(witness)) {
        cancel();
        return false;
    }
    if (!scope_ || *scope_ != scope || !call_ || *call_ != call) {
        cancel();
        return false;
    }
    if (!call.admissible(scope, witness)) {
        cancel();
        return false;
    }
    // Spend BEFORE native callback. If its target crashes or the reply is
    // ambiguous, there is no retry or transferable credential. The protected
    // SecretEntry/SecretBuffer zeroizes on completion or failure.
    auto *entry = entry_.data();
    detach();
    scope_.reset();
    call_.reset();
    state_ = State::Spent;
    if (!entry)
        return false;
    try {
        bool delivered = false;
        const bool consumed = entry->respondToNativePrompt([&](const char *secret) {
            if (!wpaPsk(secret))
                return;
            consumer(secret);
            delivered = true;
        });
        return consumed && delivered;
    } catch (...) {
        entry->cancelNativePrompt();
        return false;
    }
}

void NativeNetworkCredentialSession::detach() noexcept
{
    QObject::disconnect(cancellation_);
    QObject::disconnect(destroyed_);
    cancellation_ = {};
    destroyed_ = {};
    entry_.clear();
}

void NativeNetworkCredentialSession::cancel()
{
    SecretEntry *entry = entry_.data();
    detach();
    scope_.reset();
    call_.reset();
    deadline_ = 0;
    if (entry)
        entry->cancelNativePrompt();
    if (state_ != State::Faulted && state_ != State::Spent)
        state_ = State::Cancelled;
}

} // namespace Linura::SecurityOwner
