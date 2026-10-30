#include "native_scope.h"
#include "native_display_layout.h"

#include <QCryptographicHash>
#include <QtEndian>
#include <QStringView>
#include <QStringList>
#include <QUuid>

#include <limits>
#include <algorithm>

namespace Linura::SecurityOwner {
namespace {

bool uuid(const QString &text)
{
    if (text.size() != 36)
        return false;
    const QUuid value(text);
    return !value.isNull() && value.toString(QUuid::WithoutBraces) == text;
}

bool decimal(const QString &text, quint64 *result)
{
    if (text.isEmpty() || text.size() > 20 || (text.size() > 1 && text[0] == QLatin1Char('0')))
        return false;
    for (QChar character : text) {
        if (character < QLatin1Char('0') || character > QLatin1Char('9'))
            return false;
    }
    bool ok = false;
    *result = text.toULongLong(&ok);
    return ok;
}

bool canonicalSessionId(QStringView text)
{
    for (QChar character : text) {
        const ushort code = character.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9') || code == '_' || code == '-'))
            return false;
    }
    return true;
}

bool digest(const QString &text)
{
    if (text.size() != 71 || !text.startsWith(QLatin1String("sha256:")))
        return false;
    for (QChar character : QStringView(text).mid(7)) {
        if (!((character >= QLatin1Char('0') && character <= QLatin1Char('9')) ||
              (character >= QLatin1Char('a') && character <= QLatin1Char('f'))))
            return false;
    }
    return true;
}

} // namespace

std::optional<NativeLockIdentity> NativeLockIdentity::parse(const QString &resource)
{
    // Bound before splitting. Reject aliases and old invocation-less identities,
    // rather than normalizing them into an existing approval's scope.
    if (resource.size() > 256)
        return std::nullopt;
    const auto fields = resource.split(QLatin1Char(':'));
    if (fields.size() != 8 || fields[0] != QLatin1String("session") ||
        fields[1] != QLatin1String("lock") || !uuid(fields[2]) || !uuid(fields[6]) ||
        fields[4].isEmpty() || fields[4].size() > 64 || !canonicalSessionId(fields[4]))
        return std::nullopt;
    if (fields[4] == QLatin1String("self") || fields[4] == QLatin1String("auto") ||
        fields[4] == QLatin1String("current"))
        return std::nullopt;
    quint64 uid = 0, created = 0, generation = 0;
    if (!decimal(fields[3], &uid) || uid == 0 || uid > std::numeric_limits<quint32>::max() ||
        !decimal(fields[5], &created) || created == 0 || !decimal(fields[7], &generation) ||
        generation == 0)
        return std::nullopt;
    return NativeLockIdentity{resource,  fields[2], static_cast<quint32>(uid), fields[4], created,
                              fields[6], generation};
}

bool NativeLockIdentity::wasRetiredBy(const NativeLockIdentity &current) const
{
    const auto oldParsed = parse(resource);
    const auto currentParsed = parse(current.resource);
    return oldParsed && *oldParsed == *this && currentParsed && *currentParsed == current &&
           boot == current.boot && uid == current.uid && session == current.session &&
           createdMonotonicUs == current.createdMonotonicUs &&
           ownerInvocation == current.ownerInvocation && generation < current.generation;
}

std::optional<NativeTransitionIdentity> NativeTransitionIdentity::parse(const QString &resource)
{
    if (resource.size() > 256)
        return std::nullopt;
    const auto fields = resource.split(QLatin1Char(':'));
    if (fields.size() != 10 || fields[0] != QLatin1String("session") ||
        fields[1] != QLatin1String("transition"))
        return std::nullopt;
    NativeSessionTransition transition;
    if (fields[2] == QLatin1String("suspend"))
        transition = NativeSessionTransition::Suspend;
    else if (fields[2] == QLatin1String("logout"))
        transition = NativeSessionTransition::Logout;
    else if (fields[2] == QLatin1String("reboot"))
        transition = NativeSessionTransition::Reboot;
    else if (fields[2] == QLatin1String("power-off"))
        transition = NativeSessionTransition::PowerOff;
    else
        return std::nullopt;
    quint64 baseline = 0;
    if (!decimal(fields[3], &baseline) || baseline == std::numeric_limits<quint64>::max() ||
        (transition != NativeSessionTransition::Suspend && baseline != 0))
        return std::nullopt;
    const auto lock = NativeLockIdentity::parse(QStringLiteral("session:lock:") +
                                                fields.mid(4).join(QLatin1Char(':')));
    if (!lock)
        return std::nullopt;
    return NativeTransitionIdentity{resource, *lock, transition, baseline};
}

const char *NativeTransitionIdentity::powerPermissionAction() const noexcept
{
    switch (transition) {
    case NativeSessionTransition::Suspend:
        return "org.freedesktop.login1.suspend";
    case NativeSessionTransition::Reboot:
        return "org.freedesktop.login1.reboot";
    case NativeSessionTransition::PowerOff:
        return "org.freedesktop.login1.power-off";
    case NativeSessionTransition::Logout:
        return nullptr;
    }
    return nullptr;
}

bool NativeApprovalScope::valid() const
{
    if (principal.size() > 64 || request.size() > 128 || plan.size() > 128)
        return false;
    const auto parsed = NativeLockIdentity::parse(lock.resource);
    if (!parsed || *parsed != lock || principal != QStringLiteral("unix:uid:%1").arg(lock.uid) ||
        plan != request || !digest(requestDigest) || !digest(observationDigest) ||
        !digest(reviewDigest))
        return false;
    if (isDisplay()) {
        if (!display || transition || display->deadlineUnixMs == 0 ||
            display->deadlineBootMs == 0 || display->reason.isEmpty() ||
            display->reason.size() > 2048 ||
            std::any_of(display->reason.begin(), display->reason.end(),
                        [](QChar c) {
                            return (c.category() == QChar::Other_Control &&
                                    c != QLatin1Char('\n')) ||
                                   c.category() == QChar::Other_Format;
                        }) ||
            QString::fromUtf8(display->reason.toUtf8()) != display->reason ||
            (purpose == ApprovalPurpose::ApplyDisplay
                 ? !display->decisionDigest.isEmpty()
                 : (!digest(display->decisionDigest) ||
                    display->decisionDigest ==
                        QStringLiteral("sha256:") + QString(64, QLatin1Char('0')))))
            return false;
        const auto intent = NativeDisplayIntent::parse(display->material);
        if (!intent || intent->lock != lock || intent->encode() != display->material)
            return false;
    } else if (display)
        return false;
    const bool power = purpose == ApprovalPurpose::AuthenticateSuspend ||
                       purpose == ApprovalPurpose::AuthenticateLogout ||
                       purpose == ApprovalPurpose::AuthenticateReboot ||
                       purpose == ApprovalPurpose::AuthenticatePowerOff;
    const bool setting = purpose == ApprovalPurpose::EnableProtectiveLock ||
                         purpose == ApprovalPurpose::RevokeProtectiveLock;
    if (power) {
        if (!transition || transition->lock != lock)
            return false;
        const auto canonical = NativeTransitionIdentity::parse(transition->resource);
        if (!canonical || *canonical != *transition)
            return false;
        switch (purpose) {
        case ApprovalPurpose::AuthenticateSuspend:
            if (transition->transition != NativeSessionTransition::Suspend)
                return false;
            break;
        case ApprovalPurpose::AuthenticateLogout:
            if (transition->transition != NativeSessionTransition::Logout)
                return false;
            break;
        case ApprovalPurpose::AuthenticateReboot:
            if (transition->transition != NativeSessionTransition::Reboot)
                return false;
            break;
        case ApprovalPurpose::AuthenticatePowerOff:
            if (transition->transition != NativeSessionTransition::PowerOff)
                return false;
            break;
        default:
            return false;
        }
    } else if (transition)
        return false;
    const QString prefix = isDisplay() ? QStringLiteral("request:v010:display-layout:")
                           : power     ? QStringLiteral("request:v010:session-transition:")
                           : setting   ? QStringLiteral("request:v010:protective-lock-setting:")
                                       : QStringLiteral("request:v010:session-lock:");
    const QStringView slug = QStringView(request).mid(prefix.size());
    if (!request.startsWith(prefix) || slug.isEmpty() || slug.size() > 64 ||
        slug.startsWith(QLatin1Char('-')) || slug.endsWith(QLatin1Char('-')) ||
        slug.contains(QLatin1String("--")))
        return false;
    for (QChar character : slug) {
        if (!((character >= QLatin1Char('a') && character <= QLatin1Char('z')) ||
              (character >= QLatin1Char('0') && character <= QLatin1Char('9')) ||
              character == QLatin1Char('-')))
            return false;
    }
    switch (purpose) {
    case ApprovalPurpose::ConfirmLock:
    case ApprovalPurpose::AuthenticateUnlock:
    case ApprovalPurpose::AuthenticateSuspend:
    case ApprovalPurpose::AuthenticateLogout:
    case ApprovalPurpose::AuthenticateReboot:
    case ApprovalPurpose::AuthenticatePowerOff:
    case ApprovalPurpose::EnableProtectiveLock:
    case ApprovalPurpose::RevokeProtectiveLock:
    case ApprovalPurpose::ApplyDisplay:
    case ApprovalPurpose::KeepDisplay:
    case ApprovalPurpose::RevertDisplay:
        return true;
    }
    return false;
}

const char *NativeApprovalScope::authenticationAction() const noexcept
{
    switch (purpose) {
    case ApprovalPurpose::ConfirmLock:
        return nullptr;
    case ApprovalPurpose::AuthenticateUnlock:
        return "org.linura.authority.unlock-session";
    case ApprovalPurpose::AuthenticateSuspend:
        return "org.linura.authority.suspend-session";
    case ApprovalPurpose::AuthenticateLogout:
        return "org.linura.authority.logout-session";
    case ApprovalPurpose::AuthenticateReboot:
        return "org.linura.authority.reboot-session";
    case ApprovalPurpose::AuthenticatePowerOff:
        return "org.linura.authority.power-off-session";
    case ApprovalPurpose::EnableProtectiveLock:
        return "org.linura.authority.enable-protective-lock";
    case ApprovalPurpose::RevokeProtectiveLock:
        return "org.linura.authority.revoke-protective-lock";
    case ApprovalPurpose::ApplyDisplay:
        return "org.linura.authority.apply-display-layout";
    case ApprovalPurpose::KeepDisplay:
        return "org.linura.authority.keep-display-layout";
    case ApprovalPurpose::RevertDisplay:
        return "org.linura.authority.revert-display-layout";
    }
    return nullptr;
}

bool NativeApprovalScope::isDisplay() const noexcept
{
    return purpose == ApprovalPurpose::ApplyDisplay || purpose == ApprovalPurpose::KeepDisplay ||
           purpose == ApprovalPurpose::RevertDisplay;
}

QString NativeApprovalScope::protectedDisplayDigest() const
{
    if (!isDisplay() || !valid())
        return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    for (const auto &field :
         {QStringLiteral("linura.native.display-approval.v1"), lock.resource, principal, request,
          plan, requestDigest, observationDigest, reviewDigest,
          QString::number(static_cast<unsigned>(purpose)), display->material,
          display->decisionDigest, QString::number(display->deadlineUnixMs),
          QString::number(display->deadlineBootMs), display->reason}) {
        const auto bytes = field.toUtf8();
        const auto size = qToBigEndian(static_cast<quint64>(bytes.size()));
        hash.addData(QByteArrayView(reinterpret_cast<const char *>(&size), sizeof(size)));
        hash.addData(bytes);
    }
    return QString::fromLatin1(hash.result().toHex());
}

bool NativeApprovalScope::requiresSessionOwnerAuthentication() const noexcept
{
    return purpose == ApprovalPurpose::AuthenticateUnlock ||
           purpose == ApprovalPurpose::EnableProtectiveLock ||
           purpose == ApprovalPurpose::RevokeProtectiveLock;
}

} // namespace Linura::SecurityOwner
