#include "native_scope.h"

#include <QStringList>
#include <QStringView>
#include <QUuid>

#include <limits>

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

bool alphanumeric(QStringView text)
{
    for (QChar character : text) {
        const ushort code = character.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9')))
            return false;
    }
    return true;
}

} // namespace

std::optional<NativeLockIdentity> NativeLockIdentity::parse(const QString &resource)
{
    if (resource.size() > 256)
        return std::nullopt;
    const auto fields = resource.split(QLatin1Char(':'));
    if (fields.size() != 8 || fields[0] != QLatin1String("session") ||
        fields[1] != QLatin1String("lock") || !uuid(fields[2]) || !uuid(fields[6]) ||
        fields[4].isEmpty() || fields[4].size() > 64 || !alphanumeric(fields[4]))
        return std::nullopt;
    quint64 uid = 0, created = 0, generation = 0;
    if (!decimal(fields[3], &uid) || uid == 0 || uid > std::numeric_limits<quint32>::max() ||
        !decimal(fields[5], &created) || created == 0 || !decimal(fields[7], &generation) ||
        generation == 0)
        return std::nullopt;
    return NativeLockIdentity{resource, fields[2], static_cast<quint32>(uid), fields[4], created,
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

} // namespace Linura::SecurityOwner
