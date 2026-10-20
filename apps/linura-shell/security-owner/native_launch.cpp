#include "native_launch.h"

#include <QDBusArgument>

namespace Linura::SecurityOwner {

bool exactNativeLaunch(const NativeLaunchFacts &facts, const QString &image,
                       const QStringList &arguments, quint32 expectedPid)
{
    if (image.isEmpty() || image.size() > 128 || !image.startsWith(QLatin1Char('/')) ||
        arguments.isEmpty() || arguments.size() > 2 || arguments.first() != image ||
        expectedPid == 0 || facts.image != image || facts.arguments != arguments)
        return false;
    for (const auto &word : arguments) {
        if (word.isEmpty() || word.size() > 128 || word.contains(QChar::Null))
            return false;
    }
    return !facts.ignoreFailure && facts.startedReal != 0 && facts.startedMonotonic != 0 &&
           facts.exitedReal == 0 && facts.exitedMonotonic == 0 && facts.pid == expectedPid &&
           facts.code == 0 && facts.status == 0;
}

std::optional<NativeLaunchFacts> decodeNativeSingleLaunch(const QVariant &reply)
{
    if (reply.metaType() != QMetaType::fromType<QDBusArgument>())
        return std::nullopt;
    const auto value = reply.value<QDBusArgument>();
    if (value.currentSignature() != QLatin1String("a(sasbttttuii)"))
        return std::nullopt;
    value.beginArray();
    if (value.atEnd())
        return std::nullopt;
    value.beginStructure();
    NativeLaunchFacts facts;
    value >> facts.image;
    if (facts.image.size() > 128)
        return std::nullopt;
    value.beginArray();
    while (!value.atEnd()) {
        if (facts.arguments.size() == 2)
            return std::nullopt;
        QString word;
        value >> word;
        if (word.size() > 128)
            return std::nullopt;
        facts.arguments.append(word);
    }
    value.endArray();
    value >> facts.ignoreFailure >> facts.startedReal >> facts.startedMonotonic >>
        facts.exitedReal >> facts.exitedMonotonic >> facts.pid >> facts.code >> facts.status;
    value.endStructure();
    if (!value.atEnd())
        return std::nullopt; // More than one launch is never this fixed service.
    value.endArray();
    return facts;
}

bool exactNativeExecStart(const QVariant &reply, const QString &image, const QStringList &arguments,
                          quint32 expectedPid)
{
    const auto facts = decodeNativeSingleLaunch(reply);
    return facts && exactNativeLaunch(*facts, image, arguments, expectedPid);
}

} // namespace Linura::SecurityOwner
