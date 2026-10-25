#include "native_launch.h"

#include <QDBusArgument>

namespace Linura::SecurityOwner {

bool exactNativeLaunch(const NativeLaunchFacts &facts, const QString &image,
                       const QStringList &arguments, quint32 expectedPid)
{
    if (image.isEmpty() || image.size() > 128 || !image.startsWith(QLatin1Char('/')) ||
        arguments.isEmpty() || arguments.size() > 3 || arguments.first() != image ||
        expectedPid == 0 || facts.image != image || facts.arguments != arguments)
        return false;
    // This is an exact, audited launch profile, not permission for arbitrary
    // three-argument programs. The pinned Arch polkit 127 daemon uses both
    // fixed flags; every other native supervised program has no arguments.
    if (image == QLatin1String("/usr/lib/polkit-1/polkitd")) {
        QStringList expected{image};
        expected.append(QStringLiteral("--no-debug"));
        expected.append(QStringLiteral("--log-level=notice"));
        if (arguments != expected)
            return false;
    } else if (image == QLatin1String("/usr/lib/linura/linura-executor-session") &&
               arguments.size() == 2) {
        // The suspend pre-exec hook is a separate, exact, non-Polkit
        // privileged helper profile, never a generic two-argument allowance.
        if (arguments.last() != QLatin1String("--protect-before-sleep"))
            return false;
    } else if (arguments.size() != 1) {
        return false;
    }
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
        if (facts.arguments.size() == 3)
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
