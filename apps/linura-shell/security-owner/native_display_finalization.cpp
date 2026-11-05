#include "native_display_finalization.h"

#include <algorithm>
#include <array>

namespace Linura::SecurityOwner {
namespace {
std::optional<quint64> number(const QByteArray &text)
{
    bool okay = false;
    const auto value = text.toULongLong(&okay, 10);
    return okay && text == QByteArray::number(value) ? std::optional(value) : std::nullopt;
}
bool digest(const QString &text)
{
    return text.size() == 64 && text != QString(64, QLatin1Char('0')) &&
           std::all_of(text.begin(), text.end(), [](QChar c) {
               return (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                      (c >= QLatin1Char('a') && c <= QLatin1Char('f'));
           });
}
std::optional<QString> field(QByteArrayView &rest, qsizetype maximum)
{
    const auto colon = rest.indexOf(':');
    if (colon <= 0 || colon > 20)
        return std::nullopt;
    const auto length = number(QByteArray(rest.data(), colon));
    if (!length || *length > static_cast<quint64>(maximum))
        return std::nullopt;
    const auto size = static_cast<qsizetype>(*length);
    rest = rest.sliced(colon + 1);
    if (rest.size() <= size || rest[size] != ';')
        return std::nullopt;
    const QByteArray bytes(rest.data(), size);
    const auto value = QString::fromUtf8(bytes);
    if (value.toUtf8() != bytes)
        return std::nullopt;
    rest = rest.sliced(size + 1);
    return value;
}
bool sameLogin(const NativeLockIdentity &a, const NativeLockIdentity &b)
{
    return a.boot == b.boot && a.uid == b.uid && a.session == b.session &&
           a.createdMonotonicUs == b.createdMonotonicUs;
}
bool bounded(const NativeDisplayIntent &intent)
{
    if (intent.lock.resource.size() > 256 || intent.baseline.topology.size() > 256 ||
        intent.desired.topology.size() > 256 || intent.baseline.outputs.size() > 16 ||
        intent.desired.outputs.size() > 16)
        return false;
    const auto lock = NativeLockIdentity::parse(intent.lock.resource);
    return lock && *lock == intent.lock;
}
} // namespace

std::optional<NativeDisplayFinalizationIntent>
NativeDisplayFinalizationIntent::parse(const QString &text)
{
    if (text.isEmpty() || text.size() > MaxBytes ||
        std::any_of(text.begin(), text.end(),
                    [](QChar c) { return c.category() == QChar::Other_Control; }))
        return std::nullopt;
    const auto bytes = text.toUtf8();
    if (bytes.size() > MaxBytes || !bytes.startsWith("LNRF:1;"))
        return std::nullopt;
    QByteArrayView rest(bytes);
    rest = rest.sliced(7);
    std::array<QString, 7> fields;
    constexpr std::array<qsizetype, 7> bounds{256, 64, 64, 64, 20, 256, 12 * 1024};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto value = field(rest, bounds[i]);
        if (!value)
            return std::nullopt;
        fields[i] = *value;
    }
    const auto epoch = number(fields[4].toUtf8());
    const auto lock = NativeLockIdentity::parse(fields[5]);
    const auto restoration = NativeDisplayRestorationIntent::parse(fields[6]);
    if (!rest.empty() || fields[0].isEmpty() || !digest(fields[1]) || !digest(fields[2]) ||
        !digest(fields[3]) || !epoch || *epoch == 0 || !lock || !restoration ||
        fields[0] == restoration->originalRequest || fields[1] == restoration->originalDispatch ||
        !sameLogin(*lock, restoration->replacement.lock))
        return std::nullopt;
    NativeDisplayFinalizationIntent result{fields[0], fields[1], fields[2],   fields[3],
                                           *epoch,    *lock,     *restoration};
    return result.encode() == text ? std::optional(std::move(result)) : std::nullopt;
}
QString NativeDisplayFinalizationIntent::encode() const
{
    // Public aggregate fields may have changed after decoding. Bound nested
    // containers and strings before constructing any encoded material.
    if (restorationRequest.size() > 256 || restorationDispatch.size() > 64 ||
        terminalLink.size() > 64 || restoredSourceGuard.size() > 64 ||
        currentLock.resource.size() > 256 || restoration.originalRequest.size() > 256 ||
        restoration.originalDispatch.size() > 64 || restoration.originalCheckpoint.size() > 64 ||
        restoration.replacementBaselineGuard.size() > 64 || restoration.outputs.size() > 16 ||
        !bounded(restoration.original) || !bounded(restoration.replacement))
        return {};
    const auto lock = NativeLockIdentity::parse(currentLock.resource);
    if (!lock || *lock != currentLock)
        return {};
    const auto nested = restoration.encode();
    if (nested.toUtf8().size() > 12 * 1024)
        return {};
    QString text = QStringLiteral("LNRF:1;");
    for (const auto &value :
         {restorationRequest, restorationDispatch, terminalLink, restoredSourceGuard,
          QString::number(postWriteEpoch), currentLock.resource, nested})
        text +=
            QString::number(value.toUtf8().size()) + QLatin1Char(':') + value + QLatin1Char(';');
    return text.toUtf8().size() <= MaxBytes ? text : QString{};
}
bool NativeDisplayFinalizationIntent::matchesRestored(const NativeDisplaySnapshot &snapshot,
                                                      const QString &exactTopology,
                                                      const NativeLockIdentity &exactLock,
                                                      quint64 currentPostWriteEpoch) const
{
    // Public struct fields are revalidated. Neither an old baseline guard nor
    // equal geometry can replace the restored native source/ownership digest.
    const auto &desired = restoration.replacement.desired;
    return parse(encode()).has_value() && currentLock == exactLock &&
           desired.topology == exactTopology && postWriteEpoch == currentPostWriteEpoch &&
           desired.matchesGeometry(snapshot) &&
           snapshot.baselineGuard(desired.encode()) == std::optional(restoredSourceGuard);
}

} // namespace Linura::SecurityOwner
