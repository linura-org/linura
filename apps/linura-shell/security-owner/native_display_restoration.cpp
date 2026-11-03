#include "native_display_restoration.h"

#include <QStringList>
#include <algorithm>
#include <array>
#include <set>

namespace Linura::SecurityOwner {
namespace {
constexpr qsizetype MaxBytes = 12 * 1024;
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
NativeDisplayRestorationIntent::Output output(const NativeDisplayTarget &row)
{
    return {row.handle, row.generation};
}
} // namespace

std::optional<NativeDisplayRestorationIntent>
NativeDisplayRestorationIntent::parse(const QString &text)
{
    if (text.isEmpty() || text.size() > MaxBytes ||
        std::any_of(text.begin(), text.end(),
                    [](QChar c) { return c.category() == QChar::Other_Control; }))
        return std::nullopt;
    const auto bytes = text.toUtf8();
    if (bytes.size() > MaxBytes || !bytes.startsWith("LNRI:1;"))
        return std::nullopt;
    QByteArrayView rest(bytes);
    rest = rest.sliced(7);
    std::array<QString, 7> fields;
    constexpr std::array<qsizetype, 7> bounds{256, 64, 64, 64, 4096, 4096, 16 * 84};
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto value = field(rest, bounds[index]);
        if (!value)
            return std::nullopt;
        fields[index] = *value;
    }
    if (!rest.empty() || fields[0].isEmpty() || !digest(fields[1]) || !digest(fields[2]) ||
        !digest(fields[3]))
        return std::nullopt;
    const auto original = NativeDisplayIntent::parse(fields[4]);
    const auto replacement = NativeDisplayIntent::parse(fields[5]);
    if (!original || !replacement || original->lock.boot != replacement->lock.boot ||
        original->lock.uid != replacement->lock.uid)
        return std::nullopt;
    // Both embedded intents have independently passed the complete native
    // topology/epoch syntax checks. Login and owner generations may change.
    const auto oldScope = original->baseline.topology.split(QLatin1Char(':'));
    const auto newScope = replacement->baseline.topology.split(QLatin1Char(':'));
    if (oldScope[6] != newScope[6] || oldScope[7] == newScope[7])
        return std::nullopt;
    auto rows = fields[6].split(QLatin1Char(';'), Qt::KeepEmptyParts);
    if (rows.empty() || !rows.back().isEmpty())
        return std::nullopt;
    rows.removeLast();
    if (rows.empty() || rows.size() > 16 ||
        static_cast<std::size_t>(rows.size()) != original->baseline.outputs.size() ||
        static_cast<std::size_t>(rows.size()) != replacement->baseline.outputs.size())
        return std::nullopt;
    std::map<Output, Output> mapping;
    std::set<Output> destinations;
    std::optional<Output> previous;
    for (const auto &row : rows) {
        const auto parts = row.split(QLatin1Char(':'));
        if (parts.size() != 4 || row.size() > 83)
            return std::nullopt;
        std::array<quint64, 4> values{};
        for (std::size_t index = 0; index < values.size(); ++index) {
            const auto value = number(parts[static_cast<qsizetype>(index)].toUtf8());
            if (!value || *value == 0)
                return std::nullopt;
            values[index] = *value;
        }
        const Output source{values[0], values[1]}, destination{values[2], values[3]};
        if ((previous && source <= *previous) || !mapping.emplace(source, destination).second ||
            !destinations.insert(destination).second)
            return std::nullopt;
        previous = source;
    }
    auto remapped = original->baseline;
    remapped.topology = replacement->baseline.topology;
    for (auto &row : remapped.outputs) {
        const auto destination = mapping.find(output(row));
        if (destination == mapping.end())
            return std::nullopt;
        row.handle = destination->second.first;
        row.generation = destination->second.second;
        if (row.mirror) {
            const auto mirror = mapping.find(*row.mirror);
            if (mirror == mapping.end())
                return std::nullopt;
            row.mirror = mirror->second;
        }
    }
    std::sort(remapped.outputs.begin(), remapped.outputs.end(),
              [](const auto &a, const auto &b) { return output(a) < output(b); });
    if (remapped.encode() != replacement->desired.encode())
        return std::nullopt; // Never restore the failed desired state.
    NativeDisplayRestorationIntent result{fields[0], fields[1],    fields[2],         fields[3],
                                          *original, *replacement, std::move(mapping)};
    return result.encode() == text ? std::optional(std::move(result)) : std::nullopt;
}
QString NativeDisplayRestorationIntent::encode() const
{
    QString pairs;
    for (const auto &[source, destination] : outputs)
        pairs += QStringLiteral("%1:%2:%3:%4;")
                     .arg(source.first)
                     .arg(source.second)
                     .arg(destination.first)
                     .arg(destination.second);
    QString text = QStringLiteral("LNRI:1;");
    for (const auto &value :
         {originalRequest, originalDispatch, originalCheckpoint, replacementBaselineGuard,
          original.encode(), replacement.encode(), pairs})
        text +=
            QString::number(value.toUtf8().size()) + QLatin1Char(':') + value + QLatin1Char(';');
    return text;
}
bool NativeDisplayRestorationIntent::nativeOptions(const NativeDisplaySnapshot &snapshot,
                                                   const QString &exactTopology,
                                                   const NativeLockIdentity &exactLock) const
{
    // Revalidate public struct fields, then bind the exact current baseline,
    // including native rules/ownership/identity. Hash equality alone never
    // replaces current geometry, supported modes or the actual native objects.
    return parse(encode()).has_value() &&
           replacement.nativeOptions(snapshot, exactTopology, exactLock) &&
           replacement.baseline.matchesGeometry(snapshot) &&
           snapshot.baselineGuard(replacement.baseline.encode()) ==
               std::optional(replacementBaselineGuard);
}
std::optional<NativeDisplayIntent> nativeDisplayApprovalIntent(const NativeApprovalScope &scope)
{
    if (!scope.display || !scope.isDisplay())
        return std::nullopt;
    if (scope.purpose == ApprovalPurpose::RestoreOriginalDisplay) {
        const auto recovery = NativeDisplayRestorationIntent::parse(scope.display->material);
        return recovery ? std::optional(recovery->replacement) : std::nullopt;
    }
    return NativeDisplayIntent::parse(scope.display->material);
}
} // namespace Linura::SecurityOwner
