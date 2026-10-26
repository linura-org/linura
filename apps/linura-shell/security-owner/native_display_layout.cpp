#include "native_display_layout.h"
#include <QStringList>
#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace Linura::SecurityOwner {
namespace {
std::optional<quint64> unsignedNumber(const QString &value)
{
    bool okay = false;
    const auto number = value.toULongLong(&okay, 10);
    if (!okay || value != QString::number(number))
        return std::nullopt;
    return number;
}
std::optional<qint32> signedNumber(const QString &value)
{
    bool okay = false;
    const auto number = value.toInt(&okay, 10);
    if (!okay || value != QString::number(number))
        return std::nullopt;
    return number;
}
std::optional<NativeDisplayTarget> target(const QString &value)
{
    const auto fields = value.split(QLatin1Char(':'), Qt::KeepEmptyParts);
    if (fields.size() != 3 && fields.size() != 11)
        return std::nullopt;
    const auto handle = unsignedNumber(fields[0]), generation = unsignedNumber(fields[1]);
    if (!handle || !generation || *generation == 0 ||
        *generation == std::numeric_limits<quint64>::max())
        return std::nullopt;
    NativeDisplayTarget result;
    result.handle = *handle;
    result.generation = *generation;
    if (fields.size() == 3)
        return fields[2] == QLatin1String("disabled") ? std::optional(result) : std::nullopt;
    if (fields[2] != QLatin1String("enabled"))
        return std::nullopt;
    const auto width = unsignedNumber(fields[3]), height = unsignedNumber(fields[4]);
    const auto refresh = unsignedNumber(fields[5]), scale = unsignedNumber(fields[6]);
    const auto transform = unsignedNumber(fields[7]);
    const auto x = signedNumber(fields[8]), y = signedNumber(fields[9]);
    if (!width || !height || !refresh || !scale || !transform || !x || !y || *width == 0 ||
        *width > 32768 || *height == 0 || *height > 32768 || *refresh == 0 ||
        *refresh > 1'000'000 || *scale < 500 || *scale > 4000 || *scale % 125 != 0 ||
        *transform > 7 || *x < -65536 || *x > 65536 || *y < -65536 || *y > 65536)
        return std::nullopt;
    result.enabled = true;
    result.mode = {static_cast<qint32>(*width), static_cast<qint32>(*height),
                   static_cast<qint32>(*refresh)};
    result.scaleMilli = static_cast<quint32>(*scale);
    result.transform = static_cast<quint32>(*transform);
    result.x = *x;
    result.y = *y;
    if (fields[10] != QLatin1String("-")) {
        const auto pair = fields[10].split(QLatin1Char(','), Qt::KeepEmptyParts);
        if (pair.size() != 2)
            return std::nullopt;
        const auto handle = unsignedNumber(pair[0]), generation = unsignedNumber(pair[1]);
        if (!handle || !generation || *generation == 0 ||
            *generation == std::numeric_limits<quint64>::max())
            return std::nullopt;
        result.mirror = std::pair{*handle, *generation};
    }
    return result;
}
std::optional<NativeDisplayLayout> layout(const QStringList &tokens, qsizetype &position)
{
    if (position + 2 >= tokens.size() || tokens[position++] != QLatin1String("LNDL:1"))
        return std::nullopt;
    NativeDisplayLayout result;
    result.topology = tokens[position++];
    if (!result.topology.startsWith(QLatin1String("display:topology:")) ||
        result.topology.toUtf8().size() > 256)
        return std::nullopt;
    quint64 previous = 0;
    bool first = true;
    while (position < tokens.size() && !tokens[position].isEmpty() &&
           tokens[position] != QLatin1String("LNDL:1")) {
        const auto row = target(tokens[position++]);
        if (!row || result.outputs.size() >= 16 || (!first && row->handle <= previous))
            return std::nullopt;
        previous = row->handle;
        first = false;
        result.outputs.push_back(*row);
    }
    if (result.outputs.empty())
        return std::nullopt;
    return result;
}
QString fixedMilli(quint32 value)
{
    return QString::number(value / 1000) + QLatin1Char('.') +
           QString::number(value % 1000).rightJustified(3, QLatin1Char('0'));
}
bool nativeName(const QString &value)
{
    return !value.isEmpty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](QChar character) {
               const auto c = character.unicode();
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_' || c == '.';
           });
}
} // namespace
QString NativeDisplayTarget::encode() const
{
    QString result = QString::number(handle) + QLatin1Char(':') + QString::number(generation);
    if (!enabled)
        return result + QStringLiteral(":disabled");
    result += QStringLiteral(":enabled:%1:%2:%3:%4:%5:%6:%7:")
                  .arg(mode.width)
                  .arg(mode.height)
                  .arg(mode.refresh)
                  .arg(scaleMilli)
                  .arg(transform)
                  .arg(x)
                  .arg(y);
    return result + (mirror ? QString::number(mirror->first) + QLatin1Char(',') +
                                  QString::number(mirror->second)
                            : QStringLiteral("-"));
}
QString NativeDisplayLayout::encode() const
{
    QString result = QStringLiteral("LNDL:1;") + topology + QLatin1Char(';');
    for (const auto &output : outputs)
        result += output.encode() + QLatin1Char(';');
    return result;
}
QString NativeDisplayIntent::encode() const
{
    return QStringLiteral("LNDI:1;") + lock.resource + QLatin1Char(';') + baseline.encode() +
           desired.encode();
}
std::optional<NativeDisplayIntent> NativeDisplayIntent::parse(const QString &material)
{
    if (material.isEmpty() || material.toUtf8().size() > 4096 ||
        std::any_of(material.begin(), material.end(),
                    [](QChar c) { return c.unicode() < 32 || c.unicode() >= 127; }))
        return std::nullopt;
    const auto fields = material.split(QLatin1Char(';'), Qt::KeepEmptyParts);
    if (fields.size() < 9 || fields[0] != QLatin1String("LNDI:1"))
        return std::nullopt;
    const auto lock = NativeLockIdentity::parse(fields[1]);
    if (!lock)
        return std::nullopt;
    qsizetype position = 2;
    const auto baseline = layout(fields, position), desired = layout(fields, position);
    if (!baseline || !desired || position != fields.size() - 1 || !fields.back().isEmpty() ||
        baseline->topology != desired->topology ||
        baseline->outputs.size() != desired->outputs.size())
        return std::nullopt;
    for (std::size_t index = 0; index < baseline->outputs.size(); ++index)
        if (baseline->outputs[index].handle != desired->outputs[index].handle ||
            baseline->outputs[index].generation != desired->outputs[index].generation)
            return std::nullopt;
    NativeDisplayIntent result{*lock, *baseline, *desired};
    return result.encode() == material ? std::optional(result) : std::nullopt;
}
bool NativeDisplayLayout::nativeOptions(const NativeDisplaySnapshot &snapshot) const
{
    if (snapshot.generation == 0 || outputs.size() != snapshot.heads.size() || outputs.empty() ||
        outputs.size() > 16)
        return false;
    // No inferred identity from an ambiguous or stale native inventory,
    // including a caller-created snapshot outside the live Wayland tracker.
    std::set<quint64> handles;
    std::set<QString> names;
    for (const auto &head : snapshot.heads) {
        if (head.handle == 0 || head.generation == 0 || head.generation > snapshot.generation ||
            !nativeName(head.name) || !handles.insert(head.handle).second ||
            !names.insert(head.name).second)
            return false;
    }
    bool independent = false;
    for (const auto &row : outputs) {
        const auto head =
            std::find_if(snapshot.heads.begin(), snapshot.heads.end(), [&](const auto &head) {
                return head.handle == row.handle && head.generation == row.generation;
            });
        if (head == snapshot.heads.end() || !nativeName(head->name))
            return false;
        if (!row.enabled)
            continue;
        if (row.scaleMilli < 500 || row.scaleMilli > 4000 || row.scaleMilli % 125 != 0 ||
            row.transform > 7 || row.x < -65536 || row.x > 65536 || row.y < -65536 || row.y > 65536)
            return false;
        if (std::find(head->modes.begin(), head->modes.end(), row.mode) == head->modes.end())
            return false;
        const quint64 width = static_cast<quint64>(row.mode.width),
                      height = static_cast<quint64>(row.mode.height);
        if (width == 0 || height == 0 || row.mode.refresh <= 0 ||
            (width * 1000 + row.scaleMilli - 1) / row.scaleMilli > 32768 ||
            (height * 1000 + row.scaleMilli - 1) / row.scaleMilli > 32768)
            return false;
        if (row.mirror) {
            const auto root =
                std::find_if(outputs.begin(), outputs.end(), [&](const auto &candidate) {
                    return candidate.handle == row.mirror->first &&
                           candidate.generation == row.mirror->second;
                });
            if (root == outputs.end() || !root->enabled || root->mirror ||
                root->handle == row.handle)
                return false;
        } else
            independent = true;
    }
    return independent;
}
bool NativeDisplayIntent::nativeOptions(const NativeDisplaySnapshot &snapshot,
                                        const QString &exactTopology,
                                        const NativeLockIdentity &exactLock) const
{
    return lock == exactLock && baseline.topology == exactTopology &&
           desired.topology == exactTopology && baseline.nativeOptions(snapshot) &&
           desired.nativeOptions(snapshot);
}
bool NativeDisplayLayout::matchesGeometry(const NativeDisplaySnapshot &snapshot) const
{
    if (!nativeOptions(snapshot))
        return false;
    for (const auto &row : outputs) {
        const auto &head =
            *std::find_if(snapshot.heads.begin(), snapshot.heads.end(),
                          [&](const auto &head) { return head.handle == row.handle; });
        if (head.enabled != row.enabled)
            return false;
        if (row.enabled &&
            (!head.current || *head.current != row.mode || head.x != row.x || head.y != row.y ||
             head.transform != static_cast<qint32>(row.transform) ||
             head.scaleFixed * 1000 != static_cast<qint32>(row.scaleMilli * 256)))
            return false;
    }
    return true;
}
std::vector<QByteArray> NativeDisplayLayout::commands(const NativeDisplaySnapshot &snapshot) const
{
    if (!nativeOptions(snapshot))
        return {};
    std::map<quint64, QString> names;
    for (const auto &head : snapshot.heads)
        names.emplace(head.handle, head.name);
    std::vector<QByteArray> result;
    // Enable independent roots before mirrors and disable requests. This is
    // bounded sequential native API work, never an atomicity/success assertion.
    for (int phase : {0, 1, 2}) {
        for (const auto &row : outputs) {
            const int selected = !row.enabled ? 2 : row.mirror ? 1 : 0;
            if (selected != phase)
                continue;
            QString command =
                QStringLiteral("/keyword monitor ") + names.at(row.handle) + QLatin1Char(',');
            if (!row.enabled)
                command += QStringLiteral("disable");
            else {
                command += QStringLiteral("%1x%2@").arg(row.mode.width).arg(row.mode.height) +
                           fixedMilli(static_cast<quint32>(row.mode.refresh)) +
                           QStringLiteral(",%1x%2,").arg(row.x).arg(row.y) +
                           fixedMilli(row.scaleMilli) +
                           QStringLiteral(",transform,%1").arg(row.transform);
                if (row.mirror)
                    command += QStringLiteral(",mirror,") + names.at(row.mirror->first);
            }
            if (command.size() > 512)
                return {};
            result.push_back(command.toLatin1());
        }
    }
    return result;
}
} // namespace Linura::SecurityOwner
