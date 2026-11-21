#include "native_display_topology.h"

#include <QCryptographicHash>
#include <QtEndian>
#include <algorithm>
#include <limits>

namespace Linura::SecurityOwner {
namespace {
bool validDigest(const QString &value)
{
    return value.size() == 64 && value != QString(64, QLatin1Char('0')) &&
           std::all_of(value.cbegin(), value.cend(), [](QChar c) {
               const auto n = c.unicode();
               return (n >= '0' && n <= '9') || (n >= 'a' && n <= 'f');
           });
}
} // namespace
// Pure bounded comparison belongs to the foundation. No live Wayland object or
// provider handle is required; preserve the original guard domain and bytes.
std::optional<QString> NativeDisplaySnapshot::baselineGuard(const QString &baseline) const
{
    if (heads.empty() || heads.size() > 16 || baseline.isEmpty() || baseline.size() > 4096)
        return std::nullopt;
    std::vector<const NativeDisplayHead *> ordered;
    for (const auto &head : heads)
        ordered.push_back(&head);
    std::sort(ordered.begin(), ordered.end(), [](const auto *a, const auto *b) {
        return std::pair{a->handle, a->generation} < std::pair{b->handle, b->generation};
    });
    auto append = [](QByteArray &out, const QByteArray &value) {
        const auto size = qToBigEndian(static_cast<quint64>(value.size()));
        out.append(reinterpret_cast<const char *>(&size), sizeof(size));
        out.append(value);
    };
    QByteArray rows;
    std::optional<quint64> last;
    for (const auto *head : ordered) {
        if ((last && *last == head->handle) || head->generation == 0 ||
            head->generation == std::numeric_limits<quint64>::max() ||
            !validDigest(head->baseRuleDigest) || !validDigest(head->outputIdentityDigest) ||
            head->ownedTarget.size() > 512 ||
            (head->linuraOwned ? !head->ownedTarget.startsWith(QLatin1String("LNOT:1;"))
                               : !head->ownedTarget.isEmpty()))
            return std::nullopt;
        last = head->handle;
        for (const auto &value :
             {QString::number(head->handle), QString::number(head->generation),
              head->linuraOwned ? QStringLiteral("true") : QStringLiteral("false"),
              head->baseRuleDigest, head->outputIdentityDigest, head->ownedTarget})
            append(rows, value.toUtf8());
    }
    QByteArray canonical;
    append(canonical, "linura.display.native-baseline-guard.v1");
    append(canonical, baseline.toUtf8());
    append(canonical, rows);
    return QString::fromLatin1(
        QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
}

} // namespace Linura::SecurityOwner
