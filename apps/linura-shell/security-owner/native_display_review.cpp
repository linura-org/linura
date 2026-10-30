#include "native_display_review.h"

#include <QTextBoundaryFinder>
#include <algorithm>
#include <array>

namespace Linura::SecurityOwner {
namespace {
QString number(quint32 milli)
{
    return QString::number(milli / 1000) + QLatin1Char('.') +
           QString::number(milli % 1000).rightJustified(3, QLatin1Char('0'));
}
QString describe(const NativeDisplayTarget &row, const NativeDisplaySnapshot &snapshot)
{
    if (!row.enabled)
        return QStringLiteral("Disabled");
    static const std::array<const char *, 8> transforms{
        "normal",  "90 degrees",         "180 degrees",         "270 degrees",
        "flipped", "flipped 90 degrees", "flipped 180 degrees", "flipped 270 degrees"};
    QString text = QStringLiteral("%1 x %2 at %3 Hz; scale %4; %5; position (%6, %7)")
                       .arg(row.mode.width)
                       .arg(row.mode.height)
                       .arg(number(static_cast<quint32>(row.mode.refresh)))
                       .arg(number(row.scaleMilli))
                       .arg(QString::fromLatin1(transforms.at(row.transform)))
                       .arg(row.x)
                       .arg(row.y);
    if (row.mirror) {
        const auto target =
            std::find_if(snapshot.heads.begin(), snapshot.heads.end(), [&](const auto &head) {
                return head.handle == row.mirror->first && head.generation == row.mirror->second;
            });
        if (target == snapshot.heads.end())
            return {};
        text += QStringLiteral("; mirrors %1").arg(target->name);
    } else
        text += QStringLiteral("; independent output");
    return text;
}
} // namespace
std::optional<std::vector<NativeDisplayReviewPage>>
nativeDisplayReviewPages(const NativeApprovalScope &scope, const NativeDisplaySnapshot &snapshot)
{
    if (!scope.isDisplay() || !scope.valid())
        return std::nullopt;
    const auto intent = NativeDisplayIntent::parse(scope.display->material);
    if (!intent || !intent->baseline.nativeOptions(snapshot) ||
        !intent->desired.nativeOptions(snapshot))
        return std::nullopt;
    for (const auto &head : snapshot.heads)
        if (head.name.isEmpty() || head.name.size() > 128 ||
            !std::all_of(head.name.begin(), head.name.end(), [](QChar c) {
                const auto n = c.unicode();
                return (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '0' && n <= '9') ||
                       n == '-' || n == '_' || n == '.';
            }))
            return std::nullopt;
    const auto purpose = scope.purpose == ApprovalPurpose::ApplyDisplay  ? QStringLiteral("Apply")
                         : scope.purpose == ApprovalPurpose::KeepDisplay ? QStringLiteral("Keep")
                                                                         : QStringLiteral("Revert");
    const auto introduction =
        QStringLiteral("%1 display layout for session owner UID %2. Security-sensitive system "
                       "change. Administrator authentication is required. Escape cancels.")
            .arg(purpose)
            .arg(scope.lock.uid);
    std::vector<NativeDisplayReviewPage> pages;
    pages.push_back({purpose + QStringLiteral(" display layout?"), introduction});
    const auto &reason = scope.display->reason;
    QTextBoundaryFinder boundary(QTextBoundaryFinder::Grapheme, reason);
    qsizetype offset = 0;
    while (offset < reason.size()) {
        auto end = std::min(offset + 160, reason.size());
        boundary.setPosition(end);
        if (!boundary.isAtBoundary())
            end = boundary.toPreviousBoundary();
        if (end <= offset)
            return std::nullopt;
        pages.push_back({QStringLiteral("Reason supplied with this request"),
                         reason.mid(offset, end - offset)});
        offset = end;
    }
    for (std::size_t i = 0; i < intent->baseline.outputs.size(); ++i) {
        const auto &before = intent->baseline.outputs[i];
        const auto &after = intent->desired.outputs[i];
        const auto head =
            std::find_if(snapshot.heads.begin(), snapshot.heads.end(), [&](const auto &row) {
                return row.handle == before.handle && row.generation == before.generation;
            });
        if (head == snapshot.heads.end())
            return std::nullopt;
        const auto previous = describe(before, snapshot), desired = describe(after, snapshot);
        if (previous.isEmpty() || desired.isEmpty())
            return std::nullopt;
        pages.push_back({QStringLiteral("%1 — output %2 of %3")
                             .arg(head->name)
                             .arg(i + 1)
                             .arg(intent->baseline.outputs.size()),
                         QStringLiteral("Previous: %1\nRequested: %2").arg(previous, desired)});
    }
    pages.push_back({purpose + QStringLiteral(" this exact layout?"),
                     scope.purpose == ApprovalPurpose::ApplyDisplay
                         ? QStringLiteral("Linura will apply the reviewed layout temporarily. "
                                          "Keep requires a separate protected decision within "
                                          "15 seconds; otherwise Linura restores the previous "
                                          "layout. Existing session-lock protection stays active.")
                     : scope.purpose == ApprovalPurpose::KeepDisplay
                         ? QStringLiteral("Keep the reviewed layout before the ORIGINAL "
                                          "confirmation deadline. This decision cannot change "
                                          "the layout or authorize another apply.")
                         : QStringLiteral("Restore the previous reviewed layout. This decision "
                                          "cannot authorize a different layout or release a "
                                          "session lock.")});
    return pages;
}
} // namespace Linura::SecurityOwner
