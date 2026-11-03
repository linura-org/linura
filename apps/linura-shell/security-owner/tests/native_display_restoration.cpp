#include "native_display_restoration.h"
#include "native_approval.h"
#include "native_display_review.h"

#include <QFile>
#include <cassert>
#include <algorithm>

using namespace Linura::SecurityOwner;
namespace {
QString frame(const std::vector<QString> &fields)
{
    QString text = QStringLiteral("LNRI:1;");
    for (const auto &field : fields)
        text +=
            QString::number(field.toUtf8().size()) + QLatin1Char(':') + field + QLatin1Char(';');
    return text;
}
QString layout(const QString &topology, const QString &rows)
{
    return QStringLiteral("LNDL:1;") + topology + QLatin1Char(';') + rows;
}
QString intent(const QString &lock, const QString &baseline, const QString &desired)
{
    return QStringLiteral("LNDI:1;") + lock + QLatin1Char(';') + baseline + desired;
}
} // namespace
int main()
{
    const auto oldLock = QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:"
                                        "c2:42:22222222-2222-4222-8222-222222222222:1");
    const auto newLock = QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:"
                                        "c3:43:44444444-4444-4444-8444-444444444444:1");
    const auto oldTopology =
        QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:"
                       "1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3");
    const auto newTopology =
        QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:"
                       "1000:c3:43:seat0:66666666-6666-4666-8666-666666666666:5");
    const auto oldBaseline = layout(
        oldTopology, QStringLiteral("1:2:enabled:1920:1080:60000:1000:0:0:0:-;"
                                    "2:2:enabled:1920:1080:60000:1000:0:0:0:1,2;3:3:disabled;"));
    const auto oldDesired = layout(
        oldTopology, QStringLiteral("1:2:enabled:1280:720:60000:1000:0:0:0:-;"
                                    "2:2:enabled:1280:720:60000:1000:0:0:0:1,2;3:3:disabled;"));
    const auto currentBaseline = layout(
        newTopology, QStringLiteral("7:4:enabled:1280:720:60000:1000:0:0:0:-;"
                                    "8:4:disabled;9:5:enabled:1280:720:60000:1000:0:1280:0:-;"));
    const auto restored = layout(
        newTopology, QStringLiteral("7:4:enabled:1920:1080:60000:1000:0:0:0:9,5;"
                                    "8:4:disabled;9:5:enabled:1920:1080:60000:1000:0:0:0:-;"));
    auto fields = std::vector<QString>{QStringLiteral("request:v010:display-layout:original"),
                                       QString(64, QLatin1Char('a')),
                                       QString(64, QLatin1Char('b')),
                                       QString(64, QLatin1Char('c')),
                                       intent(oldLock, oldBaseline, oldDesired),
                                       intent(newLock, currentBaseline, restored),
                                       QStringLiteral("1:2:9:5;2:2:7:4;3:3:8:4;")};
    const auto text = frame(fields);
    QFile golden(QString::fromUtf8(LINURA_DISPLAY_RESTORATION_FIXTURE_PATH));
    assert(golden.open(QIODevice::ReadOnly));
    assert(golden.read(12 * 1024 + 1) == text.toUtf8() + '\n');
    assert(golden.atEnd());
    const auto parsed = NativeDisplayRestorationIntent::parse(text);
    assert(parsed && parsed->encode() == text && parsed->outputs.size() == 3);
    assert(parsed->replacement.desired.outputs[0].mirror ==
           std::optional(NativeDisplayRestorationIntent::Output{9, 5}));
    assert(!parsed->replacement.desired.outputs[1].enabled);
    assert(parsed->replacement.lock.session == QStringLiteral("c3"));
    for (qsizetype size = 0; size < text.size(); ++size)
        assert(!NativeDisplayRestorationIntent::parse(text.left(size)));
    for (const auto &suffix : {QStringLiteral(";"), QStringLiteral("0:;"), QString(QChar(0))})
        assert(!NativeDisplayRestorationIntent::parse(text + suffix));
    assert(!NativeDisplayRestorationIntent::parse(QString(12 * 1024 + 1, QLatin1Char('x'))));
    assert(!NativeDisplayRestorationIntent::parse(QStringLiteral("0") + text));
    const auto firstLength = QString::number(fields[0].toUtf8().size());
    for (const auto &length :
         {QStringLiteral("0") + firstLength, QStringLiteral("+") + firstLength,
          QStringLiteral(" ") + firstLength, QStringLiteral("18446744073709551616")}) {
        auto changed = text;
        changed.replace(7, firstLength.size(), length);
        assert(!NativeDisplayRestorationIntent::parse(changed));
    }
    for (const auto index : {1U, 2U, 3U}) {
        for (const auto &invalid : {QString(64, QLatin1Char('0')), QString(64, QLatin1Char('A')),
                                    QString(63, QLatin1Char('a'))}) {
            auto changed = fields;
            changed[index] = invalid;
            assert(!NativeDisplayRestorationIntent::parse(frame(changed)));
        }
    }
    for (const auto &pairs :
         {QStringLiteral("1:2:9:5;2:2:7:4;"), QStringLiteral("1:2:9:5;2:2:9:5;3:3:8:4;"),
          QStringLiteral("2:2:7:4;1:2:9:5;3:3:8:4;"), QStringLiteral("1:2:9:5;2:2:7:4;3:3:8:5;"),
          QStringLiteral("01:2:9:5;2:2:7:4;3:3:8:4;"), QStringLiteral("1:2:9:5;2:2:7:4;3:3:8:4"),
          QStringLiteral("1:2:9:5;2:2:7:4;3:3:8:4;4:4:10:5;")}) {
        auto changed = fields;
        changed[6] = pairs;
        assert(!NativeDisplayRestorationIntent::parse(frame(changed)));
    }
    for (const auto &[before, after] : std::vector<std::pair<QString, QString>>{
             {QStringLiteral("60000:1000:0:0:0:9,5"), QStringLiteral("60000:1000:0:0:0:7,4")},
             {QStringLiteral("1920:1080"), QStringLiteral("1280:720")},
             {QStringLiteral("seat0"), QStringLiteral("seat1")},
             {QStringLiteral("1000:c3"), QStringLiteral("1001:c3")},
             {QStringLiteral("11111111-1111-4111-8111-111111111111"),
              QStringLiteral("77777777-7777-4777-8777-777777777777")},
             {QStringLiteral("66666666-6666-4666-8666-666666666666"),
              QStringLiteral("33333333-3333-4333-8333-333333333333")}}) {
        auto changed = fields;
        changed[5].replace(before, after);
        assert(!NativeDisplayRestorationIntent::parse(frame(changed)));
    }
    // The original request is framed in UTF-8 bytes, not UTF-16 code units.
    auto unicode = fields;
    unicode[0] += QString::fromUtf8("é");
    assert(NativeDisplayRestorationIntent::parse(frame(unicode)));
    unicode[0] += QChar(0x0085);
    assert(!NativeDisplayRestorationIntent::parse(frame(unicode)));

    // Fresh current facts are independently required after parsing. The guard
    // includes native source/ownership/identity, not just numeric geometry.
    NativeDisplaySnapshot snapshot;
    snapshot.generation = 5;
    for (quint64 handle : {7U, 8U, 9U}) {
        NativeDisplayHead head;
        head.handle = handle;
        head.generation = handle == 9 ? 5 : 4;
        head.name = QStringLiteral("DP-%1").arg(handle);
        head.modes = {{1280, 720, 60000}, {1920, 1080, 60000}};
        head.enabled = handle != 8;
        if (head.enabled) {
            head.current = head.modes[0];
            head.scaleFixed = 256;
            head.scaleMilli = 1000;
            head.scaleFloatBits = 0x3f800000U;
            head.x = handle == 9 ? 1280 : 0;
        }
        head.baseRuleDigest = QString(64, QLatin1Char('d'));
        head.outputIdentityDigest = QString(64, QLatin1Char('e'));
        snapshot.heads.push_back(head);
    }
    const auto guard = snapshot.baselineGuard(currentBaseline);
    assert(guard);
    auto currentFields = fields;
    currentFields[3] = *guard;
    const auto current = NativeDisplayRestorationIntent::parse(frame(currentFields));
    const auto lock = NativeLockIdentity::parse(newLock);
    assert(current && lock && current->nativeOptions(snapshot, newTopology, *lock));
    auto changed = snapshot;
    changed.heads[0].baseRuleDigest = QString(64, QLatin1Char('f'));
    assert(!current->nativeOptions(changed, newTopology, *lock));
    changed = snapshot;
    changed.heads[0].current = changed.heads[0].modes[1];
    assert(!current->nativeOptions(changed, newTopology, *lock));
    changed = snapshot;
    changed.heads[0].modes.pop_back();
    assert(!current->nativeOptions(changed, newTopology, *lock));
    changed = snapshot;
    changed.heads.pop_back();
    assert(!current->nativeOptions(changed, newTopology, *lock));
    assert(!current->nativeOptions(snapshot, oldTopology, *lock));
    NativeApprovalScope scope{*lock,
                              QStringLiteral("unix:uid:1000"),
                              QStringLiteral("request:v010:display-restoration:review"),
                              QStringLiteral("request:v010:display-restoration:review"),
                              QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
                              QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
                              QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
                              ApprovalPurpose::RestoreOriginalDisplay};
    scope.display = NativeDisplayApprovalBinding{
        frame(currentFields), {}, 1000, QStringLiteral("Restore original settings"), 1000};
    assert(scope.valid() && scope.isDisplay() && !scope.requiresSessionOwnerAuthentication());
    assert(QString::fromLatin1(scope.authenticationAction()) ==
           QStringLiteral("org.linura.authority.restore-original-display-layout"));
    assert(!scope.protectedDisplayDigest().isEmpty());
    const auto pages = nativeDisplayReviewPages(scope, snapshot);
    assert(pages && pages->size() == 7);
    assert(pages->front().heading.contains(QStringLiteral("Restore original")));
    assert(pages->at(1).explanation.contains(QStringLiteral("new administrator approval")));
    assert(pages->back().explanation.contains(QStringLiteral("cannot apply a different layout")));
    for (const auto purpose : {ApprovalPurpose::ApplyDisplay, ApprovalPurpose::KeepDisplay,
                               ApprovalPurpose::RevertDisplay, ApprovalPurpose::AuthenticateUnlock,
                               ApprovalPurpose::AuthenticateSuspend}) {
        auto other = scope;
        other.purpose = purpose;
        assert(!other.valid() && other.protectedDisplayDigest().isEmpty());
    }
    for (unsigned fault = 0; fault < 4; ++fault) {
        auto other = scope;
        if (fault == 0) {
            other.request = other.plan = QStringLiteral("request:v010:display-layout:review");
        } else if (fault == 1) {
            other.display->material = fields[4];
        } else if (fault == 2) {
            other.display->decisionDigest =
                QStringLiteral("sha256:") + QString(64, QLatin1Char('a'));
        } else {
            other.lock = *NativeLockIdentity::parse(oldLock);
        }
        assert(!other.valid());
    }
    quint64 now = 1;
    const NativeDisplayPromptStatus ready{5, 1, NativeDisplayPromptStatus::Phase::Ready};
    NativeApproval denied(*lock, [&] { return now; });
    assert(!denied.begin(scope, false) && !denied.begin(scope, true));
    assert(denied.beginDisplay(scope, ready, 999));
    assert(!denied.nativeCompleted(scope, true)); // No fresh PAM conversation.
    NativeApproval authenticated(*lock, [&] { return now; });
    assert(authenticated.beginDisplay(scope, ready, 999));
    assert(authenticated.nativePrompt(scope) && authenticated.nativeCompleted(scope, true));
    auto other = scope;
    other.purpose = ApprovalPurpose::ApplyDisplay;
    assert(!authenticated.consume(other));
    assert(authenticated.consume(scope) && !authenticated.consume(scope));
    NativeApproval expired(*lock, [&] { return now; });
    assert(expired.beginDisplay(scope, ready, 999));
    now = 1000;
    assert(!expired.nativePrompt(scope) && !expired.consume(scope));
}
