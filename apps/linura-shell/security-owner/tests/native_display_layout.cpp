// Strict native adapter data/formatter fixtures only. No command is dispatched.
#include "native_display_layout.h"
#include "native_display_prompt.h"
#include "native_display_review.h"
#include <algorithm>
#include <cassert>

using namespace Linura::SecurityOwner;
int main()
{
    const NativeDisplayPromptScope validPrompt{QString(64, QLatin1Char('a')),
                                               NativeDisplayPromptScope::Purpose::Apply, 1000};
    assert(validPrompt.valid());
    for (const auto purpose :
         {NativeDisplayPromptScope::Purpose::Apply, NativeDisplayPromptScope::Purpose::Keep,
          NativeDisplayPromptScope::Purpose::Revert}) {
        auto prompt = validPrompt;
        prompt.purpose = purpose;
        assert(prompt.valid());
    }
    for (unsigned denial = 0; denial != 7; ++denial) {
        auto prompt = validPrompt;
        switch (denial) {
        case 0:
            prompt.digest = QString(64, QLatin1Char('0'));
            break;
        case 1:
            prompt.digest = QString(64, QLatin1Char('A'));
            break;
        case 2:
            prompt.digest = QString(63, QLatin1Char('a'));
            break;
        case 3:
            prompt.digest[0] = QChar(0x0100);
            break;
        case 4:
            prompt.digest[0] = QChar(0);
            break;
        case 5:
            prompt.deadlineUnixMs = 0;
            break;
        default:
            prompt.purpose = static_cast<NativeDisplayPromptScope::Purpose>(3);
            break;
        }
        assert(!prompt.valid());
    }

    const auto lock = NativeLockIdentity::parse(
        QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-"
                       "4222-8222-222222222222:1"));
    assert(lock);
    const QString scope = QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:"
                                         "1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3");
    NativeDisplaySnapshot observed;
    observed.generation = 3;
    NativeDisplayHead root;
    root.handle = 1;
    root.generation = 2;
    root.name = QStringLiteral("DP-1");
    root.enabled = true;
    root.modes = {{1920, 1080, 60000}, {1280, 720, 59940}};
    root.current = root.modes[0];
    root.scaleFixed = 256;
    root.scaleMilli = 1000;
    root.scaleFloatBits = 0x3f800000U;
    observed.heads.push_back(root);
    // Shared Rust/native vectors bind original ownership, rules, identity and
    // exact numeric baseline. Hashes alone cannot prove current geometry.
    const auto guardBaseline = QStringLiteral("LNDL:1;") + scope +
                               QStringLiteral(";1:2:enabled:1920:1080:59940:1250:0:0:0:-;");
    assert(!observed.baselineGuard(guardBaseline));
    auto guarded = observed;
    guarded.heads[0].baseRuleDigest = QString(64, QLatin1Char('a'));
    guarded.heads[0].outputIdentityDigest = QString(64, QLatin1Char('b'));
    assert(guarded.baselineGuard(guardBaseline) ==
           std::optional{
               QStringLiteral("3982e30fe93e501fb6940d694fe0e19da3d66c3dee2c3f23cd7165ff3b2f6948")});
    guarded.heads[0].linuraOwned = true;
    assert(!guarded.baselineGuard(guardBaseline));
    guarded.heads[0].ownedTarget = QStringLiteral("LNOT:1;1;2;1;1920;1080;59940;1250;0;0;0;0;0;");
    const auto originalGuard = guarded.baselineGuard(guardBaseline);
    assert(originalGuard ==
           std::optional{
               QStringLiteral("706b46fd9ed14f8a56238057e390924b131c5c134935e532faff42763292b21b")});
    auto drifted = guarded;
    drifted.heads[0].baseRuleDigest = QString(64, QLatin1Char('c'));
    assert(drifted.baselineGuard(guardBaseline) != originalGuard);
    drifted = guarded;
    drifted.heads[0].outputIdentityDigest = QString(64, QLatin1Char('c'));
    assert(drifted.baselineGuard(guardBaseline) != originalGuard);
    drifted = guarded;
    drifted.heads[0].ownedTarget.replace(QStringLiteral(";1250;"), QStringLiteral(";1000;"));
    assert(drifted.baselineGuard(guardBaseline) != originalGuard);
    drifted = guarded;
    drifted.heads[0].baseRuleDigest = QString(64, QLatin1Char('A'));
    assert(!drifted.baselineGuard(guardBaseline));
    auto twoGuarded = guarded;
    twoGuarded.heads[0].linuraOwned = false;
    twoGuarded.heads[0].ownedTarget.clear();
    auto disabledHead = guarded.heads[0];
    disabledHead.handle = 2;
    disabledHead.generation = 3;
    disabledHead.baseRuleDigest = QString(64, QLatin1Char('c'));
    disabledHead.outputIdentityDigest = QString(64, QLatin1Char('d'));
    disabledHead.ownedTarget = QStringLiteral("LNOT:1;2;3;0;0;0;0;0;0;0;0;0;0;");
    twoGuarded.heads.push_back(disabledHead);
    const auto twoGuardBaseline = guardBaseline + QStringLiteral("2:3:disabled;");
    const auto twoGuard = twoGuarded.baselineGuard(twoGuardBaseline);
    assert(twoGuard == std::optional{QStringLiteral(
                           "568c84130da7712c595748f4dc80408d63ef01f64cca8486ddb5907cccaea21d")});
    std::reverse(twoGuarded.heads.begin(), twoGuarded.heads.end());
    assert(twoGuarded.baselineGuard(twoGuardBaseline) == twoGuard);
    twoGuarded.heads[0].ownedTarget =
        QStringLiteral("LNOT:1;2;3;1;1920;1080;59940;1250;0;0;0;1;2;");
    const auto mirrorGuardBaseline =
        guardBaseline + QStringLiteral("2:3:enabled:1920:1080:59940:1250:0:0:0:1,2;");
    assert(twoGuarded.baselineGuard(mirrorGuardBaseline) ==
           std::optional{
               QStringLiteral("f5284e6c0630a02c97f4bf8c2ccadf9282e835e4285b28d2baec0e10ee691721")});
    drifted = guarded;
    drifted.heads.push_back(drifted.heads[0]);
    assert(!drifted.baselineGuard(guardBaseline));
    const auto baseline = QStringLiteral("LNDL:1;") + scope +
                          QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:0:0:-;");
    const auto desired = QStringLiteral("LNDL:1;") + scope +
                         QStringLiteral(";1:2:enabled:1280:720:59940:1250:1:-100:20:-;");
    const auto text =
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + baseline + desired;
    const auto intent = NativeDisplayIntent::parse(text);
    assert(intent && intent->encode() == text && intent->nativeOptions(observed, scope, *lock));
    NativeApprovalScope review{*lock,
                               QStringLiteral("unix:uid:1000"),
                               QStringLiteral("request:v010:display-layout:review"),
                               QStringLiteral("request:v010:display-layout:review"),
                               QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
                               QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
                               QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
                               ApprovalPurpose::ApplyDisplay};
    review.display = NativeDisplayApprovalBinding{
        text, {}, 1000, QStringLiteral("Make text easier to read"), 1000};
    const auto pages = nativeDisplayReviewPages(review, observed);
    assert(review.protectedDisplayDigest() ==
           QStringLiteral("1912667e4c6dda437542c3d34758044bdf6b575ce2aec12b6837e682bf92e907"));
    assert(pages && pages->size() == 4);
    assert(pages->at(0).explanation.contains(QStringLiteral("UID 1000")));
    assert(pages->at(0).explanation.contains(QStringLiteral("Security-sensitive")));
    assert(pages->at(1).explanation == review.display->reason);
    assert(pages->at(2).heading.startsWith(QStringLiteral("DP-1")));
    assert(pages->at(2).explanation.contains(QStringLiteral("1920 x 1080 at 60.000 Hz")));
    assert(pages->at(2).explanation.contains(QStringLiteral("1280 x 720 at 59.940 Hz")));
    assert(pages->at(2).explanation.contains(QStringLiteral("scale 1.250; 90 degrees")));
    assert(pages->at(2).explanation.contains(QStringLiteral("position (-100, 20)")));
    assert(pages->back().explanation.contains(QStringLiteral("separate protected decision")));
    auto changedReview = review;
    changedReview.display->reason = QString(2048, QLatin1Char('a'));
    const auto longPages = nativeDisplayReviewPages(changedReview, observed);
    assert(longPages && longPages->size() == 16);
    QString completeReason;
    for (std::size_t i = 1; i + 2 < longPages->size(); ++i)
        completeReason += longPages->at(i).explanation;
    assert(completeReason == changedReview.display->reason);
    changedReview.display->reason += QLatin1Char('a');
    assert(!nativeDisplayReviewPages(changedReview, observed));
    changedReview = review;
    changedReview.display->reason += QChar(0x202e); // Bidi override cannot disguise the effect.
    assert(!nativeDisplayReviewPages(changedReview, observed));
    auto staleReview = observed;
    ++staleReview.heads[0].generation;
    assert(!nativeDisplayReviewPages(review, staleReview));
    for (auto purpose : {ApprovalPurpose::KeepDisplay, ApprovalPurpose::RevertDisplay}) {
        changedReview = review;
        changedReview.purpose = purpose;
        assert(!nativeDisplayReviewPages(changedReview, observed));
        changedReview.display->decisionDigest =
            QStringLiteral("sha256:") + QString(64, QLatin1Char('4'));
        const auto decisionPages = nativeDisplayReviewPages(changedReview, observed);
        assert(decisionPages && decisionPages->size() == pages->size());
        assert(decisionPages->at(0).heading.startsWith(purpose == ApprovalPurpose::KeepDisplay
                                                           ? QStringLiteral("Keep")
                                                           : QStringLiteral("Revert")));
    }
    assert(intent->baseline.matchesGeometry(observed));
    auto missingPrecision = observed;
    missingPrecision.heads[0].scaleMilli = 0;
    assert(!intent->baseline.matchesGeometry(missingPrecision));
    auto changedPrecision = observed;
    ++changedPrecision.heads[0].scaleFloatBits;
    assert(!intent->baseline.matchesGeometry(changedPrecision));
    const auto thousandthIntent = NativeDisplayIntent::parse(
        QString(text).replace(QStringLiteral(":1250:"), QStringLiteral(":1251:")));
    assert(thousandthIntent && thousandthIntent->desired.nativeOptions(observed));
    assert(!intent->desired.matchesGeometry(observed));
    const auto commands = intent->desired.commands(observed);
    assert(commands.size() == 1 &&
           commands[0] == "/keyword monitor DP-1,1280x720@59.940,-100x20,1.250,transform,1");
    for (const auto &bad :
         {QString(text).replace(QStringLiteral("LNDI:1;"), QStringLiteral("LNDI:2;")),
          text + QLatin1Char('\n'), text + QStringLiteral("extra;"),
          QString(text).replace(QStringLiteral("1:2:enabled"), QStringLiteral("01:2:enabled")),
          QString(text).replace(QStringLiteral(":1250:"), QStringLiteral(":4001:")),
          QString(text).replace(QStringLiteral(":-100:"), QStringLiteral(":-0:")),
          QString(text).replace(QStringLiteral(":-100:"), QStringLiteral(":-65537:"))}) {
        assert(!NativeDisplayIntent::parse(bad));
    }
    auto replaced = observed;
    replaced.heads[0].generation++;
    assert(!intent->nativeOptions(replaced, scope, *lock));
    replaced = observed;
    replaced.heads[0].name = QStringLiteral("DP-1;keyword unsafe");
    assert(intent->desired.commands(replaced).empty());
    replaced = observed;
    replaced.heads[0].modes = {{1024, 768, 60000}};
    assert(intent->desired.commands(replaced).empty());
    assert(!intent->nativeOptions(observed, scope + QStringLiteral("0"), *lock));
    auto different = *lock;
    different.generation++;
    assert(!intent->nativeOptions(observed, scope, different));

    auto second = root;
    second.handle = 2;
    second.generation = 3;
    second.name = QStringLiteral("HDMI-A-1");
    observed.heads.push_back(second);
    observed.generation = 3;
    const auto twoBaseline =
        QString(baseline).append(QStringLiteral("2:3:enabled:1920:1080:60000:1000:0:1920:0:-;"));
    const auto mirrored =
        QString(baseline).append(QStringLiteral("2:3:enabled:1920:1080:60000:1000:0:0:0:1,2;"));
    const auto mirrorIntent = NativeDisplayIntent::parse(
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + twoBaseline + mirrored);
    assert(mirrorIntent && mirrorIntent->nativeOptions(observed, scope, *lock));
    review.display->material = mirrorIntent->encode();
    const auto mirrorPages = nativeDisplayReviewPages(review, observed);
    assert(mirrorPages && mirrorPages->size() == 5);
    assert(mirrorPages->at(3).heading.startsWith(QStringLiteral("HDMI-A-1")));
    assert(mirrorPages->at(3).explanation.contains(QStringLiteral("mirrors DP-1")));
    const auto mirrorCommands = mirrorIntent->desired.commands(observed);
    assert(mirrorCommands.size() == 2 && mirrorCommands[1].endsWith(",mirror,DP-1"));
    auto repeated = mirrorIntent->desired;
    repeated.outputs[1].x = 1920;
    assert(!repeated.nativeOptions(observed));
    repeated = mirrorIntent->desired;
    repeated.outputs[1] = repeated.outputs[0];
    assert(!repeated.nativeOptions(observed));
    assert(repeated.commands(observed).empty());
    auto ambiguous = observed;
    ambiguous.heads[1].name = ambiguous.heads[0].name;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.heads[1].handle = ambiguous.heads[0].handle;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.heads[1].generation = observed.generation + 1;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.generation = 0;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    const auto cyclic = NativeDisplayIntent::parse(
        QString(mirrorIntent->encode())
            .replace(QStringLiteral("1:2:enabled:1920:1080:60000:1000:0:0:0:-;"),
                     QStringLiteral("1:2:enabled:1920:1080:60000:1000:0:0:0:2,4;")));
    assert(cyclic && !cyclic->nativeOptions(observed, scope, *lock));
    const auto disabled = QString(baseline).append(QStringLiteral("2:3:disabled;"));
    const auto disabledIntent = NativeDisplayIntent::parse(
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + twoBaseline + disabled);
    assert(disabledIntent && disabledIntent->nativeOptions(observed, scope, *lock));
    review.display->material = disabledIntent->encode();
    const auto disabledPages = nativeDisplayReviewPages(review, observed);
    assert(disabledPages && disabledPages->at(3).explanation.endsWith(QStringLiteral("Disabled")));
    assert(disabledIntent->desired.commands(observed).back() ==
           "/keyword monitor HDMI-A-1,disable");
}
