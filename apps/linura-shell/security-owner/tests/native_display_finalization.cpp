#include "native_display_finalization.h"
#include "native_approval.h"
#include "native_display_ordinary_release.h"
#include "native_display_review.h"

#include <QFile>
#include <cassert>

using namespace Linura::SecurityOwner;
namespace {
QString frame(const std::vector<QString> &fields)
{
    QString text = QStringLiteral("LNRF:1;");
    for (const auto &field : fields)
        text +=
            QString::number(field.toUtf8().size()) + QLatin1Char(':') + field + QLatin1Char(';');
    return text;
}
} // namespace

void terminalMaterialBoundaries()
{
    // This exact vector is also validated by linura-core. Parsing it is not
    // evidence of a native terminal interaction, current frame or release.
    QFile fixture(QString::fromUtf8(LINURA_DISPLAY_FINALIZATION_FIXTURE_PATH));
    assert(fixture.open(QIODevice::ReadOnly));
    auto bytes = fixture.read(NativeDisplayFinalizationIntent::MaxBytes + 1);
    assert(fixture.atEnd() && bytes.endsWith('\n'));
    bytes.chop(1);
    const auto text = QString::fromUtf8(bytes);
    assert(text.toUtf8() == bytes);
    const auto parsed = NativeDisplayFinalizationIntent::parse(text);
    assert(parsed && parsed->encode() == text && parsed->postWriteEpoch == 29);
    // Synthetic comparison vectors only: all normal terminal dispositions
    // need a fresh purpose, complete original intent and current source.
    const auto &original = parsed->restoration.original;
    for (const auto outcome : {NativeDisplayOrdinaryReleaseIntent::Outcome::Keep,
                               NativeDisplayOrdinaryReleaseIntent::Outcome::Revert,
                               NativeDisplayOrdinaryReleaseIntent::Outcome::Expired}) {
        NativeDisplayOrdinaryReleaseIntent ordinary{parsed->restoration.originalRequest,
                                                    parsed->restoration.originalDispatch,
                                                    QString(64, QLatin1Char('b')),
                                                    parsed->restoration.originalCheckpoint,
                                                    QString(64, QLatin1Char('d')),
                                                    QString(64, QLatin1Char('e')),
                                                    0,
                                                    9,
                                                    outcome,
                                                    original.lock,
                                                    original};
        const auto encoded = ordinary.encode();
        assert(!encoded.isEmpty());
        const auto decoded = NativeDisplayOrdinaryReleaseIntent::parse(encoded);
        assert(decoded && decoded->encode() == encoded);
        assert(decoded->expectedAttemptPhase() ==
               (outcome == NativeDisplayOrdinaryReleaseIntent::Outcome::Keep ? 4U : 5U));
        const auto projected = decoded->presentation();
        const auto &target = outcome == NativeDisplayOrdinaryReleaseIntent::Outcome::Keep
                                 ? original.desired
                                 : original.baseline;
        assert(projected.baseline.encode() == target.encode() &&
               projected.desired.encode() == target.encode());
        NativeDisplaySnapshot native;
        const auto generation =
            target.topology.mid(target.topology.lastIndexOf(':') + 1).toULongLong();
        native.generation = generation;
        for (const auto &row : target.outputs) {
            NativeDisplayHead head;
            head.handle = row.handle;
            head.generation = row.generation;
            head.name = QStringLiteral("DP-%1").arg(row.handle);
            head.modes = {{1280, 720, 60000}, {1920, 1080, 60000}};
            head.enabled = row.enabled;
            if (row.enabled) {
                head.current = row.mode;
                head.x = row.x;
                head.y = row.y;
                head.transform = static_cast<qint32>(row.transform);
                head.scaleFixed = 256;
                head.scaleMilli = 1000;
                head.scaleFloatBits = 0x3f800000U;
            }
            head.baseRuleDigest = QString(64, QLatin1Char('d'));
            head.outputIdentityDigest = QString(64, QLatin1Char('e'));
            native.heads.push_back(head);
        }
        const auto source = native.baselineGuard(target.encode());
        assert(source);
        ordinary.sourceGuard = *source;
        assert(ordinary.matchesCurrent(native, target.topology, original.lock));
        auto drift = native;
        drift.heads[0].outputIdentityDigest = QString(64, QLatin1Char('f'));
        assert(!ordinary.matchesCurrent(drift, target.topology, original.lock));
        ++drift.generation;
        assert(!ordinary.matchesCurrent(drift, target.topology, original.lock));
        assert(!ordinary.matchesCurrent(native, target.topology + QLatin1Char('x'), original.lock));
        for (unsigned fault = 0; fault < 7; ++fault) {
            auto excessive = ordinary;
            if (fault == 0)
                excessive.original.baseline.outputs.resize(17);
            else if (fault == 1)
                excessive.original.desired.topology = QString(257, QLatin1Char('x'));
            else if (fault == 2)
                excessive.currentLock.uid += 1;
            else if (fault == 3)
                excessive.stateVersion = 0;
            else if (fault == 4)
                excessive.outcome = static_cast<NativeDisplayOrdinaryReleaseIntent::Outcome>(3);
            else if (fault == 5)
                excessive.sourceGuard = QString(64, QLatin1Char('0'));
            else
                excessive.originalRequest = QString(129, QChar(0x00e9));
            assert(excessive.encode().isEmpty());
            assert(!excessive.matchesCurrent(native, target.topology, original.lock));
        }
        for (qsizetype length = 0; length < encoded.size(); ++length)
            assert(!NativeDisplayOrdinaryReleaseIntent::parse(encoded.left(length)));
        assert(!NativeDisplayOrdinaryReleaseIntent::parse(encoded + QStringLiteral("0:;")));
        assert(!NativeDisplayFinalizationIntent::parse(encoded));
        assert(!NativeDisplayOrdinaryReleaseIntent::parse(text));
        NativeApprovalScope review{
            original.lock,
            QStringLiteral("unix:uid:1000"),
            QStringLiteral("request:v010:display-ordinary-release:review"),
            QStringLiteral("request:v010:display-ordinary-release:review"),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
            ApprovalPurpose::ReleaseOrdinaryDisplay,
            std::nullopt,
            NativeDisplayApprovalBinding{
                ordinary.encode(), {}, 1000, QStringLiteral("Finish the display change"), 900}};
        assert(review.valid());
        assert(QString::fromLatin1(review.authenticationAction()) ==
               QStringLiteral("org.linura.authority.release-ordinary-display"));
        const auto pages = nativeDisplayReviewPages(review, native);
        assert(pages && pages->front().heading == QStringLiteral("Finish this display change?"));
        for (auto purpose :
             {ApprovalPurpose::ApplyDisplay, ApprovalPurpose::KeepDisplay,
              ApprovalPurpose::RevertDisplay, ApprovalPurpose::RestoreOriginalDisplay,
              ApprovalPurpose::FinalizeOriginalDisplay}) {
            auto changed = review;
            changed.purpose = purpose;
            assert(!changed.valid());
        }
        auto changed = review;
        changed.display->decisionDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('4'));
        assert(!changed.valid());
        quint64 clock = 100;
        NativeApproval fresh(review.lock, [&] { return clock; });
        NativeDisplayPromptStatus ready{generation, 7, NativeDisplayPromptStatus::Phase::Ready};
        assert(!fresh.begin(review, true));
        assert(fresh.beginDisplay(review, ready, 60'000));
        assert(fresh.nativePrompt(review) && fresh.nativeCompleted(review, true));
        assert(fresh.consume(review) && !fresh.consume(review));
    }
    for (quint32 phase = 0; phase < 8; ++phase) {
        assert(NativeDisplayOrdinaryReleaseIntent::terminalAttemptPhase(phase) ==
               (phase == 4U || phase == 5U));
        assert(NativeDisplayOrdinaryReleaseIntent::retainedAttemptPhase(phase) ==
               (phase >= 2U && phase <= 5U));
    }
    assert(parsed->restorationRequest == QStringLiteral("restore-before-finalization"));
    assert(parsed->currentLock == parsed->restoration.replacement.lock);
    auto fields = std::vector<QString>{parsed->restorationRequest,
                                       parsed->restorationDispatch,
                                       parsed->terminalLink,
                                       parsed->restoredSourceGuard,
                                       QString::number(parsed->postWriteEpoch),
                                       parsed->currentLock.resource,
                                       parsed->restoration.encode()};
    assert(frame(fields) == text);
    assert(!NativeDisplayFinalizationIntent::parse(parsed->restoration.encode()));
    for (qsizetype size = 0; size < text.size(); ++size)
        assert(!NativeDisplayFinalizationIntent::parse(text.left(size)));
    for (const auto &suffix : {QStringLiteral(";"), QStringLiteral("0:;"), QString(QChar(0))})
        assert(!NativeDisplayFinalizationIntent::parse(text + suffix));
    assert(!NativeDisplayFinalizationIntent::parse(
        QString(NativeDisplayFinalizationIntent::MaxBytes + 1, QLatin1Char('x'))));
    auto version = text;
    version.replace(5, 1, QStringLiteral("2"));
    assert(!NativeDisplayFinalizationIntent::parse(version));
    const auto firstLength = QString::number(fields[0].toUtf8().size());
    for (const auto &length :
         {QStringLiteral("0") + firstLength, QStringLiteral("+") + firstLength,
          QStringLiteral(" ") + firstLength, QStringLiteral("18446744073709551616")}) {
        auto changed = text;
        changed.replace(7, firstLength.size(), length);
        assert(!NativeDisplayFinalizationIntent::parse(changed));
    }
    for (const auto index : {1U, 2U, 3U}) {
        for (const auto &invalid : {QString(64, QLatin1Char('0')), QString(64, QLatin1Char('A')),
                                    QString(63, QLatin1Char('a'))}) {
            auto changed = fields;
            changed[index] = invalid;
            assert(!NativeDisplayFinalizationIntent::parse(frame(changed)));
        }
    }
    for (const auto &invalid : {QStringLiteral("0"), QStringLiteral("029"), QStringLiteral("+29"),
                                QStringLiteral("18446744073709551616")}) {
        auto changed = fields;
        changed[4] = invalid;
        assert(!NativeDisplayFinalizationIntent::parse(frame(changed)));
    }
    for (unsigned fault = 0; fault < 7; ++fault) {
        auto changed = fields;
        if (fault == 0)
            changed[0] = parsed->restoration.originalRequest;
        else if (fault == 1)
            changed[1] = parsed->restoration.originalDispatch;
        else if (fault == 2)
            changed[5] = parsed->restoration.original.lock.resource;
        else if (fault == 3)
            changed[5].replace(QStringLiteral(":1000:"), QStringLiteral(":1001:"));
        else if (fault == 4)
            changed[5].replace(QStringLiteral(":43:"), QStringLiteral(":44:"));
        else if (fault == 5)
            changed[6] = parsed->restoration.original.encode();
        else
            changed[6] += QStringLiteral("0:;");
        assert(!NativeDisplayFinalizationIntent::parse(frame(changed)));
    }
    // Bounds refer to UTF-8 bytes, not QString's UTF-16 length. Non-ASCII
    // comparison IDs remain allowed just as in the canonical core contract.
    auto unicode = fields;
    unicode[0] += QString::fromUtf8("é");
    assert(NativeDisplayFinalizationIntent::parse(frame(unicode)));
    unicode[0] += QChar(0x0085);
    assert(!NativeDisplayFinalizationIntent::parse(frame(unicode)));
    unicode[0] = QString(129, QChar(0x00e9));
    assert(!NativeDisplayFinalizationIntent::parse(frame(unicode)));
    unicode[0] = QString(QChar(0xd800));
    assert(!NativeDisplayFinalizationIntent::parse(frame(unicode)));

    // A current same-login owner/generation may differ in the comparison codec;
    // it still needs independent current authentication and native admission.
    auto rotated = fields;
    rotated[5].replace(QStringLiteral("44444444-4444-4444-8444-444444444444:1"),
                       QStringLiteral("55555555-5555-4555-8555-555555555555:17"));
    const auto current = NativeDisplayFinalizationIntent::parse(frame(rotated));
    assert(current && current->currentLock != parsed->currentLock);

    NativeDisplaySnapshot snapshot;
    snapshot.generation = 5;
    const auto &restored = current->restoration.replacement.desired;
    for (const auto &row : restored.outputs) {
        NativeDisplayHead head;
        head.handle = row.handle;
        head.generation = row.generation;
        head.name = QStringLiteral("DP-%1").arg(row.handle);
        head.modes = {{1280, 720, 60000}, {1920, 1080, 60000}};
        head.enabled = row.enabled;
        if (row.enabled) {
            head.current = row.mode;
            head.x = row.x;
            head.y = row.y;
            head.transform = static_cast<qint32>(row.transform);
            head.scaleFixed = 256;
            head.scaleMilli = 1000;
            head.scaleFloatBits = 0x3f800000U;
        }
        head.baseRuleDigest = QString(64, QLatin1Char('d'));
        head.outputIdentityDigest = QString(64, QLatin1Char('e'));
        snapshot.heads.push_back(head);
    }
    const auto guard = snapshot.baselineGuard(restored.encode());
    assert(guard);
    auto material = *current;
    material.restoredSourceGuard = *guard;
    assert(material.matchesRestored(snapshot, restored.topology, material.currentLock, 29));
    for (unsigned fault = 0; fault < 8; ++fault) {
        auto changed = snapshot;
        auto other = material;
        if (fault == 0)
            changed.generation += 1;
        else if (fault == 1)
            changed.heads[0].current = NativeDisplayMode{1280, 720, 60000};
        else if (fault == 2)
            changed.heads[0].baseRuleDigest = QString(64, QLatin1Char('f'));
        else if (fault == 3)
            changed.heads[0].outputIdentityDigest = QString(64, QLatin1Char('f'));
        else if (fault == 4)
            other.restoredSourceGuard = other.restoration.replacementBaselineGuard;
        else if (fault == 5)
            other.postWriteEpoch += 1;
        else if (fault == 6)
            other.currentLock = parsed->currentLock;
        else
            other.restorationRequest = other.restoration.originalRequest;
        assert(!other.matchesRestored(changed, restored.topology, material.currentLock, 29));
    }
    assert(!material.matchesRestored(snapshot, restored.topology + QLatin1Char('x'),
                                     material.currentLock, 29));
    assert(!material.matchesRestored(snapshot, restored.topology, material.currentLock, 0));
    assert(material.matchesRestored(snapshot, restored.topology, material.currentLock, 29));

    for (unsigned fault = 0; fault < 6; ++fault) {
        auto excessive = material;
        if (fault == 0)
            excessive.restorationRequest = QString(257, QLatin1Char('x'));
        else if (fault == 1)
            excessive.restoration.replacement.baseline.topology = QString(257, QLatin1Char('x'));
        else if (fault == 2)
            excessive.restoration.original.baseline.outputs.resize(17);
        else if (fault == 3)
            excessive.restoration.originalRequest = QString(257, QLatin1Char('x'));
        else if (fault == 4)
            excessive.currentLock.uid += 1;
        else
            excessive.restoration.replacement.lock.generation += 1;
        assert(excessive.encode().isEmpty());
        assert(!excessive.matchesRestored(snapshot, restored.topology, material.currentLock, 29));
    }

    // Existing purposes cannot acquire terminal scope from these new bytes.
    NativeApprovalScope scope{
        parsed->currentLock,
        QStringLiteral("unix:uid:1000"),
        QStringLiteral("request:v010:display-restoration:review"),
        QStringLiteral("request:v010:display-restoration:review"),
        QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
        QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
        QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
        ApprovalPurpose::RestoreOriginalDisplay,
        std::nullopt,
        NativeDisplayApprovalBinding{text, {}, 1000, QStringLiteral("Finish recovery"), 900}};
    assert(!scope.valid() && scope.protectedDisplayDigest().isEmpty());
    scope.purpose = ApprovalPurpose::ApplyDisplay;
    scope.request = scope.plan = QStringLiteral("request:v010:display-layout:review");
    assert(!scope.valid() && scope.protectedDisplayDigest().isEmpty());
    scope.purpose = ApprovalPurpose::FinalizeOriginalDisplay;
    scope.request = scope.plan = QStringLiteral("request:v010:display-finalization:review");
    assert(scope.valid() && scope.isDisplay() && !scope.requiresSessionOwnerAuthentication());
    assert(QString::fromLatin1(scope.authenticationAction()) ==
           QStringLiteral("org.linura.authority.finalize-original-display-restoration"));
    const auto digest = scope.protectedDisplayDigest();
    const auto presentation = nativeDisplayApprovalIntent(scope);
    assert(digest.size() == 64 && presentation &&
           presentation->baseline.encode() == parsed->restoration.replacement.desired.encode() &&
           presentation->desired.encode() == presentation->baseline.encode());
    auto substitute = scope;
    substitute.reviewDigest[7] = QLatin1Char('4');
    assert(substitute.protectedDisplayDigest() != digest);
    substitute = scope;
    substitute.display->decisionDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('4'));
    assert(!substitute.valid());
    substitute = scope;
    substitute.display->material = parsed->restoration.encode();
    assert(!substitute.valid());
    for (const auto &prefix :
         {QStringLiteral("display-layout"), QStringLiteral("display-restoration"),
          QStringLiteral("session-lock"), QStringLiteral("session-transition")}) {
        substitute = scope;
        substitute.request = substitute.plan =
            QStringLiteral("request:v010:") + prefix + QStringLiteral(":review");
        assert(!substitute.valid());
    }
    quint64 clock = 100;
    NativeApproval approval(scope.lock, [&] { return clock; });
    NativeDisplayPromptStatus ready{5, 7, NativeDisplayPromptStatus::Phase::Ready};
    assert(!approval.begin(scope, true)); // S17 is purpose-separated.
    assert(!approval.beginDisplay(scope, ready, 60'001));
    assert(approval.beginDisplay(scope, ready, 60'000));
    assert(approval.nativePrompt(scope) && approval.nativeCompleted(scope, true));
    substitute = scope;
    substitute.reviewDigest[7] = QLatin1Char('4');
    assert(!approval.consume(substitute));
    assert(approval.consume(scope) && !approval.consume(scope));
    auto currentScope = scope;
    currentScope.lock = material.currentLock;
    currentScope.display->material = material.encode();
    const auto pages = nativeDisplayReviewPages(currentScope, snapshot);
    assert(pages && pages->size() > restored.outputs.size());
    assert(pages->front().heading == QStringLiteral("Finish display recovery?"));
    assert(pages->back().explanation.contains(QStringLiteral("session-lock")));
    for (const auto &page : *pages)
        assert(!page.explanation.contains(QStringLiteral("15 seconds")));
    NativeApproval expired(scope.lock, [&] { return clock; });
    assert(expired.beginDisplay(scope, ready, 100));
    clock += 100;
    assert(!expired.nativeCompleted(scope, true) && !expired.consume(scope));
    NativeApproval cancelled(scope.lock, [&] { return clock; });
    assert(cancelled.beginDisplay(scope, ready, 100));
    cancelled.cancel();
    assert(!cancelled.nativeCompleted(scope, true) && !cancelled.consume(scope));
    const NativeDisplayPromptScope prompt{digest, NativeDisplayPromptScope::Purpose::Finalization,
                                          1000, 900};
    assert(prompt.valid());
    auto invalid = prompt;
    invalid.purpose = static_cast<NativeDisplayPromptScope::Purpose>(6);
    assert(!invalid.valid());
}
