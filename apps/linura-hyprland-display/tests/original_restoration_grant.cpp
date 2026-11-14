#include "original_restoration_grant.h"
#include "original_finalization_intent.h"
#include "original_finalization_grant.h"
#include "original_native_release_grant.h"
#include "original_completion_grant.h"
#include "original_power_retirement.h"
#include "original_current_commit.h"
#include "original_final_retirement.h"
#include "original_successor_preparation.h"
#include "ordinary_release_grant.h"
#include "sealed_native_material.h"
#include "native_digest.h"
#include "native_baseline_guard.h"
#include "recovery_rule_fixture.h"

#include <cassert>
#include <fstream>
#include <iterator>

using namespace Linura::HyprlandDisplay;
namespace ReleaseCodec = OriginalNativeReleaseGrantCodec;
namespace {
std::string framed(const std::vector<std::string> &fields)
{
    std::string bytes;
    for (const auto &field : fields) {
        const auto size = static_cast<std::uint64_t>(field.size());
        for (unsigned shift = 64; shift != 0; shift -= 8)
            bytes += static_cast<char>((size >> (shift - 8)) & 255U);
        bytes += field;
    }
    return bytes;
}
void ordinaryReleaseComparison()
{
    // Synthetic mechanism comparison only. These bytes are not a Root grant,
    // protected approval, physical scanout or release qualification evidence.
    const std::string topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:"
                                 "seat0:33333333-3333-4333-8333-333333333333:3";
    const std::string lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:"
                             "22222222-2222-4222-8222-222222222222:1";
    const std::string request = "request:v010:display-layout:ordinary-original";
    const auto baseline = "LNDL:1;" + topology + ";1:2:enabled:1920:1080:60000:1000:0:0:0:-;";
    const auto desired = "LNDL:1;" + topology + ";1:2:enabled:1920:1080:60000:1000:0:100:0:-;";
    const auto original = "LNDI:1;" + lock + ';' + baseline + desired;
    const auto intent = OriginalGrantCodec::intent(original);
    assert(intent);
    const auto transaction = OriginalFinalizationCodec::transaction(request, lock);
    assert(transaction);
    const Correlation held{*transaction, std::string(64, 'a'), std::string(64, 'b'), 25'000};
    const Correlation release{"transaction:ordinary-release", std::string(64, 'c'),
                              std::string(64, 'd'), 20'000};
    for (const auto &outcome :
         {std::string("keep"), std::string("revert"), std::string("expired")}) {
        Snapshot current;
        current.generation = 3;
        current.securityEpoch = 1;
        current.coverage = Coverage::Unlocked;
        Head head;
        head.key = {1, 2};
        head.current = outcome == "keep" ? intent->desired.front() : intent->baseline.front();
        head.modes.push_back(head.current.mode);
        head.powered = true;
        head.baseRuleWitness = "bounded synthetic base rule";
        head.outputIdentityWitness = "bounded synthetic connector";
        current.heads.push_back(head);
        const auto source = nativeBaselineGuard(current, outcome == "keep" ? desired : baseline);
        assert(source);
        const std::vector<std::string> fields{request,
                                              held.dispatchDigest,
                                              std::string(64, 'e'),
                                              std::string(64, 'f'),
                                              std::string(64, '1'),
                                              "0",
                                              "9",
                                              *source,
                                              outcome,
                                              lock,
                                              original};
        const auto encode = [](const std::vector<std::string> &values) {
            std::string result = "LNOR:1;";
            for (const auto &value : values)
                result += std::to_string(value.size()) + ':' + value + ';';
            return result;
        };
        const auto material = encode(fields);
        const auto decoded = OrdinaryReleaseCodec::decode(material);
        assert(decoded && OrdinaryReleaseCodec::matchesHeld(*decoded, held, intent->baseline,
                                                            intent->desired, current));
        assert(!OrdinaryReleaseCodec::decode(material + 'x'));
        assert(
            !OrdinaryReleaseCodec::decode(std::string(OrdinaryReleaseCodec::MaxMaterial + 1, 'x')));
        for (const auto &[index, bad] :
             std::vector<std::pair<std::size_t, std::string>>{{0, ""},
                                                              {1, std::string(64, '0')},
                                                              {2, "invalid"},
                                                              {3, ""},
                                                              {4, std::string(64, 'G')},
                                                              {5, "00"},
                                                              {6, "0"},
                                                              {6, "09"},
                                                              {7, "invalid"},
                                                              {8, "unknown"},
                                                              {9, "session:lock:foreign"},
                                                              {10, "LNDI:2;"}}) {
            auto changed = fields;
            changed[index] = bad;
            assert(!OrdinaryReleaseCodec::decode(encode(changed)));
        }
        auto altered = current;
        altered.heads[0].current.x += 1;
        assert(!OrdinaryReleaseCodec::matchesHeld(*decoded, held, intent->baseline, intent->desired,
                                                  altered));
        altered = current;
        altered.heads[0].baseRuleWitness += 'x';
        assert(!OrdinaryReleaseCodec::matchesHeld(*decoded, held, intent->baseline, intent->desired,
                                                  altered));
        auto wrong = held;
        wrong.dispatchDigest[0] = 'c';
        assert(!OrdinaryReleaseCodec::matchesHeld(*decoded, wrong, intent->baseline,
                                                  intent->desired, current));
        const std::vector<std::string> preparation{"linura.native-display.ordinary-release.v1",
                                                   material,
                                                   release.transaction,
                                                   "0",
                                                   "1",
                                                   std::string(64, '2'),
                                                   std::string(64, '3'),
                                                   release.effectDigest,
                                                   release.dispatchDigest,
                                                   "1000",
                                                   "100",
                                                   "3000",
                                                   "2100"};
        const auto bytes = framed(preparation);
        assert(OrdinaryReleaseCodec::preparation(bytes, material, release, {1001, 101}));
        for (const auto now : {ClockSample{999, 101}, ClockSample{1001, 99}, ClockSample{3000, 101},
                               ClockSample{1001, 2100}})
            assert(!OrdinaryReleaseCodec::preparation(bytes, material, release, now));
        assert(!OrdinaryReleaseCodec::preparation(bytes + 'x', material, release, {1001, 101}));
        for (const auto &[index, bad] : std::vector<std::pair<std::size_t, std::string>>{
                 {0, "linura.native-display.retirement-preparation.v1"},
                 {1, material + 'x'},
                 {2, "transaction:foreign"},
                 {3, "00"},
                 {4, "0"},
                 {5, std::string(64, '0')},
                 {6, "invalid"},
                 {7, held.effectDigest},
                 {8, held.dispatchDigest},
                 {9, "0"},
                 {10, "0100"},
                 {11, "3001"},
                 {12, "2101"}}) {
            auto changed = preparation;
            changed[index] = bad;
            assert(!OrdinaryReleaseCodec::preparation(framed(changed), material, release,
                                                      {1001, 101}));
        }
    }
    StartupFence ordinary;
    int lease[2]{}, channel[2]{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel) == 0);
    assert(ordinary.retain(lease[0], true));
    assert(!ordinary.authenticatesGrantPeer(channel[0]));
    close(channel[1]);
    assert(!OrdinaryReleaseGrant::receive(ordinary, OwnedNativeFd{channel[0]}, release, "LNOR:1;"));
    assert(fcntl(channel[0], F_GETFD) == -1 && errno == EBADF);
    close(lease[1]);
    assert(!ordinary.authenticatesOrdinaryGrantPeer(-1));
}
void comparisonOnly(const std::string &material)
{
    // Root validates canonical material/effect/source semantics independently.
    // These tests exercise the bounded native comparison codec, not authority,
    // kernel continuity, authentication or an accepted restoration operation.
    const Correlation expected{"transaction:original-restoration", std::string(64, 'a'),
                               std::string(64, 'b'), 10};
    const std::vector<std::string> reservation{"linura.native-display.restoration-reservation.v1",
                                               expected.transaction,
                                               "0",
                                               "1",
                                               std::string(64, 'c'),
                                               std::string(64, 'd'),
                                               expected.effectDigest,
                                               expected.dispatchDigest,
                                               material};
    std::vector<std::string> projection{"linura.native-display.restoration-projection.v1",
                                        "efb50993780079460b0cbed1363e2166a2de1d9f",
                                        std::string(64, 'e'),
                                        "3",
                                        "3",
                                        "1",
                                        "2",
                                        "9",
                                        "5",
                                        "226:0:1",
                                        Test::RulePreimage,
                                        "1",
                                        "LNOT:1;1;2;1;1920;1080;60000;1000;0;0;0;0;0;",
                                        std::string(64, '1'),
                                        "2",
                                        "2",
                                        "7",
                                        "4",
                                        "226:0:2",
                                        Test::RulePreimage,
                                        "0",
                                        "",
                                        std::string(64, '2'),
                                        "3",
                                        "3",
                                        "8",
                                        "4",
                                        "226:0:3",
                                        Test::DisabledRulePreimage,
                                        "0",
                                        "",
                                        std::string(64, '3')};
    const auto bytes = framed(reservation), original = framed(projection);
    const auto decoded = OriginalGrantCodec::decode(bytes, original, expected);
    assert(decoded && decoded->material == material && decoded->originalGeneration == 3 &&
           decoded->heads.size() == 3);
    assert(decoded->heads[0].priorOverlay &&
           decoded->heads[0].priorOverlay->output == (OutputKey{1, 2}));
    assert(decoded->heads[1].replacement == (OutputKey{7, 4}) && !decoded->heads[1].priorOverlay);
    for (std::size_t size = 0; size < bytes.size(); ++size)
        assert(!OriginalGrantCodec::decode(std::string_view(bytes).substr(0, size), original,
                                           expected));
    for (std::size_t size = 0; size < original.size(); ++size)
        assert(!OriginalGrantCodec::decode(bytes, std::string_view(original).substr(0, size),
                                           expected));
    assert(!OriginalGrantCodec::decode(bytes + 'x', original, expected));
    assert(!OriginalGrantCodec::decode(bytes, original + 'x', expected));
    assert(!OriginalGrantCodec::decode(std::string(OriginalGrantCodec::MaxReservation + 1, 'x'),
                                       original, expected));
    for (const auto &[index, bad] : std::vector<std::pair<std::size_t, std::string>>{
             {0, "untrusted-projection"},
             {1, std::string(40, '0')},
             {2, std::string(64, '0')},
             {3, "03"},
             {3, "4"},
             {3, "18446744073709551615"},
             {4, "0"},
             {4, "17"},
             {5, "0"},
             {5, "18446744073709551615"},
             {7, "0"},
             {9, "226:64:1"},
             {9, "226:0:0"},
             {9, "226:0:1:2"},
             {10, "LNRL:1;"},
             {11, "2"},
             {12, "LNOT:1;"},
             {12, "LNOT:1;2;2;1;1920;1080;60000;1000;0;0;0;0;0;"},
             {13, std::string(64, 'G')},
             {14, "1"},
             {16, "9"},
             {17, "5"},
             {18, "226:0:1"},
             {21, "unexpected"}}) {
        auto changed = projection;
        changed[index] = bad;
        assert(!OriginalGrantCodec::decode(bytes, framed(changed), expected));
    }
    for (const auto index : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U}) {
        auto changed = reservation;
        changed[index] = index == 2 ? "00" : "invalid";
        assert(!OriginalGrantCodec::decode(framed(changed), original, expected));
    }
    for (const auto &bad :
         {"LNOT:1;1;2;0;0;0;0;0;0;1;0;0;0;", "LNOT:1;1;2;1;1920;1080;60000;499;0;0;0;0;0;",
          "LNOT:1;1;2;1;1920;1080;60000;1000;0;0;0;1;2;"})
        assert(!OriginalGrantCodec::target(bad));
}
std::string terminalMaterial(const OriginalFinalizationCodec::Intent &intent)
{
    std::string material = "LNRF:1;";
    for (const auto &value :
         {std::string(intent.restorationRequest), std::string(intent.restorationDispatch),
          std::string(intent.terminalLink), std::string(intent.sourceGuard),
          std::to_string(intent.postWriteEpoch), std::string(intent.currentLock),
          std::string(intent.restoration)})
        material += std::to_string(value.size()) + ':' + value + ';';
    return material;
}
// Bounded comparison only. Root's full codec and the genuine non-cloneable
// retirement handle separately bind this parent; this fixture grants nothing.
void successorComparison(const std::string &finalBytes)
{
    const std::string topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:"
                                 "seat0:44444444-4444-4444-8444-444444444444:3";
    const std::string lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c3:99:"
                             "22222222-2222-4222-8222-222222222222:1";
    const auto baselineText = "LNDL:1;" + topology + ";1:2:enabled:1920:1080:60000:1000:0:0:0:-;";
    const auto desiredText = "LNDL:1;" + topology + ";1:2:enabled:1920:1080:60000:1000:0:100:0:-;";
    const auto material = "LNDI:1;" + lock + ';' + baselineText + desiredText;
    const auto intent = OriginalGrantCodec::intent(material);
    assert(intent);
    Snapshot captured;
    captured.generation = 3;
    captured.securityEpoch = 1;
    captured.coverage = Coverage::Unlocked;
    Head head;
    head.key = {1, 2};
    head.current = intent->baseline.front();
    head.modes.push_back(head.current.mode);
    head.powered = true;
    captured.heads.push_back(head);
    const Correlation next{"transaction:next", std::string(64, 'a'), std::string(64, 'b'), 15000};
    const auto retired = nativeSha256(finalBytes);
    assert(retired);
    const auto parent = framed({"linura.native-display.released-current.v1", finalBytes,
                                std::string(64, '1'), "1100", "200", "3100", "2200"});
    const std::vector<std::string> fields{"linura.native-display.successor-preparation.v1",
                                          parent,
                                          material,
                                          next.transaction,
                                          "0",
                                          "1",
                                          std::string(64, '2'),
                                          std::string(64, '3'),
                                          next.effectDigest,
                                          next.dispatchDigest,
                                          std::string(64, '4'),
                                          std::string(64, '5'),
                                          "1200",
                                          "300",
                                          "3200",
                                          "2300"};
    const auto matches = [&](std::string_view bytes, ClockSample now = {1201, 301}) {
        return OriginalSuccessorCodec::matches(bytes, *retired, next, intent->baseline,
                                               intent->desired, captured, {1200, 300}, now,
                                               std::string(64, '5'));
    };
    const auto bytes = framed(fields);
    assert(matches(bytes));
    assert(!matches(bytes + 'x'));
    for (std::size_t index = 0; index < fields.size(); ++index) {
        auto changed = fields;
        changed[index] = "untrusted";
        assert(!matches(framed(changed)));
    }
    for (const auto now : {ClockSample{1199, 301}, ClockSample{1201, 299}, ClockSample{3200, 301},
                           ClockSample{1201, 2300}})
        assert(!matches(bytes, now));
    for (const auto &[index, bad] :
         std::vector<std::pair<std::size_t, std::string>>{{4, "00"},
                                                          {5, "0"},
                                                          {6, std::string(64, '0')},
                                                          {7, std::string(64, 'G')},
                                                          {10, std::string(64, '0')},
                                                          {11, std::string(64, '6')},
                                                          {12, "1199"},
                                                          {13, "301"},
                                                          {14, "3201"},
                                                          {15, "2301"}}) {
        auto changed = fields;
        changed[index] = bad;
        assert(!matches(framed(changed)));
    }
    assert(!OriginalSuccessorCodec::matches(bytes, std::string(64, '9'), next, intent->baseline,
                                            intent->desired, captured, {1200, 300}, {1201, 301},
                                            std::string(64, '5')));
    auto drifted = captured;
    drifted.heads.front().modes.clear();
    assert(!OriginalSuccessorCodec::matches(bytes, *retired, next, intent->baseline,
                                            intent->desired, drifted, {1200, 300}, {1201, 301},
                                            std::string(64, '5')));
}
void terminalComparison(const std::string &material)
{
    using namespace OriginalFinalizationCodec;
    const auto decoded = decode(material);
    assert(decoded && terminalMaterial(*decoded) == material);
    const Correlation terminal{"transaction:terminal", std::string(64, 'a'), std::string(64, 'b'),
                               10};
    auto continuation = terminal;
    assert(ReleaseCodec::continues(terminal, continuation));
    continuation.deadlineUnixMs = 9;
    assert(ReleaseCodec::continues(terminal, continuation));
    assert(continuation != terminal); // Original equality stays exact.
    for (const auto deadline : {0ULL, 11ULL}) {
        continuation.deadlineUnixMs = deadline;
        assert(!ReleaseCodec::continues(terminal, continuation));
    }
    for (unsigned field = 0; field < 3; ++field) {
        continuation = terminal;
        if (field == 0)
            continuation.transaction += 'x';
        else if (field == 1)
            continuation.effectDigest[0] = 'e';
        else
            continuation.dispatchDigest[0] = 'f';
        assert(!ReleaseCodec::continues(terminal, continuation));
    }
    const std::vector<std::string> reservation{"linura.native-display.finalization-reservation.v1",
                                               terminal.transaction,
                                               "0",
                                               "1",
                                               std::string(64, 'c'),
                                               std::string(64, 'd'),
                                               terminal.effectDigest,
                                               terminal.dispatchDigest,
                                               material};
    const auto bytes = framed(reservation);
    assert(OriginalFinalizationGrantCodec::matches(bytes, terminal, material));
    // Reject malformed terminal reservations directly as well as through the
    // nested native-release codec.
    for (std::size_t size = 0; size < bytes.size(); ++size)
        assert(!OriginalFinalizationGrantCodec::matches(std::string_view(bytes).substr(0, size),
                                                        terminal, material));
    assert(!OriginalFinalizationGrantCodec::matches(bytes + 'x', terminal, material));
    assert(!OriginalFinalizationGrantCodec::matches(
        std::string(OriginalGrantCodec::MaxReservation + 1, 'x'), terminal, material));
    const std::string controlBinding(64, '7');
    const std::string controlObservation(64, '8');
    const std::vector<std::string> retirement{
        "linura.native-display.retirement-preparation.v1",
        "7",
        controlBinding,
        controlObservation,
        bytes,
    };
    const auto releaseBytes = framed(retirement);
    const auto matchRelease = [&](std::string_view value, std::uint64_t version,
                                  std::string_view binding, std::string_view observation) {
        const ReleaseCodec::ControlAnchor anchor{version, binding, observation};
        return ReleaseCodec::matches(value, terminal, material, anchor);
    };
    assert(matchRelease(releaseBytes, 7, controlBinding, controlObservation));
    {
        // The completion parent is the exact previously authenticated native
        // spend. Its frame comparison must match a FRESH native/KMS sample.
        const Correlation restoration{"transaction:restored", std::string(64, '9'),
                                      std::string(64, 'a'), 15'000};
        NativeFirstFrameGate::Receipt actual{};
        actual.generation = 81;
        actual.securityEpoch = 19;
        actual.postWriteEpoch = 13;
        actual.observedUnixMs = 1010;
        actual.observedBootMs = 110;
        actual.deadlineUnixMs = 1200;
        actual.deadlineBootMs = 300;
        actual.completedCount = 1;
        actual.completed[0] = {{{2, 3}, 4, 5, 6, 7, true}, 8, 9};
        std::vector<std::string> fields{
            "linura.native-display.completion-preparation.v1",
            releaseBytes,
            std::string(64, '1'),
            std::string(64, '2'),
            restoration.transaction,
            restoration.effectDigest,
            "1001",
            "101",
            "1200",
            "300",
            "19",
            "1150",
            "1",
            "2",
            "3",
            "1",
            "4",
            "5",
            "7",
            "6",
            "8",
            "9",
        };
        const auto original = framed(fields);
        const auto match = [&](std::string_view bytes) {
            return OriginalCompletionGrantCodec::matches(bytes, releaseBytes, restoration, actual);
        };
        auto ordinaryFields = fields;
        ordinaryFields[0] = "linura.native-display.ordinary-completion.v1";
        ordinaryFields.insert(ordinaryFields.begin() + 10, "13");
        const auto ordinary = framed(ordinaryFields);
        const auto matchesOrdinary = [&](std::string_view bytes) {
            return OriginalCompletionGrantCodec::matches(bytes, releaseBytes, restoration, actual,
                                                         true);
        };
        assert(matchesOrdinary(ordinary));
        assert(!match(ordinary) && !matchesOrdinary(original));
        for (std::size_t size = 0; size < ordinary.size(); ++size)
            assert(!matchesOrdinary(std::string_view(ordinary).substr(0, size)));
        assert(!matchesOrdinary(ordinary + 'x'));
        for (const auto index : {0U, 1U, 4U, 5U, 8U, 9U, 10U, 11U, 13U, 14U, 15U, 18U, 20U, 22U}) {
            auto changed = ordinaryFields;
            changed[index] += '1';
            assert(!matchesOrdinary(framed(changed)));
        }
        const auto limit = match(original);
        assert(limit && limit->unixMs == 1150 && limit->bootMs == 300);
        for (std::size_t size = 0; size < original.size(); ++size)
            assert(!match(std::string_view(original).substr(0, size)));
        assert(!match(original + 'x'));
        assert(!match(std::string(OriginalCompletionGrantCodec::MaxPreparation + 1, 'x')));
        for (const auto &[index, bad] :
             std::vector<std::pair<std::size_t, std::string>>{{0, "other-purpose"},
                                                              {1, releaseBytes + 'x'},
                                                              {2, std::string(64, '0')},
                                                              {3, std::string(64, '1')},
                                                              {4, "transaction:foreign"},
                                                              {5, std::string(64, '8')},
                                                              {6, "01001"},
                                                              {6, "1011"},
                                                              {7, "111"},
                                                              {8, "1201"},
                                                              {9, "301"},
                                                              {10, "20"},
                                                              {11, "1010"},
                                                              {11, "1201"},
                                                              {12, "0"},
                                                              {12, "2"},
                                                              {13, "1"},
                                                              {14, "4"},
                                                              {15, "0"},
                                                              {16, "5"},
                                                              {17, "6"},
                                                              {18, "8"},
                                                              {19, "9"},
                                                              {20, "7"},
                                                              {21, "10"}}) {
            auto changed = fields;
            changed[index] = bad;
            assert(!match(framed(changed)));
        }

        // Native power uses the full separately prepared comparison, including
        // the tighter original BOOTTIME bound, on this same Root lifetime.
        auto current = actual;
        current.observedUnixMs = 1100;
        current.observedBootMs = 200;
        current.completed[0].spendHighWater = 9;
        current.completed[0].completedCommit = 10;
        std::vector<std::string> powerFields{"linura.native-display.power-retirement.v1",
                                             original,
                                             std::string(64, '3'),
                                             std::string(64, '4'),
                                             "1149",
                                             "1090",
                                             "190",
                                             "1290",
                                             "250",
                                             "1",
                                             "2",
                                             "3",
                                             "1",
                                             "4",
                                             "5",
                                             "7",
                                             "6",
                                             "9",
                                             "10"};
        const auto fingerprint = nativeSha256(original);
        assert(fingerprint);
        const auto powerMatches = [&](std::string_view bytes, ClockSample now = {1100, 200}) {
            return OriginalPowerRetirementCodec::matches(bytes, *fingerprint, current, now);
        };
        const auto powerBytes = framed(powerFields);
        assert(powerMatches(powerBytes));
        assert(!powerMatches(powerBytes, {1149, 249}));
        assert(!powerMatches(powerBytes, {1148, 250}));
        assert(!powerMatches(powerBytes, {1089, 200}));
        assert(!powerMatches(powerBytes, {1100, 189}));
        for (std::size_t size = 0; size < powerBytes.size(); ++size)
            assert(!powerMatches(std::string_view(powerBytes).substr(0, size)));
        assert(!powerMatches(powerBytes + 'x'));
        for (const auto &[index, bad] :
             std::vector<std::pair<std::size_t, std::string>>{{0, "wrong-purpose"},
                                                              {1, original + 'x'},
                                                              {2, std::string(64, '0')},
                                                              {3, std::string(64, '3')},
                                                              {4, "1151"},
                                                              {5, "01090"},
                                                              {9, "0"},
                                                              {10, "9"},
                                                              {12, "0"},
                                                              {16, "4294967296"},
                                                              {17, "8"},
                                                              {18, "11"}}) {
            auto changed = powerFields;
            changed[index] = bad;
            assert(!powerMatches(framed(changed)));
        }
        // Full committed-current comparison remains powerless without LNCF.
        auto rootFields = powerFields;
        rootFields[0] = "linura.native-display.root-retirement.v1";
        rootFields[1] = powerBytes;
        rootFields[2] = std::string(64, '5');
        rootFields[3] = std::string(64, '6');
        std::vector<std::string> committedFields{"linura.native-display.current-commit.v1",
                                                 framed(rootFields),
                                                 std::string(64, '9'),
                                                 std::string(64, 'a'),
                                                 "0",
                                                 "9",
                                                 controlBinding,
                                                 "1149",
                                                 "1090",
                                                 "190",
                                                 "1290",
                                                 "250",
                                                 "1",
                                                 "2",
                                                 "3",
                                                 "1",
                                                 "4",
                                                 "5",
                                                 "7",
                                                 "6",
                                                 "9",
                                                 "10"};
        const auto committedBytes = framed(committedFields);
        const auto committedMatches = [&](std::string_view bytes, ClockSample now = {1100, 200}) {
            return OriginalCurrentCommitCodec::matches(bytes, *fingerprint, current, now);
        };
        assert(committedMatches(committedBytes));
        assert(!committedMatches(committedBytes, {1149, 249}));
        assert(!committedMatches(committedBytes, {1148, 250}));
        for (std::size_t size = 0; size < committedBytes.size(); ++size)
            assert(!committedMatches(std::string_view(committedBytes).substr(0, size)));
        assert(!committedMatches(committedBytes + 'x'));
        for (const auto &[index, bad] :
             std::vector<std::pair<std::size_t, std::string>>{{0, "wrong-purpose"},
                                                              {1, framed(powerFields)},
                                                              {2, std::string(64, '0')},
                                                              {3, std::string(64, '9')},
                                                              {4, "1"},
                                                              {5, "8"},
                                                              {5, "09"},
                                                              {6, std::string(64, '8')},
                                                              {7, "1151"},
                                                              {8, "01090"},
                                                              {12, "0"},
                                                              {13, "9"},
                                                              {15, "0"},
                                                              {19, "4294967296"},
                                                              {20, "8"},
                                                              {21, "11"}}) {
            auto changed = committedFields;
            changed[index] = bad;
            assert(!committedMatches(framed(changed)));
        }
        // A final-retirement comparison is powerless without the distinct
        // one-use LNCA exchange on the actual committed-current Root channel.
        auto finalFields = powerFields;
        finalFields[0] = "linura.native-display.final-retirement.v1";
        finalFields[1] = committedBytes;
        finalFields[2] = std::string(64, 'b');
        finalFields[3] = std::string(64, 'c');
        const auto currentDigest = nativeSha256(committedBytes);
        assert(currentDigest);
        const auto finalMatches = [&](std::string_view bytes, ClockSample now = {1100, 200}) {
            return OriginalFinalRetirementCodec::matches(bytes, *currentDigest, current, now);
        };
        const auto finalBytes = framed(finalFields);
        assert(finalMatches(finalBytes));
        successorComparison(finalBytes);
        for (const auto now : {ClockSample{1149, 249}, ClockSample{1148, 250},
                               ClockSample{1089, 200}, ClockSample{1100, 189}})
            assert(!finalMatches(finalBytes, now));
        for (std::size_t size = 0; size < finalBytes.size(); ++size)
            assert(!finalMatches(std::string_view(finalBytes).substr(0, size)));
        assert(!finalMatches(finalBytes + 'x'));
        assert(!OriginalFinalRetirementCodec::matches(finalBytes, std::string(64, '1'), current,
                                                      {1100, 200}));
        for (const auto &[index, bad] :
             std::vector<std::pair<std::size_t, std::string>>{{0, "other-purpose"},
                                                              {1, powerBytes},
                                                              {2, std::string(64, '0')},
                                                              {3, std::string(64, 'b')},
                                                              {4, "1151"},
                                                              {5, "01090"},
                                                              {9, "0"},
                                                              {10, "9"},
                                                              {12, "0"},
                                                              {16, "4294967296"},
                                                              {17, "8"},
                                                              {18, "11"}}) {
            auto changed = finalFields;
            changed[index] = bad;
            assert(!finalMatches(framed(changed)));
        }
        ++current.completed[0].completedCommit;
        ++current.completed[0].kernel.framebuffer;
        assert(powerMatches(powerBytes)); // new buffer requires a newer commit
        --current.completed[0].completedCommit;
        assert(!powerMatches(powerBytes));
        auto other = actual;
        other.completed[0].completedCommit++;
        assert(!OriginalCompletionGrantCodec::matches(original, releaseBytes, restoration, other));
    }
    assert(!matchRelease(releaseBytes, 8, controlBinding, controlObservation));
    assert(!matchRelease(releaseBytes, 7, controlObservation, controlBinding));
    assert(!matchRelease(releaseBytes + 'x', 7, controlBinding, controlObservation));
    for (std::size_t size = 0; size < releaseBytes.size(); ++size) {
        const auto partial = std::string_view(releaseBytes).substr(0, size);
        assert(!matchRelease(partial, 7, controlBinding, controlObservation));
    }
    for (unsigned fault = 0; fault < 5; ++fault) {
        auto changed = retirement;
        changed[fault] = fault == 1 ? "07" : "invalid";
        assert(!matchRelease(framed(changed), 7, controlBinding, controlObservation));
    }
    for (const auto &[index, bad] : std::vector<std::pair<std::size_t, std::string>>{
             {0, "linura.native-display.restoration-reservation.v1"},
             {1, "transaction:other"},
             {2, "00"},
             {3, "0"},
             {3, "01"},
             {4, std::string(64, '0')},
             {5, std::string(64, 'G')},
             {6, std::string(64, 'e')},
             {7, std::string(64, 'f')},
             {8, "LNRF:1;"}}) {
        auto changed = reservation;
        changed[index] = bad;
        assert(!OriginalFinalizationGrantCodec::matches(framed(changed), terminal, material));
    }
    auto changed = *decoded;
    changed.sourceGuard = std::string(64, 'e');
    assert(!OriginalFinalizationGrantCodec::matches(bytes, terminal, terminalMaterial(changed)));
    std::array<int, 2> lease{}, grant{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease.data()) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, grant.data()) == 0);
    StartupFence fence;
    assert(fence.retain(lease[0], false));
    assert(close(grant[1]) == 0);
    // No actual Root producer or live transfer exists here. Denial consumes the
    // descriptor and cannot admit ordinary frames, even in root-run unit tests.
    timespec now{};
    assert(clock_gettime(CLOCK_BOOTTIME, &now) == 0 && now.tv_sec >= 0 && now.tv_nsec >= 0);
    const auto sampledBootMs = static_cast<std::uint64_t>(now.tv_sec) * 1000 +
                               static_cast<std::uint64_t>(now.tv_nsec) / 1'000'000;
    assert(!OriginalFinalizationGrant::receive(fence, OwnedNativeFd{grant[0]}, terminal, material,
                                               sampledBootMs));
    int releasePair[2]{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, releasePair) == 0);
    assert(close(releasePair[1]) == 0);
    const ReleaseCodec::ControlAnchor control{7, controlBinding, controlObservation};
    const auto denied = OriginalNativeReleaseGrant::receive(
        fence, OwnedNativeFd{releasePair[0]}, terminal, material, control, sampledBootMs);
    assert(!denied);
    assert(fcntl(releasePair[0], F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(grant[0], F_GETFD) == -1 && errno == EBADF);
    assert(fence.recoveryAvailable() && !fence.ordinaryAllowed());
    assert(close(lease[1]) == 0);
    assert(decoded->postWriteEpoch == 29 && decoded->sourceGuard == std::string(64, '3'));
    assert(transaction(decoded->restorationRequest, decoded->currentLock) ==
           std::optional<std::string>{
               "transaction:v1:ae393480ff2a701ad2b95c237c1fea76adcf9b866471d3550847c6eff3f519a4"});
    assert(!OriginalGrantCodec::intent(material) && !OriginalGrantCodec::materialFields(material));
    for (std::size_t size = 0; size < material.size(); ++size)
        assert(!decode(std::string_view(material).substr(0, size)));
    assert(!decode(material + 'x') && !decode(std::string(MaxMaterial + 1, 'x')));
    assert(!decode("LNRF:2;" + material.substr(7)));
    assert(!decode("LNRF:1;027:" + material.substr(10)));
    assert(!decode("LNRF:1;18446744073709551616:" + material.substr(10)));
    for (const auto &invalid :
         {std::string("\x80"), std::string("\xc0\xaf"), std::string("\xed\xa0\x80"),
          std::string("\xf4\x90\x80\x80"), std::string("\xe2\x82"), std::string("\xc2\x80"),
          std::string("\x7f"), std::string("\0", 1)}) {
        auto changed = *decoded;
        changed.restorationRequest = invalid;
        assert(!decode(terminalMaterial(changed)));
    }
    for (const auto &valid : {std::string("request with spaces"), std::string("r\xc3\xa9"),
                              std::string("r\xf0\x9f\x98\x80"), std::string("\xe2\x80\xa8")}) {
        auto changed = *decoded;
        changed.restorationRequest = valid;
        const auto encoded = terminalMaterial(changed);
        const auto roundtrip = decode(encoded);
        assert(roundtrip && roundtrip->restorationRequest == valid);
    }
    const auto nested = OriginalGrantCodec::materialFields(decoded->restoration);
    assert(nested);
    const auto replacement = OriginalGrantCodec::intent((*nested)[5]);
    assert(replacement);
    Snapshot snapshot;
    snapshot.generation = 5;
    for (const auto &target : replacement->desired) {
        Head head;
        head.key = target.output;
        head.current = target;
        head.baseRuleWitness = "actual native rules";
        head.outputIdentityWitness = "actual native identity";
        snapshot.heads.push_back(head);
    }
    const Correlation held{*transaction(decoded->restorationRequest, decoded->currentLock),
                           std::string(64, 'a'), std::string(decoded->restorationDispatch), 10};
    assert(!matchesHeld(*decoded, decoded->restoration, held, snapshot, 29));
    const auto guard = nativeBaselineGuard(snapshot, replacement->desiredText);
    assert(guard);
    auto valid = *decoded;
    valid.sourceGuard = *guard;
    assert(matchesHeld(valid, decoded->restoration, held, snapshot, 29));
    assert(!matchesHeld(valid, decoded->restoration, held, snapshot, 28));
    assert(!matchesHeld(valid, decoded->restoration, held, snapshot, 0));
    assert(!matchesHeld(valid, std::string(decoded->restoration) + 'x', held, snapshot, 29));
    for (unsigned fault = 0; fault != 8; ++fault) {
        auto changed = valid;
        auto correlation = held;
        auto facts = snapshot;
        if (fault == 0)
            changed.restorationRequest = (*nested)[0];
        if (fault == 1)
            changed.restorationDispatch = (*nested)[1];
        if (fault == 2)
            changed.currentLock = "session:lock:foreign";
        if (fault == 3)
            correlation.transaction += 'x';
        if (fault == 4)
            correlation.dispatchDigest[0] = 'a';
        if (fault == 5)
            facts.heads[0].baseRuleWitness += 'x';
        if (fault == 6)
            facts.heads[0].current.x = 1;
        if (fault == 7)
            ++facts.generation;
        assert(!matchesHeld(changed, decoded->restoration, correlation, facts, 29));
    }
    assert(!transaction("request", "session:lock:boot:4294967296:session"));
    assert(!transaction("request", "session:lock:boot:01000:session"));
    assert(!transaction("request", "session:lock:incomplete"));
}
void sealedMaterialTransport()
{
    using namespace SealedNativeMaterial;
    assert(!create("") && !create(std::string(MaxBytes + 1, 'x')));
    for (const auto &bytes : {std::string("comparison"), std::string(MaxBytes, 'x'),
                              std::string("embedded\0byte", 13)}) {
        const auto sealed = create(bytes);
        assert(sealed);
        assert(lseek(sealed->get(), 3, SEEK_SET) == 3);
        assert(pwrite(sealed->get(), "x", 1, 0) == -1 && errno == EPERM);
        const auto duplicate = dup(sealed->get());
        assert(duplicate >= 0);
        assert(SealedNativeMaterial::read(OwnedNativeFd{duplicate}) == std::optional(bytes));
        assert(fcntl(duplicate, F_GETFD) == -1 && errno == EBADF);
        assert(lseek(sealed->get(), 0, SEEK_CUR) == 3);
    }
    assert(!SealedNativeMaterial::read(OwnedNativeFd{-1}));
    for (const auto missing : {F_SEAL_WRITE, F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_SEAL}) {
        const auto descriptor = memfd_create("mutable-comparison", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert(descriptor >= 0 && write(descriptor, "x", 1) == 1);
        assert(fcntl(descriptor, F_ADD_SEALS, Seals & ~missing) == 0);
        assert(!SealedNativeMaterial::read(OwnedNativeFd{descriptor}));
        assert(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    }
    for (const auto size : {std::size_t{0}, MaxBytes + 1}) {
        const auto descriptor =
            memfd_create("invalid-size-comparison", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert(descriptor >= 0 && ftruncate(descriptor, static_cast<off_t>(size)) == 0);
        assert(fcntl(descriptor, F_ADD_SEALS, Seals) == 0);
        assert(!SealedNativeMaterial::read(OwnedNativeFd{descriptor}));
        assert(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    }
    int sockets[2]{}, pipes[2]{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(pipe2(pipes, O_CLOEXEC) == 0);
    // Neither an empty blocking socket nor an empty pipe is ever read.
    for (const auto descriptor : {sockets[0], pipes[0]}) {
        assert(!SealedNativeMaterial::read(OwnedNativeFd{descriptor}));
        assert(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    }
    close(sockets[1]);
    close(pipes[1]);
}

void unauthenticatedEndpoints()
{
    StartupFence fence;
    int lease[2]{}, grant[2]{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, grant) == 0);
    assert(fence.retain(lease[0], false));
    // Ordinary unprivileged sockets and serialized data cannot impersonate the
    // original Root peer. Actual Root positive admission is a native VM gate.
    const bool unprivileged = getuid() != 0 || getgid() != 0;
    if (!unprivileged) {
        // A Root test runner supplies an actual Root peer, so exercise an
        // incomplete closed stream. It is still never a positive native grant.
        if (grant[1] >= 0)
            close(grant[1]);
        grant[1] = -1;
    }
    assert(!OriginalRestorationGrant::receive(fence, OwnedNativeFd{grant[0]}, {}));
    assert(fcntl(grant[0], F_GETFD) == -1 && errno == EBADF);
    if (grant[1] >= 0)
        close(grant[1]);
    close(lease[1]);
}
void guardComparisonVector()
{
    // Shared with the Qt owner test. Independent SHA/framing vector only;
    // these synthetic witness bytes are never native authority evidence.
    Snapshot sample;
    Head head;
    head.key = {1, 2};
    head.baseRuleWitness = "abc";
    head.outputIdentityWitness = "identity";
    sample.heads.push_back(head);
    assert(nativeBaselineGuard(sample, "bounded comparison baseline") ==
           std::optional<std::string>{
               "ec6b56a675dc3e1dc66237ae9807dcf0b5f687369012e83b85caa903edba86a3"});
    sample.heads.push_back(head);
    sample.heads.back().key.generation = 3;
    assert(!nativeBaselineGuard(sample, "bounded comparison baseline"));
    sample.heads.pop_back();
    sample.heads[0].linuraOwned = true;
    assert(!nativeBaselineGuard(sample, "bounded comparison baseline"));
    std::string deadline(8, '\0');
    deadline.back() = 10;
    assert(OriginalGrantCodec::deadlineBinding(deadline, 10));
    assert(!OriginalGrantCodec::deadlineBinding(deadline, 11));
    assert(!OriginalGrantCodec::deadlineBinding(deadline, 0));
    assert(!OriginalGrantCodec::deadlineBinding(deadline + 'x', 10));
    assert(OriginalGrantCodec::freshSample(10, 2009));
    assert(!OriginalGrantCodec::freshSample(10, 2010));
    assert(!OriginalGrantCodec::freshSample(10, 9));
    assert(!OriginalGrantCodec::freshSample(0, 1));
}
} // namespace
int main(int argc, char **argv)
{
    assert(argc == 3);
    std::ifstream input(argv[1]);
    assert(input.good());
    std::string material{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    assert(material.ends_with('\n'));
    material.pop_back();
    assert(nativeSha256("") ==
           std::optional<std::string>{
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"});
    assert(nativeSha256("abc") ==
           std::optional<std::string>{
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"});
    comparisonOnly(material);
    ordinaryReleaseComparison();
    std::ifstream terminalInput(argv[2]);
    assert(terminalInput.good());
    std::string terminal{std::istreambuf_iterator<char>(terminalInput),
                         std::istreambuf_iterator<char>()};
    assert(terminal.ends_with('\n'));
    terminal.pop_back();
    terminalComparison(terminal);
    sealedMaterialTransport();
    guardComparisonVector();
    unauthenticatedEndpoints();
}
