#include "original_restoration_grant.h"
#include "native_digest.h"
#include "native_baseline_guard.h"
#include "recovery_rule_fixture.h"

#include <cassert>
#include <fstream>
#include <iterator>

using namespace Linura::HyprlandDisplay;
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
    assert(argc == 2);
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
    guardComparisonVector();
    unauthenticatedEndpoints();
}
