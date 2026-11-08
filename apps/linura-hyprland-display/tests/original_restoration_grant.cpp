#include "original_restoration_grant.h"
#include "original_finalization_intent.h"
#include "original_finalization_grant.h"
#include "original_native_release_grant.h"
#include "sealed_native_material.h"
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
void terminalComparison(const std::string &material)
{
    using namespace OriginalFinalizationCodec;
    const auto decoded = decode(material);
    assert(decoded && terminalMaterial(*decoded) == material);
    const Correlation terminal{"transaction:terminal", std::string(64, 'a'), std::string(64, 'b'),
                               10};
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
    using ReleaseCodec = OriginalNativeReleaseGrantCodec;
    const auto matchRelease = [&](std::string_view value, std::uint64_t version,
                                  std::string_view binding, std::string_view observation) {
        return ReleaseCodec::matches(value, terminal, material,
                                     {version, binding, observation});
    };
    assert(matchRelease(releaseBytes, 7, controlBinding, controlObservation));
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
    assert(!OriginalNativeReleaseGrant::receive(
        fence, OwnedNativeFd{releasePair[0]}, terminal, material, 7,
        controlBinding, controlObservation, sampledBootMs));
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
