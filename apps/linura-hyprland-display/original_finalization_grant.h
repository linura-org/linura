#pragma once

#include "original_finalization_intent.h"

namespace Linura::HyprlandDisplay {
namespace OriginalFinalizationGrantCodec {
// Comparison only. The caller must separately authenticate the actual Root
// endpoint and match this material against the actual consumed terminal scene.
inline bool matches(std::string_view bytes, const Correlation &expected, std::string_view material)
{
    if (bytes.empty() || bytes.size() > OriginalGrantCodec::MaxReservation ||
        !OriginalFinalizationCodec::decode(material))
        return false;
    std::array<std::string_view, 9> fields{};
    constexpr std::array<std::size_t, 9> bounds{
        64, 256, 20, 20, 64, 64, 64, 64, OriginalFinalizationCodec::MaxMaterial};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto field = OriginalGrantCodec::field(bytes, bounds[i]);
        if (!field)
            return false;
        fields[i] = *field;
    }
    const auto generation = OriginalGrantCodec::number(fields[2]);
    const auto state = OriginalGrantCodec::number(fields[3]);
    return bytes.empty() && fields[0] == "linura.native-display.finalization-reservation.v1" &&
           fields[1] == expected.transaction && generation && state && *state != 0 &&
           std::all_of(fields.begin() + 4, fields.begin() + 8, OriginalGrantCodec::digest) &&
           fields[6] == expected.effectDigest && fields[7] == expected.dispatchDigest &&
           fields[8] == material;
}
} // namespace OriginalFinalizationGrantCodec

// One original-Root channel, consumed even on denial. Quiescence retains every
// protection. There is deliberately no retirement, release or startup-admit API.
class OriginalFinalizationGrant final
{
  public:
    OriginalFinalizationGrant(const OriginalFinalizationGrant &) = delete;
    OriginalFinalizationGrant &operator=(const OriginalFinalizationGrant &) = delete;
    [[nodiscard]] static std::unique_ptr<OriginalFinalizationGrant>
    receive(StartupFence &fence, OwnedNativeFd descriptor, const Correlation &expected,
            std::string_view material, std::uint64_t expectedSampleBootMs)
    {
        auto result = std::unique_ptr<OriginalFinalizationGrant>(
            new OriginalFinalizationGrant(fence, std::move(descriptor)));
        const auto now = result->clock();
        if (!now || !fence.recoveryAvailable() || *now > std::numeric_limits<std::uint64_t>::max() - 2000 ||
            !OriginalGrantCodec::freshSample(expectedSampleBootMs, *now) ||
            !fence.authenticatesGrantPeer(result->descriptor_.get()))
            return {};
        const auto deadline = *now + 2000;
        std::string header(7, '\0'), length(8, '\0');
        if (!result->read(header, deadline) || header != "LNFT:1\n" ||
            !result->read(length, deadline))
            return {};
        const auto size = OriginalGrantCodec::clockField(length);
        if (!size || *size > OriginalGrantCodec::MaxReservation)
            return {};
        std::string reservation(static_cast<std::size_t>(*size), '\0');
        std::string dispatchDeadline(8, '\0'), sample(8, '\0'), end(11, '\0');
        if (!result->read(reservation, deadline) ||
            !OriginalFinalizationGrantCodec::matches(reservation, expected, material) ||
            !result->read(dispatchDeadline, deadline) ||
            !OriginalGrantCodec::deadlineBinding(dispatchDeadline, expected.deadlineUnixMs) ||
            !result->read(sample, deadline) ||
            !OriginalGrantCodec::deadlineBinding(sample, expectedSampleBootMs) ||
            !result->read(end, deadline) || end != "LNFT-END:1\n")
            return {};
        const auto digest = nativeSha256(reservation);
        const auto finished = result->clock();
        if (!digest || !finished ||
            !OriginalGrantCodec::freshSample(expectedSampleBootMs, *finished))
            return {};
        result->digest_ = *digest;
        result->sampledBootMs_ = expectedSampleBootMs;
        return result;
    }
    // Called only after the actual consumed scene verifies current source,
    // post-write epoch, opaque hardware frames and retired protected input.
    [[nodiscard]] bool quiesce()
    {
        const auto now = clock();
        if (quiescenceAttempted_ || sequence_ != 1 || !now ||
            !OriginalGrantCodec::freshSample(sampledBootMs_, *now))
            return fail();
        quiescenceAttempted_ = true;
        return probe(true);
    }
    [[nodiscard]] bool verify()
    {
        return sequence_ > 1 ? probe(false) : fail();
    }
    [[nodiscard]] bool live()
    {
        if (sequence_ <= 1 || lost_ || !fence_.authenticatesGrantPeer(descriptor_.get()))
            return fail();
        pollfd event{descriptor_.get(), POLLIN, 0};
        return poll(&event, 1, 0) == 0 && event.revents == 0 ? true : fail();
    }

  private:
    OriginalFinalizationGrant(StartupFence &fence, OwnedNativeFd descriptor)
        : fence_(fence), descriptor_(std::move(descriptor))
    {}
    bool fail() noexcept
    {
        lost_ = true;
        return false;
    }
    static std::optional<std::uint64_t> bootMs()
    {
        timespec clock{};
        if (clock_gettime(CLOCK_BOOTTIME, &clock) != 0 || clock.tv_sec < 0 || clock.tv_nsec < 0 ||
            clock.tv_nsec >= 1'000'000'000 ||
            static_cast<std::uint64_t>(clock.tv_sec) >
                (std::numeric_limits<std::uint64_t>::max() - 999) / 1000)
            return std::nullopt;
        return static_cast<std::uint64_t>(clock.tv_sec) * 1000 +
               static_cast<std::uint64_t>(clock.tv_nsec) / 1'000'000;
    }
    std::optional<std::uint64_t> clock()
    {
        const auto now = bootMs();
        if (lost_ || !now || *now < lastBootMs_) {
            fail();
            return std::nullopt;
        }
        lastBootMs_ = *now;
        return now;
    }
    bool transfer(char *bytes, std::size_t size, std::uint64_t deadline, bool write)
    {
        while (size != 0) {
            const auto now = clock();
            if (lost_ || !now || *now >= deadline ||
                !fence_.authenticatesGrantPeer(descriptor_.get()))
                return fail();
            const auto count =
                write ? send(descriptor_.get(), bytes, size, MSG_DONTWAIT | MSG_NOSIGNAL)
                      : recv(descriptor_.get(), bytes, size, MSG_DONTWAIT);
            if (count > 0) {
                const auto part = static_cast<std::size_t>(count);
                bytes += part;
                size -= part;
            } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd event{descriptor_.get(), static_cast<short>(write ? POLLOUT : POLLIN), 0};
                if (poll(&event, 1, static_cast<int>(deadline - *now)) != 1 ||
                    event.revents != event.events)
                    return fail();
            } else
                return fail();
        }
        const auto finished = clock();
        return finished && *finished < deadline && fence_.authenticatesGrantPeer(descriptor_.get())
                   ? true
                   : fail();
    }
    bool read(std::string &bytes, std::uint64_t deadline)
    {
        return transfer(bytes.data(), bytes.size(), deadline, false);
    }
    bool probe(bool quiesce)
    {
        const auto now = clock();
        if (!now || *now > std::numeric_limits<std::uint64_t>::max() - 1000 || lost_ ||
            sequence_ == std::numeric_limits<std::uint64_t>::max())
            return fail();
        const auto deadline = *now + 1000;
        std::string request = quiesce ? "LNFQ:1\n" : "LNFV:1\n";
        request += '\0';
        for (unsigned shift = 64; shift != 0; shift -= 8)
            request += static_cast<char>((sequence_ >> (shift - 8)) & 255U);
        for (std::size_t i = 0; i < digest_.size(); i += 2) {
            const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            request += static_cast<char>((nibble(digest_[i]) << 4) | nibble(digest_[i + 1]));
        }
        std::string reply(request.size(), '\0');
        if (!transfer(request.data(), request.size(), deadline, true) || !read(reply, deadline) ||
            reply != request)
            return fail();
        ++sequence_;
        return true;
    }
    StartupFence &fence_;
    OwnedNativeFd descriptor_;
    std::string digest_;
    std::uint64_t sampledBootMs_ = 0, sequence_ = 1, lastBootMs_ = 0;
    bool lost_ = false, quiescenceAttempted_ = false;
};
} // namespace Linura::HyprlandDisplay
