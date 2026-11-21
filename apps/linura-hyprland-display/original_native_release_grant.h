#pragma once

#include "original_finalization_grant.h"

namespace Linura::HyprlandDisplay {
namespace OriginalNativeReleaseGrantCodec {
inline constexpr std::size_t MaxReservation = OriginalGrantCodec::MaxReservation + 512;

// This is comparison only: original Root socket credentials, current terminal
// scene, protected hardware and Control durability must be checked separately.
struct ControlAnchor final
{
    std::uint64_t version;
    std::string_view binding, observation;
};
using Text = std::string_view;
// A separately prepared continuation may shorten the original execution
// window. It may never retarget the dispatch or extend that window. Keep
// Correlation's full equality for all original execution/observation callers.
inline bool continues(const Correlation &original, const Correlation &next)
{
    return next.transaction == original.transaction && next.effectDigest == original.effectDigest &&
           next.dispatchDigest == original.dispatchDigest && original.deadlineUnixMs &&
           next.deadlineUnixMs && next.deadlineUnixMs <= original.deadlineUnixMs;
}
inline bool matches(Text bytes, const Correlation &terminal, Text material, ControlAnchor anchor)
{
    if (bytes.empty() || bytes.size() > MaxReservation || !anchor.version ||
        !OriginalGrantCodec::digest(anchor.binding) ||
        !OriginalGrantCodec::digest(anchor.observation))
        return false;
    constexpr std::array<std::size_t, 5> bounds{64, 20, 64, 64, OriginalGrantCodec::MaxReservation};
    std::array<std::string_view, 5> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto field = OriginalGrantCodec::field(bytes, bounds[i]);
        if (!field)
            return false;
        fields[i] = *field;
    }
    if (!bytes.empty())
        return false;
    if (fields[0] != "linura.native-display.retirement-preparation.v1")
        return false;
    if (OriginalGrantCodec::number(fields[1]) != std::optional{anchor.version})
        return false;
    if (fields[2] != anchor.binding || fields[3] != anchor.observation)
        return false;
    return OriginalFinalizationGrantCodec::matches(fields[4], terminal, material);
}
} // namespace OriginalNativeReleaseGrantCodec

// A one-use ORIGINAL Root channel, not an unlocked display or a Control
// terminal receipt. It cannot release S17/input/power, startup or Root fences.
class OriginalNativeReleaseGrant final
{
  public:
    OriginalNativeReleaseGrant(const OriginalNativeReleaseGrant &) = delete;
    OriginalNativeReleaseGrant &operator=(const OriginalNativeReleaseGrant &) = delete;

    [[nodiscard]] static std::unique_ptr<OriginalNativeReleaseGrant>
    receive(StartupFence &fence, OwnedNativeFd descriptor, const Correlation &terminal,
            std::string_view material, OriginalNativeReleaseGrantCodec::ControlAnchor anchor,
            std::uint64_t sampledBootMs)
    {
        auto result = std::unique_ptr<OriginalNativeReleaseGrant>(
            new OriginalNativeReleaseGrant(fence, std::move(descriptor)));
        const auto now = result->clock();
        if (!now || !fence.recoveryAvailable() ||
            *now > std::numeric_limits<std::uint64_t>::max() - 2000 ||
            !OriginalGrantCodec::freshSample(sampledBootMs, *now) ||
            !fence.authenticatesGrantPeer(result->descriptor_.get()))
            return {};
        const auto deadline = *now + 2000;
        std::string header(7, '\0'), length(8, '\0');
        if (!result->read(header, deadline) || header != "LNRS:1\n" ||
            !result->read(length, deadline))
            return {};
        const auto size = OriginalGrantCodec::clockField(length);
        if (!size || *size > OriginalNativeReleaseGrantCodec::MaxReservation)
            return {};
        std::string reservation(static_cast<std::size_t>(*size), '\0');
        std::string dispatchDeadline(8, '\0'), sample(8, '\0'), end(11, '\0');
        if (!result->read(reservation, deadline))
            return {};
        if (!OriginalNativeReleaseGrantCodec::matches(reservation, terminal, material, anchor))
            return {};
        if (!result->read(dispatchDeadline, deadline))
            return {};
        if (!OriginalGrantCodec::deadlineBinding(dispatchDeadline, terminal.deadlineUnixMs))
            return {};
        if (!result->read(sample, deadline))
            return {};
        if (!OriginalGrantCodec::deadlineBinding(sample, sampledBootMs))
            return {};
        if (!result->read(end, deadline) || end != "LNRS-END:1\n")
            return {};
        const auto digest = nativeSha256(reservation);
        const auto finished = result->clock();
        if (!digest || !finished || !OriginalGrantCodec::freshSample(sampledBootMs, *finished))
            return {};
        result->digest_ = *digest;
        result->reservation_ = std::move(reservation);
        result->sampledBootMs_ = sampledBootMs;
        return result;
    }
    [[nodiscard]] const std::string &reservation() const noexcept
    {
        return reservation_;
    }

    // Root fsyncs LNRX before its one-use ACK. This ACK never proves physical
    // release or permits a second grant after loss/timeout.
    [[nodiscard]] bool spend()
    {
        const auto now = clock();
        if (attempted_ || !now || !OriginalGrantCodec::freshSample(sampledBootMs_, *now) ||
            !fence_.authenticatesGrantPeer(descriptor_.get()))
            return fail();
        attempted_ = true;
        if (digest_.size() != 64 || !OriginalGrantCodec::digest(digest_) ||
            *now > std::numeric_limits<std::uint64_t>::max() - 1000)
            return fail();
        std::string request = "LNRW:1\n";
        request += '\0';
        constexpr std::uint64_t Sequence = 1;
        for (unsigned shift = 64; shift != 0; shift -= 8)
            request += static_cast<char>((Sequence >> (shift - 8)) & 255U);
        for (std::size_t i = 0; i < digest_.size(); i += 2) {
            const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            request += static_cast<char>((nibble(digest_[i]) << 4) | nibble(digest_[i + 1]));
        }
        if (request.size() != 48)
            return fail();
        const auto deadline = *now + 1000;
        std::string reply(request.size(), '\0');
        if (!transfer(request.data(), request.size(), deadline, true))
            return fail();
        if (!read(reply, deadline))
            return fail();
        return reply == request ? true : fail();
    }

  private:
    OriginalNativeReleaseGrant(StartupFence &fence, OwnedNativeFd descriptor)
        : fence_(fence), descriptor_(std::move(descriptor))
    {}
    bool fail() noexcept
    {
        failed_ = true;
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
    [[nodiscard]] std::optional<std::uint64_t> clock()
    {
        const auto now = bootMs();
        if (failed_ || !now || *now < lastBootMs_) {
            fail();
            return std::nullopt;
        }
        lastBootMs_ = *now;
        return now;
    }
    [[nodiscard]] bool transfer(char *bytes, std::size_t size, std::uint64_t deadline, bool write)
    {
        while (size) {
            const auto now = clock();
            if (failed_ || !now || *now >= deadline ||
                !fence_.authenticatesGrantPeer(descriptor_.get()))
                return fail();
            const auto count =
                write ? send(descriptor_.get(), bytes, size, MSG_DONTWAIT | MSG_NOSIGNAL)
                      : recv(descriptor_.get(), bytes, size, MSG_DONTWAIT);
            if (count > 0) {
                bytes += count;
                size -= static_cast<std::size_t>(count);
            } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd event{descriptor_.get(), static_cast<short>(write ? POLLOUT : POLLIN), 0};
                if (poll(&event, 1, static_cast<int>(deadline - *now)) != 1 ||
                    event.revents != event.events)
                    return fail();
            } else {
                return fail();
            }
        }
        const auto end = clock();
        if (!end || *end >= deadline)
            return fail();
        return fence_.authenticatesGrantPeer(descriptor_.get()) ? true : fail();
    }
    [[nodiscard]] bool read(std::string &bytes, std::uint64_t deadline)
    {
        return transfer(bytes.data(), bytes.size(), deadline, false);
    }
    StartupFence &fence_;
    OwnedNativeFd descriptor_;
    std::string digest_, reservation_;
    std::uint64_t sampledBootMs_ = 0, lastBootMs_ = 0;
    bool failed_ = false, attempted_ = false;
};
} // namespace Linura::HyprlandDisplay
