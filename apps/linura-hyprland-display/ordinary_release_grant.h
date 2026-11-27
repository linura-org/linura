#pragma once

#include "ordinary_release_intent.h"

namespace Linura::HyprlandDisplay {
// One original Root endpoint, distinct from replacement restoration. It may
// spend only LNOW for the complete LNOR preparation. The ACK is before-effect
// correlation; it never proves frames, retires input/power, or completes Control.
class OrdinaryReleaseGrant final
{
  public:
    OrdinaryReleaseGrant(const OrdinaryReleaseGrant &) = delete;
    OrdinaryReleaseGrant &operator=(const OrdinaryReleaseGrant &) = delete;
    [[nodiscard]] static std::unique_ptr<OrdinaryReleaseGrant> receive(StartupFence &fence,
                                                                       OwnedNativeFd descriptor,
                                                                       const Correlation &release,
                                                                       std::string_view material)
    {
        auto result = std::unique_ptr<OrdinaryReleaseGrant>(
            new OrdinaryReleaseGrant(fence, std::move(descriptor)));
        const auto now = result->clock();
        if (!now || !fence.authenticatesOrdinaryGrantPeer(result->descriptor_.get()) ||
            now->bootMs > std::numeric_limits<std::uint64_t>::max() - 2000)
            return {};
        const auto deadline = now->bootMs + 2000;
        std::string header(7, '\0'), length(8, '\0');
        if (!result->read(header, deadline) || header != "LNOG:1\n" ||
            !result->read(length, deadline))
            return {};
        const auto size = OriginalGrantCodec::clockField(length);
        if (!size || *size > OrdinaryReleaseCodec::MaxPreparation)
            return {};
        std::string record(static_cast<std::size_t>(*size), '\0'), end(11, '\0');
        if (!result->read(record, deadline) || !result->read(end, deadline) ||
            end != "LNOG-END:1\n")
            return {};
        const auto sampled = result->clock();
        const auto window =
            sampled ? OrdinaryReleaseCodec::preparation(record, material, release, *sampled)
                    : std::nullopt;
        const auto digest = nativeSha256(record);
        if (!window || !digest)
            return {};
        result->window_ = *window;
        result->digest_ = *digest;
        result->record_ = std::move(record);
        return result;
    }
    [[nodiscard]] const std::string &record() const noexcept
    {
        return record_;
    }
    [[nodiscard]] const OrdinaryReleaseCodec::Window &window() const noexcept
    {
        return window_;
    }
    [[nodiscard]] bool spent() const noexcept
    {
        return acknowledged_ && !failed_ &&
               fence_.authenticatesOrdinaryGrantPeer(descriptor_.get());
    }
    [[nodiscard]] bool live()
    {
        const auto now = clock();
        return spent() && now && inside(*now);
    }
    [[nodiscard]] const std::string &comparisonDigest() const noexcept
    {
        return digest_;
    }
    [[nodiscard]] bool spend()
    {
        if (attempted_)
            return fail();
        attempted_ = true;
        const auto now = clock();
        if (!now || !inside(*now) || !OriginalGrantCodec::digest(digest_) ||
            now->bootMs > std::numeric_limits<std::uint64_t>::max() - 1000)
            return fail();
        const auto deadline = std::min(now->bootMs + 1000, window_.deadline.bootMs);
        std::string request = "LNOW:1\n";
        request += '\0';
        constexpr std::uint64_t Sequence = 1;
        for (unsigned shift = 64; shift != 0; shift -= 8)
            request += static_cast<char>((Sequence >> (shift - 8)) & 255U);
        for (std::size_t i = 0; i < digest_.size(); i += 2) {
            const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            request += static_cast<char>((nibble(digest_[i]) << 4) | nibble(digest_[i + 1]));
        }
        std::string reply(48, '\0');
        if (request.size() != reply.size() ||
            !transfer(request.data(), request.size(), deadline, true) || !read(reply, deadline) ||
            reply != request)
            return fail();
        const auto after = clock();
        if (!after || !inside(*after))
            return fail();
        acknowledged_ = true;
        return true;
    }

  private:
    OrdinaryReleaseGrant(StartupFence &fence, OwnedNativeFd descriptor)
        : fence_(fence), descriptor_(std::move(descriptor))
    {}
    bool fail() noexcept
    {
        failed_ = true;
        return false;
    }
    [[nodiscard]] bool inside(ClockSample now) const noexcept
    {
        return now.unixMs >= window_.observed.unixMs && now.bootMs >= window_.observed.bootMs &&
               now.unixMs < window_.deadline.unixMs && now.bootMs < window_.deadline.bootMs;
    }
    [[nodiscard]] std::optional<ClockSample> clock()
    {
        const auto ms = [](clockid_t id) -> std::optional<std::uint64_t> {
            timespec sample{};
            if (clock_gettime(id, &sample) != 0 || sample.tv_sec < 0 || sample.tv_nsec < 0 ||
                sample.tv_nsec >= 1'000'000'000 ||
                static_cast<std::uint64_t>(sample.tv_sec) >
                    (std::numeric_limits<std::uint64_t>::max() - 999) / 1000)
                return {};
            return static_cast<std::uint64_t>(sample.tv_sec) * 1000 +
                   static_cast<std::uint64_t>(sample.tv_nsec) / 1'000'000;
        };
        const auto wall = ms(CLOCK_REALTIME), boot = ms(CLOCK_BOOTTIME);
        if (failed_ || !wall || !boot || *wall < last_.unixMs || *boot < last_.bootMs) {
            fail();
            return {};
        }
        last_ = {*wall, *boot};
        return last_;
    }
    [[nodiscard]] bool transfer(char *bytes, std::size_t size, std::uint64_t deadline, bool write)
    {
        while (size) {
            const auto now = clock();
            if (!now || now->bootMs >= deadline ||
                !fence_.authenticatesOrdinaryGrantPeer(descriptor_.get()))
                return fail();
            const auto count =
                write ? send(descriptor_.get(), bytes, size, MSG_DONTWAIT | MSG_NOSIGNAL)
                      : recv(descriptor_.get(), bytes, size, MSG_DONTWAIT);
            if (count > 0) {
                bytes += count;
                size -= static_cast<std::size_t>(count);
            } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd event{descriptor_.get(), static_cast<short>(write ? POLLOUT : POLLIN), 0};
                if (poll(&event, 1, static_cast<int>(deadline - now->bootMs)) != 1 ||
                    event.revents != event.events)
                    return fail();
            } else
                return fail();
        }
        const auto end = clock();
        return end && end->bootMs < deadline &&
                       fence_.authenticatesOrdinaryGrantPeer(descriptor_.get())
                   ? true
                   : fail();
    }
    [[nodiscard]] bool read(std::string &bytes, std::uint64_t deadline)
    {
        return transfer(bytes.data(), bytes.size(), deadline, false);
    }
    StartupFence &fence_;
    OwnedNativeFd descriptor_;
    std::string digest_, record_;
    OrdinaryReleaseCodec::Window window_{};
    ClockSample last_{};
    bool failed_ = false, attempted_ = false, acknowledged_ = false;
};
} // namespace Linura::HyprlandDisplay
