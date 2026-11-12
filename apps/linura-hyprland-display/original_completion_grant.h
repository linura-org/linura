#pragma once

#include "original_native_release_grant.h"
#include "native_first_frame_gate.h"
#include "native_digest.h"

namespace Linura::HyprlandDisplay {
namespace OriginalCompletionGrantCodec {
inline constexpr std::size_t MaxPreparation =
    OriginalNativeReleaseGrantCodec::MaxReservation + 8 * 1024;

// Complete comparison against the original authenticated LNRX parent and a
// newly sampled physical receipt. Parsing cannot mint a live Root lifetime.
inline std::optional<ClockSample> matches(std::string_view bytes, std::string_view parent,
                                          const Correlation &restoration,
                                          const NativeFirstFrameGate::Receipt &physical)
{
    if (bytes.empty() || bytes.size() > MaxPreparation || parent.empty() ||
        !physical.completedCount || physical.completedCount > DisplayTransaction::MaxHeads)
        return {};
    const auto next = [&](std::size_t bound) { return OriginalGrantCodec::field(bytes, bound); };
    const auto domain = next(64), retained = next(OriginalNativeReleaseGrantCodec::MaxReservation);
    const auto preparation = next(64), verification = next(64);
    const auto transaction = next(256), effect = next(64);
    if (!domain || *domain != "linura.native-display.completion-preparation.v1" || !retained ||
        *retained != parent || !preparation || !verification ||
        !OriginalGrantCodec::digest(*preparation) || !OriginalGrantCodec::digest(*verification) ||
        *preparation == *verification || !transaction || *transaction != restoration.transaction ||
        !effect || *effect != restoration.effectDigest)
        return {};
    const auto number = [&]() -> std::optional<std::uint64_t> {
        const auto value = next(20);
        return value ? OriginalGrantCodec::number(*value) : std::nullopt;
    };
    const auto wall = number(), boot = number(), wallEnd = number(), bootEnd = number();
    const auto security = number(), expires = number(), count = number();
    if (!wall || !boot || !wallEnd || !bootEnd || !security || !expires || !count || !*wall ||
        !*boot || *wall > physical.observedUnixMs || *boot > physical.observedBootMs ||
        *wallEnd != physical.deadlineUnixMs || *bootEnd != physical.deadlineBootMs ||
        *wall >= *wallEnd || *boot >= *bootEnd || *wallEnd - *wall > 2000 ||
        *bootEnd - *boot > 2000 || *security != physical.securityEpoch ||
        *expires <= physical.observedUnixMs || *expires > *wallEnd ||
        *count != physical.completedCount)
        return {};
    for (std::size_t i = 0; i < physical.completedCount; ++i) {
        const auto &row = physical.completed[i];
        const auto &kms = row.kernel;
        for (const auto expected :
             {kms.key.handle, kms.key.generation, static_cast<std::uint64_t>(kms.active),
              static_cast<std::uint64_t>(kms.connector), static_cast<std::uint64_t>(kms.crtc),
              static_cast<std::uint64_t>(kms.plane), static_cast<std::uint64_t>(kms.framebuffer),
              row.spendHighWater, row.completedCommit}) {
            if (number() != std::optional{expected})
                return {};
        }
    }
    return bytes.empty() ? std::optional{ClockSample{*expires, *bootEnd}} : std::nullopt;
}
} // namespace OriginalCompletionGrantCodec

// Non-cloneable lifetime received from the SAME continuously held original
// supervised Root peer. This exact prepared continuation permits only the
// same-invocation native handoff after all original comparisons. Its transfer
// ACK cannot prove the post-effect state, retire power or complete Control.
class OriginalCompletionGrant final
{
  public:
    // Unforgeable, non-copyable lifetime. It is created only after the separate
    // original Root LNCF spend; raw comparison bytes or a bool cannot create it.
    class CommittedCurrent final
    {
      public:
        CommittedCurrent(const CommittedCurrent &) = delete;
        CommittedCurrent &operator=(const CommittedCurrent &) = delete;
        [[nodiscard]] bool live() const
        {
            return check_ && check_();
        }
        [[nodiscard]] const std::string &comparisonDigest() const noexcept
        {
            return digest_;
        }

      private:
        friend class OriginalCompletionGrant;
        CommittedCurrent(std::string digest, std::function<bool()> check)
            : digest_(std::move(digest)), check_(std::move(check))
        {}
        const std::string digest_;
        std::function<bool()> check_;
    };
    ~OriginalCompletionGrant()
    {
        liveness_->owner = nullptr;
    }
    OriginalCompletionGrant(const OriginalCompletionGrant &) = delete;
    OriginalCompletionGrant &operator=(const OriginalCompletionGrant &) = delete;
    [[nodiscard]] static std::unique_ptr<OriginalCompletionGrant>
    receive(StartupFence &fence, OwnedNativeFd descriptor, std::string_view expectedDigest,
            std::string_view parent, const Correlation &restoration,
            const NativeFirstFrameGate::Receipt &physical)
    {
        auto result = std::unique_ptr<OriginalCompletionGrant>(
            new OriginalCompletionGrant(fence, std::move(descriptor)));
        const auto now = result->clock();
        if (!now || !fence.recoveryAvailable() || !OriginalGrantCodec::digest(expectedDigest) ||
            now->bootMs > std::numeric_limits<std::uint64_t>::max() - 2000 ||
            !fence.authenticatesGrantPeer(result->descriptor_.get()) ||
            now->unixMs < physical.observedUnixMs || now->bootMs < physical.observedBootMs ||
            now->unixMs >= physical.deadlineUnixMs || now->bootMs >= physical.deadlineBootMs)
            return {};
        const auto deadline = std::min(now->bootMs + 2000, physical.deadlineBootMs);
        std::string header(7, '\0'), length(8, '\0');
        if (!result->read(header, deadline) || header != "LNCG:1\n" ||
            !result->read(length, deadline))
            return {};
        const auto size = OriginalGrantCodec::clockField(length);
        if (!size || !*size || *size > OriginalCompletionGrantCodec::MaxPreparation)
            return {};
        std::string record(static_cast<std::size_t>(*size), '\0'), end(11, '\0');
        if (!result->read(record, deadline) || !result->read(end, deadline) ||
            end != "LNCG-END:1\n")
            return {};
        const auto digest = nativeSha256(record);
        const auto bound =
            OriginalCompletionGrantCodec::matches(record, parent, restoration, physical);
        if (!digest || *digest != expectedDigest || !bound)
            return {};
        result->digest_ = *digest;
        result->expires_ = *bound;
        const auto finished = result->clock();
        if (!finished || finished->unixMs >= bound->unixMs || finished->bootMs >= bound->bootMs)
            return {};
        return result;
    }
    [[nodiscard]] bool transferLifetime()
    {
        if (attempted_ || sequence_ != 1)
            return fail();
        attempted_ = true;
        return probe(true);
    }
    [[nodiscard]] bool verify()
    {
        return sequence_ > 1 ? probe(false) : fail();
    }
    [[nodiscard]] bool retirePower(std::string_view preparation)
    {
        if (powerAttempted_ || !currentAttempted_ || !OriginalGrantCodec::digest(preparation) ||
            !live())
            return fail();
        powerAttempted_ = true;
        return probe(false, preparation);
    }
    [[nodiscard]] std::unique_ptr<CommittedCurrent> commitCurrent(std::string_view digest)
    {
        if (commitAttempted_ || !currentAttempted_ || !powerAttempted_ ||
            !OriginalGrantCodec::digest(digest) || !live()) {
            fail();
            return {};
        }
        commitAttempted_ = true;
        if (!probe(false, {}, digest))
            return {};
        committedDigest_ = std::string(digest);
        std::weak_ptr<Liveness> weak = liveness_;
        return std::unique_ptr<CommittedCurrent>(
            new CommittedCurrent(committedDigest_, [weak, digest = committedDigest_] {
                const auto scope = weak.lock();
                return scope && scope->owner && scope->owner->committedDigest_ == digest &&
                       scope->owner->live();
            }));
    }
    [[nodiscard]] bool live()
    {
        if (failed_ || sequence_ <= 1 || !fence_.authenticatesGrantPeer(descriptor_.get()))
            return fail();
        pollfd event{descriptor_.get(), POLLIN, 0};
        return poll(&event, 1, 0) == 0 && event.revents == 0 ? true : fail();
    }
    [[nodiscard]] const std::string &comparisonDigest() const noexcept
    {
        return digest_;
    }
    [[nodiscard]] bool handoffWindowCurrent()
    {
        const auto now = clock();
        return now && now->unixMs < expires_.unixMs && now->bootMs < expires_.bootMs && live();
    }
    // Called only at the actual compositor-thread handoff, after independent
    // first-frame comparison and input quarantine. It cannot admit a future
    // compositor or replace the continuously retained original Root endpoint.
    [[nodiscard]] bool admitCurrent(std::function<bool()> scopeAlive)
    {
        if (currentAttempted_ || !scopeAlive || !scopeAlive() || !handoffWindowCurrent() ||
            !verify() || !handoffWindowCurrent())
            return fail();
        currentAttempted_ = true;
        std::weak_ptr<Liveness> weak = liveness_;
        const bool admitted = fence_.admitCurrent([weak, scopeAlive = std::move(scopeAlive)] {
            const auto retained = weak.lock();
            if (!retained || !retained->owner || !retained->owner->live())
                return false;
            try {
                if (scopeAlive())
                    return true;
            } catch (...) {
                // Unsupported native state/observation failure is permanent.
            }
            retained->owner->invalidate();
            return false;
        });
        return admitted ? true : fail();
    }
    void invalidate() noexcept
    {
        (void)fail();
    }

  private:
    struct Liveness final
    {
        OriginalCompletionGrant *owner;
    };
    OriginalCompletionGrant(StartupFence &fence, OwnedNativeFd descriptor)
        : fence_(fence), descriptor_(std::move(descriptor)),
          liveness_(std::make_shared<Liveness>(this))
    {}
    bool fail() noexcept
    {
        failed_ = true;
        return false;
    }
    std::optional<ClockSample> clock()
    {
        const auto milliseconds = [](clockid_t id) -> std::optional<std::uint64_t> {
            timespec sample{};
            if (clock_gettime(id, &sample) != 0 || sample.tv_sec < 0 || sample.tv_nsec < 0 ||
                sample.tv_nsec >= 1'000'000'000 ||
                static_cast<std::uint64_t>(sample.tv_sec) >
                    (std::numeric_limits<std::uint64_t>::max() - 999) / 1000)
                return {};
            return static_cast<std::uint64_t>(sample.tv_sec) * 1000 +
                   static_cast<std::uint64_t>(sample.tv_nsec) / 1'000'000;
        };
        const auto wall = milliseconds(CLOCK_REALTIME), boot = milliseconds(CLOCK_BOOTTIME);
        if (failed_ || !wall || !boot || !*wall || !*boot || *wall < last_.unixMs ||
            *boot < last_.bootMs) {
            fail();
            return {};
        }
        last_ = {*wall, *boot};
        return last_;
    }
    bool transfer(char *bytes, std::size_t size, std::uint64_t deadline, bool write)
    {
        while (size) {
            const auto now = clock();
            if (!now || now->bootMs >= deadline ||
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
                if (poll(&event, 1, static_cast<int>(deadline - now->bootMs)) != 1 ||
                    event.revents != event.events)
                    return fail();
            } else {
                return fail();
            }
        }
        const auto end = clock();
        return end && end->bootMs < deadline && fence_.authenticatesGrantPeer(descriptor_.get())
                   ? true
                   : fail();
    }
    bool read(std::string &bytes, std::uint64_t deadline)
    {
        return transfer(bytes.data(), bytes.size(), deadline, false);
    }
    bool probe(bool initial, std::string_view power = {}, std::string_view committed = {})
    {
        const auto now = clock();
        if (!now || sequence_ == std::numeric_limits<std::uint64_t>::max() ||
            now->bootMs > std::numeric_limits<std::uint64_t>::max() - 1000 ||
            (initial && (now->unixMs >= expires_.unixMs || now->bootMs >= expires_.bootMs)))
            return fail();
        auto deadline = now->bootMs + 1000;
        if (initial)
            deadline = std::min(deadline, expires_.bootMs);
        std::string request = !committed.empty() ? "LNCF:1\n"
                              : !power.empty()   ? "LNPR:1\n"
                              : initial          ? "LNCH:1\n"
                                                 : "LNCV:1\n";
        request += '\0';
        for (unsigned shift = 64; shift; shift -= 8)
            request += static_cast<char>((sequence_ >> (shift - 8)) & 255U);
        const std::string_view digest = !committed.empty() ? committed
                                        : power.empty()    ? std::string_view(digest_)
                                                           : power;
        for (std::size_t i = 0; i < digest.size(); i += 2) {
            const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            request += static_cast<char>((nibble(digest[i]) << 4) | nibble(digest[i + 1]));
        }
        std::string response(48, '\0');
        if (request.size() != 48 || !transfer(request.data(), request.size(), deadline, true) ||
            !read(response, deadline) || response != request)
            return fail();
        const auto finished = clock();
        if (!finished || (initial && (finished->unixMs >= expires_.unixMs ||
                                      finished->bootMs >= expires_.bootMs)))
            return fail();
        ++sequence_;
        return true;
    }
    StartupFence &fence_;
    OwnedNativeFd descriptor_;
    std::string digest_, committedDigest_;
    std::shared_ptr<Liveness> liveness_;
    ClockSample last_{}, expires_{};
    std::uint64_t sequence_ = 1;
    bool failed_ = false, attempted_ = false, currentAttempted_ = false, powerAttempted_ = false,
         commitAttempted_ = false;
};
} // namespace Linura::HyprlandDisplay
