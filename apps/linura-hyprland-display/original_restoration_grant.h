#pragma once

#include "display_transaction.h"
#include "recovery_lineage.h"
#include "startup_fence.h"
#include "owned_native_fd.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <time.h>

namespace Linura::HyprlandDisplay {

// Private Root-projected comparison data. Parsing these bytes grants no effect.
// Only OriginalRestorationGrant can authenticate their original kernel endpoint.
struct OriginalRestorationSource final
{
    struct Head final
    {
        OutputKey original, replacement;
        std::array<std::uint32_t, 3> kernel;
        RecoveryLineage lineage;
        bool owned;
        std::optional<Target> priorOverlay;
        std::string identityDigest;
    };
    std::string material, integration, replacementTopology, baselineText, desiredText;
    Layout baseline, desired;
    std::uint64_t originalGeneration = 0;
    std::vector<Head> heads;
};

namespace OriginalGrantCodec {
inline constexpr std::size_t MaxReservation = 16 * 1024, MaxProjection = 384 * 1024;
inline bool digest(std::string_view text)
{
    return text.size() == 64 && text != std::string(64, '0') &&
           std::all_of(text.begin(), text.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
inline std::optional<std::uint64_t> number(std::string_view text)
{
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
                   std::to_string(value) == text
               ? std::optional{value}
               : std::nullopt;
}
inline std::optional<std::uint64_t> clockField(std::string_view bytes)
{
    if (bytes.size() != 8)
        return std::nullopt;
    std::uint64_t value = 0;
    for (const auto byte : bytes)
        value = (value << 8U) | static_cast<unsigned char>(byte);
    return value ? std::optional{value} : std::nullopt;
}
inline bool deadlineBinding(std::string_view bytes, std::uint64_t expected)
{
    return expected != 0 && clockField(bytes) == std::optional{expected};
}
inline bool freshSample(std::uint64_t sampled, std::uint64_t now)
{
    return sampled != 0 && now >= sampled && now - sampled < 2000;
}
inline std::optional<std::string_view> field(std::string_view &rest, std::size_t maximum)
{
    if (rest.size() < 8)
        return std::nullopt;
    std::uint64_t length = 0;
    for (unsigned i = 0; i < 8; ++i)
        length = (length << 8U) | static_cast<unsigned char>(rest[i]);
    rest.remove_prefix(8);
    if (length > maximum || length > rest.size())
        return std::nullopt;
    const auto result = rest.substr(0, static_cast<std::size_t>(length));
    rest.remove_prefix(static_cast<std::size_t>(length));
    return result;
}
inline std::optional<std::array<std::string_view, 7>> materialFields(std::string_view text)
{
    if (text.size() > 12 * 1024 || !text.starts_with("LNRI:1;"))
        return std::nullopt;
    text.remove_prefix(7);
    constexpr std::array<std::size_t, 7> bounds{256, 64, 64, 64, 4096, 4096, 16 * 84};
    std::array<std::string_view, 7> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto colon = text.find(':');
        if (colon == std::string_view::npos || colon > 20)
            return std::nullopt;
        const auto length = number(text.substr(0, colon));
        if (!length || *length > bounds[i])
            return std::nullopt;
        text.remove_prefix(colon + 1);
        const auto size = static_cast<std::size_t>(*length);
        if (text.size() <= size || text[size] != ';')
            return std::nullopt;
        fields[i] = text.substr(0, size);
        text.remove_prefix(size + 1);
    }
    if (!text.empty() || fields[0].empty() || !digest(fields[1]) || !digest(fields[2]) ||
        !digest(fields[3]) || !fields[4].starts_with("LNDI:1;") ||
        !fields[5].starts_with("LNDI:1;"))
        return std::nullopt;
    return fields;
}
inline std::optional<Target> target(std::string_view text)
{
    if (text.size() > 512 || !text.starts_with("LNOT:1;"))
        return std::nullopt;
    text.remove_prefix(7);
    std::array<std::string_view, 12> fields{};
    for (auto &field : fields) {
        const auto end = text.find(';');
        if (end == std::string_view::npos)
            return std::nullopt;
        field = text.substr(0, end);
        text.remove_prefix(end + 1);
    }
    std::array<std::uint64_t, 12> values{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i == 8 || i == 9)
            continue;
        const auto value = number(fields[i]);
        if (!value)
            return std::nullopt;
        values[i] = *value;
    }
    std::array<std::int32_t, 2> position{};
    for (std::size_t i = 0; i < position.size(); ++i) {
        const auto field = fields[8 + i];
        const auto parsed = std::from_chars(field.data(), field.data() + field.size(), position[i]);
        if (parsed.ec != std::errc{} || parsed.ptr != field.data() + field.size() ||
            std::to_string(position[i]) != field || position[i] < -65536 || position[i] > 65536)
            return std::nullopt;
    }
    if (!text.empty() || values[0] == 0 || values[1] == 0 || values[2] > 1 || values[3] > 32768 ||
        values[4] > 32768 || values[5] > 1'000'000 || values[6] > 4000 || values[7] > 7 ||
        (values[10] == 0) != (values[11] == 0))
        return std::nullopt;
    Target result{{values[0], values[1]},
                  values[2] != 0,
                  {static_cast<std::int32_t>(values[3]), static_cast<std::int32_t>(values[4]),
                   static_cast<std::int32_t>(values[5])},
                  static_cast<std::uint32_t>(values[6]),
                  static_cast<std::uint32_t>(values[7]),
                  position[0],
                  position[1],
                  std::nullopt};
    if (values[10])
        result.mirror = OutputKey{values[10], values[11]};
    if ((!result.enabled && (result.mode != Mode{} || result.scaleMilli || result.transform ||
                             result.x || result.y || result.mirror)) ||
        (result.enabled && (result.mode.width == 0 || result.mode.height == 0 ||
                            result.mode.refreshMilliHz == 0 || result.scaleMilli < 500)) ||
        result.mirror == std::optional{result.output})
        return std::nullopt;
    return result;
}
struct Intent final
{
    std::string_view topology, baselineText, desiredText;
    Layout baseline, desired;
};
inline std::optional<std::pair<std::string_view, Layout>> layout(std::string_view text)
{
    if (text.size() > 4096 || !text.starts_with("LNDL:1;"))
        return std::nullopt;
    text.remove_prefix(7);
    const auto end = text.find(';');
    if (end == std::string_view::npos || end > 256)
        return std::nullopt;
    const auto topology = text.substr(0, end);
    if (!topology.starts_with("display:topology:"))
        return std::nullopt;
    text.remove_prefix(end + 1);
    Layout result;
    std::set<std::uint64_t> handles;
    while (!text.empty()) {
        if (result.size() >= DisplayTransaction::MaxHeads)
            return std::nullopt;
        const auto separator = text.find(';');
        if (separator == std::string_view::npos || separator > 512)
            return std::nullopt;
        auto row = text.substr(0, separator);
        text.remove_prefix(separator + 1);
        std::vector<std::string_view> parts;
        for (;;) {
            const auto colon = row.find(':');
            parts.push_back(row.substr(0, colon));
            if (parts.size() > 11)
                return std::nullopt;
            if (colon == std::string_view::npos)
                break;
            row.remove_prefix(colon + 1);
        }
        if (parts.size() < 3)
            return std::nullopt;
        std::string projected =
            "LNOT:1;" + std::string(parts[0]) + ';' + std::string(parts[1]) + ';';
        if (parts.size() == 3 && parts[2] == "disabled")
            projected += "0;0;0;0;0;0;0;0;0;0;";
        else if (parts.size() == 11 && parts[2] == "enabled") {
            projected += "1;";
            for (std::size_t i = 3; i < 10; ++i)
                projected += std::string(parts[i]) + ';';
            if (parts[10] == "-")
                projected += "0;0;";
            else {
                const auto comma = parts[10].find(',');
                if (comma == std::string_view::npos ||
                    parts[10].find(',', comma + 1) != std::string_view::npos)
                    return std::nullopt;
                projected += std::string(parts[10].substr(0, comma)) + ';' +
                             std::string(parts[10].substr(comma + 1)) + ';';
            }
        } else
            return std::nullopt;
        const auto decoded = target(projected);
        if (!decoded || (!result.empty() && decoded->output <= result.back().output) ||
            !handles.insert(decoded->output.handle).second)
            return std::nullopt;
        result.push_back(*decoded);
    }
    if (result.empty())
        return std::nullopt;
    for (const auto &row : result)
        if (row.mirror) {
            const auto root =
                std::find_if(result.begin(), result.end(), [&](const Target &candidate) {
                    return candidate.output == *row.mirror;
                });
            if (root == result.end() || !root->enabled || root->mirror || root->x != row.x ||
                root->y != row.y)
                return std::nullopt;
        }
    return std::pair{topology, result};
}
inline std::optional<Intent> intent(std::string_view text)
{
    if (!text.starts_with("LNDI:1;") || text.size() > 4096)
        return std::nullopt;
    text.remove_prefix(7);
    const auto lockEnd = text.find(';');
    if (lockEnd == std::string_view::npos || lockEnd > 256 ||
        !text.substr(0, lockEnd).starts_with("session:lock:"))
        return std::nullopt;
    text.remove_prefix(lockEnd + 1);
    const auto next = text.find("LNDL:1;", 7);
    if (next == std::string_view::npos)
        return std::nullopt;
    const auto before = layout(text.substr(0, next)), after = layout(text.substr(next));
    if (!before || !after || before->first != after->first ||
        before->second.size() != after->second.size())
        return std::nullopt;
    for (std::size_t i = 0; i < before->second.size(); ++i)
        if (before->second[i].output != after->second[i].output)
            return std::nullopt;
    return Intent{before->first, text.substr(0, next), text.substr(next), before->second,
                  after->second};
}
inline std::optional<OriginalRestorationSource>
decode(std::string_view reservation, std::string_view projection, const Correlation &expected)
{
    if (reservation.empty() || reservation.size() > MaxReservation || projection.empty() ||
        projection.size() > MaxProjection)
        return std::nullopt;
    std::array<std::string_view, 9> fields{};
    for (auto &value : fields) {
        const auto read = field(reservation, MaxReservation);
        if (!read)
            return std::nullopt;
        value = *read;
    }
    const auto generation = number(fields[2]), state = number(fields[3]);
    if (!reservation.empty() || fields[0] != "linura.native-display.restoration-reservation.v1" ||
        fields[1] != expected.transaction || fields[6] != expected.effectDigest ||
        fields[7] != expected.dispatchDigest || !generation || !state || *state == 0 ||
        !std::all_of(fields.begin() + 4, fields.begin() + 8, digest) || fields[8].empty() ||
        fields[8].size() > 12 * 1024 || !fields[8].starts_with("LNRI:1;"))
        return std::nullopt;
    const auto candidate = materialFields(fields[8]);
    if (!candidate)
        return std::nullopt;
    const auto originalIntent = intent((*candidate)[4]),
               replacementIntent = intent((*candidate)[5]);
    if (!originalIntent || !replacementIntent)
        return std::nullopt;
    OriginalRestorationSource result;
    result.material = fields[8];
    result.replacementTopology = replacementIntent->topology;
    result.baselineText = replacementIntent->baselineText;
    result.desiredText = replacementIntent->desiredText;
    result.baseline = replacementIntent->baseline;
    result.desired = replacementIntent->desired;
    std::array<std::string_view, 5> header{};
    for (auto &value : header) {
        const auto read = field(projection, 256);
        if (!read)
            return std::nullopt;
        value = *read;
    }
    const auto originalGeneration = number(header[3]), count = number(header[4]);
    const auto originalScopeGeneration =
        number(originalIntent->topology.substr(originalIntent->topology.rfind(':') + 1));
    if (header[0] != "linura.native-display.restoration-projection.v1" ||
        header[1] != "efb50993780079460b0cbed1363e2166a2de1d9f" || !digest(header[2]) ||
        !originalGeneration || *originalGeneration == 0 ||
        *originalGeneration == std::numeric_limits<std::uint64_t>::max() ||
        originalGeneration != originalScopeGeneration || !count || *count == 0 ||
        *count > DisplayTransaction::MaxHeads)
        return std::nullopt;
    result.integration = header[2];
    result.originalGeneration = *originalGeneration;
    std::optional<OutputKey> previous;
    std::set<OutputKey> destinations;
    std::set<std::uint64_t> oldHandles, newHandles;
    std::string mapping;
    std::set<std::array<std::uint32_t, 3>> devices;
    for (std::uint64_t i = 0; i < *count; ++i) {
        std::array<std::string_view, 9> head{};
        for (std::size_t index = 0; index < head.size(); ++index) {
            const auto read = field(projection, index == 5 ? RecoveryLineage::MaxBytes : 512);
            if (!read)
                return std::nullopt;
            head[index] = *read;
        }
        std::array<std::uint64_t, 4> keys{};
        for (std::size_t j = 0; j < keys.size(); ++j) {
            const auto value = number(head[j]);
            if (!value || *value == 0 || *value == std::numeric_limits<std::uint64_t>::max())
                return std::nullopt;
            keys[j] = *value;
        }
        const OutputKey old{keys[0], keys[1]}, current{keys[2], keys[3]};
        const auto lineage = RecoveryLineage::decode(head[5]);
        std::array<std::uint32_t, 3> kernel{};
        auto drm = head[4];
        for (std::size_t j = 0; j < kernel.size(); ++j) {
            const auto separator = drm.find(':');
            const auto value = number(drm.substr(0, separator));
            if (!value || *value > std::numeric_limits<std::uint32_t>::max() ||
                (j < 2) != (separator != std::string_view::npos))
                return std::nullopt;
            kernel[j] = static_cast<std::uint32_t>(*value);
            if (j < 2)
                drm.remove_prefix(separator + 1);
        }
        if (!lineage || kernel[0] != 226 || kernel[1] > 63 || kernel[2] == 0 ||
            !devices.insert(kernel).second || (previous && old <= *previous) ||
            !destinations.insert(current).second || !oldHandles.insert(old.handle).second ||
            !newHandles.insert(current.handle).second || (head[6] != "0" && head[6] != "1") ||
            (head[6] == "0") != head[7].empty() || !digest(head[8]))
            return std::nullopt;
        const auto priorOverlay = head[6] == "1" ? target(head[7]) : std::nullopt;
        if (head[6] == "1" && (!priorOverlay || priorOverlay->output != old))
            return std::nullopt;
        mapping += std::to_string(old.handle) + ':' + std::to_string(old.generation) + ':' +
                   std::to_string(current.handle) + ':' + std::to_string(current.generation) + ';';
        previous = old;
        result.heads.push_back(
            {old, current, kernel, *lineage, head[6] == "1", priorOverlay, std::string(head[8])});
    }
    if (!projection.empty() || mapping != (*candidate)[6] ||
        result.heads.size() != originalIntent->baseline.size() ||
        result.heads.size() != result.desired.size())
        return std::nullopt;
    Layout remapped = originalIntent->baseline;
    for (auto &row : remapped) {
        const auto source =
            std::find_if(result.heads.begin(), result.heads.end(),
                         [&](const auto &head) { return head.original == row.output; });
        if (source == result.heads.end())
            return std::nullopt;
        row.output = source->replacement;
        if (row.mirror) {
            const auto mirror =
                std::find_if(result.heads.begin(), result.heads.end(),
                             [&](const auto &head) { return head.original == *row.mirror; });
            if (mirror == result.heads.end())
                return std::nullopt;
            row.mirror = mirror->replacement;
        }
    }
    std::sort(remapped.begin(), remapped.end(),
              [](const Target &a, const Target &b) { return a.output < b.output; });
    return remapped == result.desired ? std::optional{std::move(result)} : std::nullopt;
}
} // namespace OriginalGrantCodec

// One native recipient, one original-Root endpoint. The received descriptor is
// always consumed, including denial. Copies of bytes/descriptors cannot recreate
// this object, reconnect to a replacement service or renew its original transfer.
class OriginalRestorationGrant final
{
  public:
    OriginalRestorationGrant(const OriginalRestorationGrant &) = delete;
    OriginalRestorationGrant &operator=(const OriginalRestorationGrant &) = delete;
    [[nodiscard]] static std::unique_ptr<OriginalRestorationGrant>
    receive(StartupFence &fence, OwnedNativeFd descriptor, const Correlation &expected)
    {
        auto grant = std::unique_ptr<OriginalRestorationGrant>(
            new OriginalRestorationGrant(fence, std::move(descriptor)));
        const auto now = bootMs();
        if (!now || *now > std::numeric_limits<std::uint64_t>::max() - 2000 ||
            !fence.authenticatesGrantPeer(grant->descriptor_.get()))
            return {};
        const auto deadline = *now + 2000;
        std::string header(7, '\0'), end(11, '\0');
        if (!grant->read(header, deadline) || header != "LNRG:2\n")
            return {};
        const auto reservation = grant->frame(OriginalGrantCodec::MaxReservation, deadline);
        const auto projection =
            reservation ? grant->frame(OriginalGrantCodec::MaxProjection, deadline) : std::nullopt;
        std::string dispatchDeadline(8, '\0'), sampledBoot(8, '\0');
        if (!reservation || !projection || !grant->read(dispatchDeadline, deadline) ||
            !OriginalGrantCodec::deadlineBinding(dispatchDeadline, expected.deadlineUnixMs) ||
            !grant->read(sampledBoot, deadline) || !OriginalGrantCodec::clockField(sampledBoot) ||
            !grant->read(end, deadline) || end != "LNRG-END:2\n")
            return {};
        grant->sampledBootMs_ = *OriginalGrantCodec::clockField(sampledBoot);
        grant->source_ = OriginalGrantCodec::decode(*reservation, *projection, expected);
        if (!grant->source_ || !grant->checkWitness(deadline))
            return {};
        return grant;
    }
    [[nodiscard]] const OriginalRestorationSource &source() const
    {
        return *source_;
    }
    [[nodiscard]] bool sampleFreshAt(std::uint64_t nowBootMs) const
    {
        return OriginalGrantCodec::freshSample(sampledBootMs_, nowBootMs);
    }
    // Cheap compositor-thread lifetime check only. Fresh probes are explicit
    // at the write/verification boundaries; input/render callbacks never wait.
    [[nodiscard]] bool live()
    {
        if (lost_ || !fence_.authenticatesGrantPeer(descriptor_.get()))
            return fail();
        pollfd event{descriptor_.get(), POLLIN, 0};
        if (poll(&event, 1, 0) != 0 || event.revents != 0)
            return fail();
        return true;
    }
    [[nodiscard]] bool verify()
    {
        const auto now = bootMs();
        return now && *now <= std::numeric_limits<std::uint64_t>::max() - 2000
                   ? checkWitness(*now + 2000)
                   : fail();
    }

  private:
    bool checkWitness(std::uint64_t deadline)
    {
        if (lost_ || !fence_.authenticatesGrantPeer(descriptor_.get()) ||
            sequence_ == std::numeric_limits<std::uint64_t>::max())
            return fail();
        std::string probe = "LNRV:1\n";
        probe += '\0';
        for (unsigned shift = 64; shift != 0; shift -= 8)
            probe += static_cast<char>((sequence_ >> (shift - 8)) & 255U);
        std::string response(probe.size(), '\0');
        if (!transfer(probe.data(), probe.size(), deadline, true) || !read(response, deadline) ||
            response != probe || !fence_.authenticatesGrantPeer(descriptor_.get()))
            return fail();
        ++sequence_;
        return true;
    }

  private:
    OriginalRestorationGrant(StartupFence &fence, OwnedNativeFd descriptor)
        : fence_(fence), descriptor_(std::move(descriptor))
    {}
    [[nodiscard]] bool fail() noexcept
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
    bool transfer(char *bytes, std::size_t size, std::uint64_t deadline, bool write)
    {
        while (size != 0) {
            const auto now = bootMs();
            if (!now || *now >= deadline || !fence_.authenticatesGrantPeer(descriptor_.get()))
                return false;
            const auto transferred =
                write ? send(descriptor_.get(), bytes, size, MSG_DONTWAIT | MSG_NOSIGNAL)
                      : recv(descriptor_.get(), bytes, size, MSG_DONTWAIT);
            if (transferred > 0) {
                const auto part = static_cast<std::size_t>(transferred);
                bytes += part;
                size -= part;
            } else if (transferred < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd event{descriptor_.get(), static_cast<short>(write ? POLLOUT : POLLIN), 0};
                if (poll(&event, 1, static_cast<int>(deadline - *now)) != 1 ||
                    event.revents != event.events)
                    return false;
            } else
                return false;
        }
        const auto finished = bootMs();
        return finished && *finished < deadline && fence_.authenticatesGrantPeer(descriptor_.get());
    }
    bool read(std::string &bytes, std::uint64_t deadline)
    {
        return transfer(bytes.data(), bytes.size(), deadline, false);
    }
    std::optional<std::string> frame(std::size_t maximum, std::uint64_t deadline)
    {
        std::string length(8, '\0');
        if (!read(length, deadline))
            return std::nullopt;
        std::uint64_t size = 0;
        for (const auto byte : length)
            size = (size << 8U) | static_cast<unsigned char>(byte);
        if (size == 0 || size > maximum)
            return std::nullopt;
        std::string result(static_cast<std::size_t>(size), '\0');
        return read(result, deadline) ? std::optional{std::move(result)} : std::nullopt;
    }
    StartupFence &fence_;
    OwnedNativeFd descriptor_;
    std::uint64_t sequence_ = 1;
    std::uint64_t sampledBootMs_ = 0;
    bool lost_ = false;
    std::optional<OriginalRestorationSource> source_;
};
} // namespace Linura::HyprlandDisplay
