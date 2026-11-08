#pragma once

#include "recovery_rule.h"

#include <vector>

namespace Linura::HyprlandDisplay {

// Historical comparison data only. Config selection, underlying owned fields
// and the effective wlr projection remain distinct. Decode grants no permission
// to overwrite a native rule, adopt an output or recreate a Wayland client.
class RecoveryLineage final
{
  public:
    enum class WlrSource { None = 0, LiveClient = 1, RestoredProjection = 2 };
    static constexpr std::size_t MaxBytes = RecoveryRule::MaxBytes, MaxSelectors = 256;
    [[nodiscard]] static std::optional<RecoveryLineage>
    capture(RecoveryRule native, RecoveryRule effective, std::vector<std::string> selectors,
            std::optional<std::size_t> selected, bool wlr, std::uint32_t mask,
            std::uint32_t refreshMilliHz = 0, std::string restoredOrigin = {})
    {
        if (wlr && !restoredOrigin.empty())
            return std::nullopt;
        RecoveryLineage saved{
            std::move(native), std::move(effective), std::move(selectors), selected, wlr, mask,
            refreshMilliHz};
        if (!restoredOrigin.empty()) {
            saved.source_ = WlrSource::RestoredProjection;
            saved.restoredOrigin_ = std::move(restoredOrigin);
        }
        return saved.valid() && saved.encode().size() <= MaxBytes ? std::optional{std::move(saved)}
                                                                  : std::nullopt;
    }
    [[nodiscard]] static std::optional<RecoveryLineage> decode(std::string_view bytes)
    {
        const bool historical = bytes.starts_with("LNRL:1;");
        if (bytes.size() > MaxBytes || (!historical && !bytes.starts_with("LNRL:2;")))
            return std::nullopt;
        Reader reader{bytes.substr(7)};
        const auto selected = reader.integer();
        const auto count = reader.integer();
        if (!selected || !count || *count > MaxSelectors || *selected > *count)
            return std::nullopt;
        std::vector<std::string> selectors;
        for (std::size_t i = 0; i < *count; ++i) {
            const auto selector = reader.hex();
            if (!selector)
                return std::nullopt;
            selectors.push_back(*selector);
        }
        const auto native = reader.rule(), effective = reader.rule();
        const auto wlr = reader.integer(), mask = reader.integer(), refresh = reader.integer();
        const auto origin =
            historical ? std::optional<std::string_view>{std::string_view{}} : reader.field();
        if (!native || !effective || !wlr || *wlr > (historical ? 1U : 2U) || !origin ||
            ((*wlr == 2) != !origin->empty()) || !mask || *mask > 31 || !refresh ||
            *refresh > std::numeric_limits<std::uint32_t>::max() || !reader.rest.empty())
            return std::nullopt;
        RecoveryLineage saved{*native,
                              *effective,
                              std::move(selectors),
                              *selected ? std::optional{static_cast<std::size_t>(*selected - 1)}
                                        : std::nullopt,
                              *wlr == 1,
                              static_cast<std::uint32_t>(*mask),
                              static_cast<std::uint32_t>(*refresh)};
        if (*wlr == 2) {
            saved.source_ = WlrSource::RestoredProjection;
            saved.restoredOrigin_ = *origin;
        }
        // Historical bounds/bytes retain their own version; validating them
        // must not first expand them into the new current representation.
        saved.version_ = historical ? 1U : 2U;
        return saved.valid() && saved.encode() == bytes ? std::optional{std::move(saved)}
                                                        : std::nullopt;
    }
    [[nodiscard]] std::string encode() const
    {
        std::string out = "LNRL:" + std::to_string(version_) + ';' +
                          std::to_string(selected_ ? *selected_ + 1 : 0) + ';' +
                          std::to_string(selectors_.size()) + ';';
        for (const auto &selector : selectors_) {
            for (const auto byte : selector) {
                const auto c = static_cast<unsigned char>(byte);
                out += Digits[c >> 4U];
                out += Digits[c & 15U];
            }
            out += ';';
        }
        out += native_.encode().substr(7);
        out += effective_.encode().substr(7);
        out += std::to_string(static_cast<unsigned>(source_)) + ';' + std::to_string(mask_) + ';' +
               std::to_string(refreshMilliHz_) + ';';
        return version_ == 1 ? out : out + restoredOrigin_ + ';';
    }
    [[nodiscard]] const RecoveryRule &native() const noexcept
    {
        return native_;
    }
    [[nodiscard]] const RecoveryRule &effective() const noexcept
    {
        return effective_;
    }
    [[nodiscard]] const std::vector<std::string> &selectors() const noexcept
    {
        return selectors_;
    }
    [[nodiscard]] std::optional<std::size_t> selected() const noexcept
    {
        return selected_;
    }
    [[nodiscard]] bool wlr() const noexcept
    {
        return source_ == WlrSource::LiveClient;
    }
    [[nodiscard]] bool hasWlrProjection() const noexcept
    {
        return source_ != WlrSource::None;
    }
    [[nodiscard]] WlrSource wlrSource() const noexcept
    {
        return source_;
    }
    [[nodiscard]] const std::string &restoredOrigin() const noexcept
    {
        return restoredOrigin_;
    }
    // The original checkpoint hash explains this new native projection; it is
    // comparison lineage, never authority or a recreated historical client.
    [[nodiscard]] std::optional<RecoveryLineage>
    replacementProjection(std::string_view origin) const
    {
        return capture(native_, effective_, selectors_, selected_, false, mask_, refreshMilliHz_,
                       hasWlrProjection() ? std::string(origin) : std::string{});
    }
    [[nodiscard]] std::uint32_t wlrMask() const noexcept
    {
        return mask_;
    }
    [[nodiscard]] std::uint32_t wlrRefreshMilliHz() const noexcept
    {
        return refreshMilliHz_;
    }
    // Replacement recovery may restore owned fields, never select/reorder a
    // different live rule or overwrite a new native wlr client's ownership.
    // This comparison is not authorization; callers need the original Root
    // endpoint, exact consumed Recovery scene and prepared one-use handoff.
    [[nodiscard]] bool replacementSourceCompatible(const RecoveryLineage &current) const
    {
        return selectors_ == current.selectors_ && selected_ == current.selected_ &&
               native_.selector() == current.native_.selector() &&
               current.source_ == WlrSource::None;
    }
    // Recreate only the committed owned-field wlr projection. No historical
    // client/socket is recreated and no uncommitted native field is frozen.
    // Adaptive sync, color, ICC and every unrelated live field stay current.
    template <typename Rule>
    [[nodiscard]] std::optional<Rule> restoredWlrProjection(Rule current) const
    {
        if (!hasWlrProjection())
            return std::nullopt;
        const auto saved = effective_.mergeOwnedFields(current);
        if (!saved)
            return std::nullopt;
        current.m_disabled = saved->m_disabled;
        if (mask_ & 3U) {
            current.m_resolution = saved->m_resolution;
            current.m_refreshRate = static_cast<float>(refreshMilliHz_) / 1000.F;
        }
        if (mask_ & 4U)
            current.m_offset = saved->m_offset;
        if (mask_ & 8U)
            current.m_transform = saved->m_transform;
        if (mask_ & 16U)
            current.m_scale = saved->m_scale;
        return current;
    }
    // Only for removing/restoring an in-process Linura overlay, which never
    // writes a native config rule or wlr manager. The actual selected owned
    // semantics must remain identical; an unrelated selector-list edit need
    // not strand compensation. Prepared/replacement identity uses full encode.
    [[nodiscard]] bool sameOverlayCompensationSources(const RecoveryLineage &other) const
    {
        return native_.encode() == other.native_.encode() &&
               effective_.encode() == other.effective_.encode() && source_ == other.source_ &&
               restoredOrigin_ == other.restoredOrigin_ && mask_ == other.mask_ &&
               refreshMilliHz_ == other.refreshMilliHz_;
    }

  private:
    RecoveryLineage(RecoveryRule native, RecoveryRule effective, std::vector<std::string> selectors,
                    std::optional<std::size_t> selected, bool wlr, std::uint32_t mask,
                    std::uint32_t refreshMilliHz)
        : native_(std::move(native)), effective_(std::move(effective)),
          selectors_(std::move(selectors)), selected_(selected),
          source_(wlr ? WlrSource::LiveClient : WlrSource::None), mask_(mask),
          refreshMilliHz_(refreshMilliHz)
    {}
    RecoveryRule native_, effective_;
    std::vector<std::string> selectors_;
    std::optional<std::size_t> selected_;
    unsigned version_ = 2;
    WlrSource source_ = WlrSource::None;
    std::string restoredOrigin_;
    std::uint32_t mask_ = 0;
    // The float Hz projection can collapse distinct integer source values.
    // Keep the actual original millihertz; never reconstruct it by rounding.
    std::uint32_t refreshMilliHz_ = 0;
    inline static constexpr char Digits[] = "0123456789abcdef";
    [[nodiscard]] bool valid() const
    {
        if ((source_ == WlrSource::RestoredProjection && !originDigest(restoredOrigin_)) ||
            (source_ != WlrSource::RestoredProjection && !restoredOrigin_.empty()) ||
            selectors_.size() > MaxSelectors || mask_ > 31 || (!hasWlrProjection() && mask_ != 0))
            return false;
        if ((hasWlrProjection() && (mask_ & 3U)) ? !effective_.hasWlrRefresh(refreshMilliHz_)
                                                 : refreshMilliHz_ != 0)
            return false;
        std::size_t bytes = 0;
        for (const auto &selector : selectors_) {
            if (selector.size() > 4096 || bytes > MaxBytes - selector.size() * 2 - 1)
                return false;
            bytes += selector.size() * 2 + 1;
        }
        if (selected_) {
            if (*selected_ >= selectors_.size() || native_.selector() != selectors_[*selected_])
                return false;
        } else if (!native_.selector().empty() ||
                   std::find(selectors_.begin(), selectors_.end(), "") != selectors_.end())
            return false;
        return hasWlrProjection() ? effective_.isWlrProjectionOf(native_, mask_)
                                  : effective_.encode() == native_.encode();
    }
    static bool originDigest(std::string_view value)
    {
        return value.size() == 64 && value != std::string(64, '0') &&
               std::all_of(value.begin(), value.end(),
                           [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    }
    struct Reader final
    {
        std::string_view rest;
        [[nodiscard]] std::optional<std::string_view> field()
        {
            const auto end = rest.find(';');
            if (end == rest.npos)
                return std::nullopt;
            const auto value = rest.substr(0, end);
            rest.remove_prefix(end + 1);
            return value;
        }
        [[nodiscard]] std::optional<std::uint64_t> integer()
        {
            const auto value = field();
            if (!value || value->empty())
                return std::nullopt;
            std::uint64_t number = 0;
            const auto [end, error] =
                std::from_chars(value->data(), value->data() + value->size(), number);
            return error == std::errc{} && end == value->data() + value->size() &&
                           std::to_string(number) == *value
                       ? std::optional{number}
                       : std::nullopt;
        }
        [[nodiscard]] std::optional<std::string> hex()
        {
            const auto value = field();
            if (!value || value->size() > 8192 || value->size() % 2 != 0)
                return std::nullopt;
            std::string decoded;
            for (std::size_t i = 0; i < value->size(); i += 2) {
                const auto high = std::string_view(Digits, 16).find((*value)[i]);
                const auto low = std::string_view(Digits, 16).find((*value)[i + 1]);
                if (high == std::string_view::npos || low == std::string_view::npos)
                    return std::nullopt;
                decoded += static_cast<char>((high << 4U) | low);
            }
            return decoded;
        }
        [[nodiscard]] std::optional<RecoveryRule> rule()
        {
            std::string text = "LNDR:2;";
            for (std::size_t i = 0; i < 26; ++i) {
                const auto value = field();
                if (!value || text.size() + value->size() + 1 > RecoveryRule::MaxBytes)
                    return std::nullopt;
                text += *value;
                text += ';';
            }
            return RecoveryRule::decode(text);
        }
    };
};
} // namespace Linura::HyprlandDisplay
