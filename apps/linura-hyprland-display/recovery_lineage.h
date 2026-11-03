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
    static constexpr std::size_t MaxBytes = RecoveryRule::MaxBytes, MaxSelectors = 256;
    [[nodiscard]] static std::optional<RecoveryLineage>
    capture(RecoveryRule native, RecoveryRule effective, std::vector<std::string> selectors,
            std::optional<std::size_t> selected, bool wlr, std::uint32_t mask,
            std::uint32_t refreshMilliHz = 0)
    {
        RecoveryLineage saved{
            std::move(native), std::move(effective), std::move(selectors), selected, wlr, mask,
            refreshMilliHz};
        return saved.valid() && saved.encode().size() <= MaxBytes ? std::optional{std::move(saved)}
                                                                  : std::nullopt;
    }
    [[nodiscard]] static std::optional<RecoveryLineage> decode(std::string_view bytes)
    {
        if (bytes.size() > MaxBytes || !bytes.starts_with("LNRL:1;"))
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
        if (!native || !effective || !wlr || *wlr > 1 || !mask || *mask > 31 || !refresh ||
            *refresh > std::numeric_limits<std::uint32_t>::max() || !reader.rest.empty())
            return std::nullopt;
        auto saved = capture(
            *native, *effective, std::move(selectors),
            *selected ? std::optional{static_cast<std::size_t>(*selected - 1)} : std::nullopt,
            *wlr != 0, static_cast<std::uint32_t>(*mask), static_cast<std::uint32_t>(*refresh));
        return saved && saved->encode() == bytes ? saved : std::nullopt;
    }
    [[nodiscard]] std::string encode() const
    {
        std::string out = "LNRL:1;" + std::to_string(selected_ ? *selected_ + 1 : 0) + ';' +
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
        return out + (wlr_ ? "1;" : "0;") + std::to_string(mask_) + ';' +
               std::to_string(refreshMilliHz_) + ';';
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
        return wlr_;
    }
    [[nodiscard]] std::uint32_t wlrMask() const noexcept
    {
        return mask_;
    }
    [[nodiscard]] std::uint32_t wlrRefreshMilliHz() const noexcept
    {
        return refreshMilliHz_;
    }
    // Only for removing/restoring an in-process Linura overlay, which never
    // writes a native config rule or wlr manager. The actual selected owned
    // semantics must remain identical; an unrelated selector-list edit need
    // not strand compensation. Prepared/replacement identity uses full encode.
    [[nodiscard]] bool sameOverlayCompensationSources(const RecoveryLineage &other) const
    {
        return native_.encode() == other.native_.encode() &&
               effective_.encode() == other.effective_.encode() && wlr_ == other.wlr_ &&
               mask_ == other.mask_ && refreshMilliHz_ == other.refreshMilliHz_;
    }

  private:
    RecoveryLineage(RecoveryRule native, RecoveryRule effective, std::vector<std::string> selectors,
                    std::optional<std::size_t> selected, bool wlr, std::uint32_t mask,
                    std::uint32_t refreshMilliHz)
        : native_(std::move(native)), effective_(std::move(effective)),
          selectors_(std::move(selectors)), selected_(selected), wlr_(wlr), mask_(mask),
          refreshMilliHz_(refreshMilliHz)
    {}
    RecoveryRule native_, effective_;
    std::vector<std::string> selectors_;
    std::optional<std::size_t> selected_;
    bool wlr_ = false;
    std::uint32_t mask_ = 0;
    // The float Hz projection can collapse distinct integer source values.
    // Keep the actual original millihertz; never reconstruct it by rounding.
    std::uint32_t refreshMilliHz_ = 0;
    inline static constexpr char Digits[] = "0123456789abcdef";
    [[nodiscard]] bool valid() const
    {
        if (selectors_.size() > MaxSelectors || mask_ > 31 || (!wlr_ && mask_ != 0))
            return false;
        if ((wlr_ && (mask_ & 3U)) ? !effective_.hasWlrRefresh(refreshMilliHz_)
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
        return wlr_ ? effective_.isWlrProjectionOf(native_, mask_)
                    : effective_.encode() == native_.encode();
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
