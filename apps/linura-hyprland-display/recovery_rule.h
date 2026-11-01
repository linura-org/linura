#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

namespace Linura::HyprlandDisplay {

// Private native-rule preimage, not a command, current observation or recovery
// permit. Decoding it never grants admission to an output or a compositor.
// Keep this independent of the SDK so the bounded decoder is also exercised
// without constructing a compositor. Actual SDK consumers test the projection.
class RecoveryRule final
{
  public:
    static constexpr std::size_t MaxBytes = 12 * 1024;

    template <typename Rule>
    [[nodiscard]] static std::optional<RecoveryRule> capture(const Rule &rule)
    {
        if (rule.m_mirrorOf.size() > 4096)
            return std::nullopt;
        RecoveryRule saved;
        saved.disabled_ = rule.m_disabled;
        saved.reals_ = {
            static_cast<double>(rule.m_resolution.x), static_cast<double>(rule.m_resolution.y),
            static_cast<double>(rule.m_refreshRate),  static_cast<double>(rule.m_offset.x),
            static_cast<double>(rule.m_offset.y),     static_cast<double>(rule.m_scale)};
        saved.autoDir_ = static_cast<std::uint64_t>(rule.m_autoDir);
        saved.transform_ = static_cast<std::uint64_t>(rule.m_transform);
        saved.mirror_ = rule.m_mirrorOf;
        const auto &mode = rule.m_drmMode;
        saved.mode_ = {mode.clock, mode.hdisplay, mode.hsync_start, mode.hsync_end, mode.htotal,
                       mode.hskew, mode.vdisplay, mode.vsync_start, mode.vsync_end, mode.vtotal,
                       mode.vscan, mode.vrefresh, mode.flags,       mode.type};
        static_assert(std::extent_v<decltype(mode.name)> == 32);
        std::copy(std::begin(mode.name), std::end(mode.name), saved.modeName_.begin());
        if (!saved.valid())
            return std::nullopt;
        for (auto &value : saved.reals_)
            if (value == 0)
                value = 0; // Preserve the existing canonical positive-zero encoding.
        return saved;
    }

    [[nodiscard]] static std::optional<RecoveryRule> decode(std::string_view bytes)
    {
        if (bytes.size() > MaxBytes || !bytes.starts_with("LNDR:1;"))
            return std::nullopt;
        Reader reader{bytes.substr(7)};
        RecoveryRule saved;
        std::uint64_t disabled = 0;
        if (!reader.integer(disabled) || disabled > 1)
            return std::nullopt;
        saved.disabled_ = disabled != 0;
        for (auto &value : saved.reals_)
            if (!reader.real(value))
                return std::nullopt;
        if (!reader.integer(saved.autoDir_) || !reader.integer(saved.transform_) ||
            !reader.hex(saved.mirror_, 4096))
            return std::nullopt;
        for (auto &value : saved.mode_)
            if (!reader.integer(value))
                return std::nullopt;
        std::string name;
        if (!reader.hex(name, saved.modeName_.size()) || name.size() != saved.modeName_.size() ||
            !reader.remaining.empty() || !saved.valid())
            return std::nullopt;
        std::copy(name.begin(), name.end(), saved.modeName_.begin());
        // Reject every alternate representation, including negative zero,
        // leading zeroes, uppercase hex, unsupported fields and trailing data.
        if (saved.encode() != bytes)
            return std::nullopt;
        return saved;
    }

    [[nodiscard]] std::string encode() const
    {
        std::string out = "LNDR:1;";
        integer(out, disabled_ ? 1 : 0);
        for (const auto value : reals_) {
            const auto bits = std::bit_cast<std::uint64_t>(value);
            for (unsigned shift = 64; shift != 0; shift -= 4)
                out += Digits[(bits >> (shift - 4)) & 15U];
            out += ';';
        }
        integer(out, autoDir_);
        integer(out, transform_);
        hex(out, mirror_);
        for (const auto value : mode_)
            integer(out, value);
        hex(out, std::string_view(modeName_.data(), modeName_.size()));
        return out;
    }

    // Merge into a COPY of the current rule. The selector, precedence, color,
    // VRR, ICC, reserved areas and all other current fields remain untouched.
    // Callers still require independent continuity/admission before effects.
    template <typename Rule> [[nodiscard]] Rule mergeOwnedFields(Rule current) const
    {
        current.m_disabled = disabled_;
        current.m_resolution.x = reals_[0];
        current.m_resolution.y = reals_[1];
        current.m_refreshRate = static_cast<float>(reals_[2]);
        current.m_offset.x = reals_[3];
        current.m_offset.y = reals_[4];
        current.m_scale = static_cast<float>(reals_[5]);
        current.m_autoDir = static_cast<decltype(current.m_autoDir)>(autoDir_);
        current.m_transform = static_cast<decltype(current.m_transform)>(transform_);
        current.m_mirrorOf = mirror_;
        auto &mode = current.m_drmMode;
        mode.clock = static_cast<decltype(mode.clock)>(mode_[0]);
        mode.hdisplay = static_cast<decltype(mode.hdisplay)>(mode_[1]);
        mode.hsync_start = static_cast<decltype(mode.hsync_start)>(mode_[2]);
        mode.hsync_end = static_cast<decltype(mode.hsync_end)>(mode_[3]);
        mode.htotal = static_cast<decltype(mode.htotal)>(mode_[4]);
        mode.hskew = static_cast<decltype(mode.hskew)>(mode_[5]);
        mode.vdisplay = static_cast<decltype(mode.vdisplay)>(mode_[6]);
        mode.vsync_start = static_cast<decltype(mode.vsync_start)>(mode_[7]);
        mode.vsync_end = static_cast<decltype(mode.vsync_end)>(mode_[8]);
        mode.vtotal = static_cast<decltype(mode.vtotal)>(mode_[9]);
        mode.vscan = static_cast<decltype(mode.vscan)>(mode_[10]);
        mode.vrefresh = static_cast<decltype(mode.vrefresh)>(mode_[11]);
        mode.flags = static_cast<decltype(mode.flags)>(mode_[12]);
        mode.type = static_cast<decltype(mode.type)>(mode_[13]);
        static_assert(std::extent_v<decltype(mode.name)> == 32);
        std::copy(modeName_.begin(), modeName_.end(), std::begin(mode.name));
        return current;
    }

  private:
    RecoveryRule() = default;
    bool disabled_ = false;
    std::array<double, 6> reals_{};
    std::uint64_t autoDir_ = 0, transform_ = 0;
    std::string mirror_;
    std::array<std::uint64_t, 14> mode_{};
    std::array<char, 32> modeName_{};
    inline static constexpr char Digits[] = "0123456789abcdef";
    [[nodiscard]] bool valid() const
    {
        if (autoDir_ > 8 || transform_ > 7 || mirror_.size() > 4096 ||
            !std::all_of(reals_.begin(), reals_.end(), [](double v) { return std::isfinite(v); }))
            return false;
        // Refresh and scale originate in native float members. Reject bytes
        // that could only be reconstructed by rounding or overflowing them.
        for (const auto i : {2U, 5U})
            if (std::abs(reals_[i]) > std::numeric_limits<float>::max() ||
                static_cast<double>(static_cast<float>(reals_[i])) != reals_[i])
                return false;
        for (std::size_t i = 0; i < mode_.size(); ++i)
            if (mode_[i] > (i >= 1 && i <= 10 ? std::numeric_limits<std::uint16_t>::max()
                                              : std::numeric_limits<std::uint32_t>::max()))
                return false;
        return true;
    }
    static void integer(std::string &out, std::uint64_t value)
    {
        out += std::to_string(value) + ';';
    }
    static void hex(std::string &out, std::string_view value)
    {
        for (const auto c : value) {
            const auto byte = static_cast<unsigned char>(c);
            out += Digits[byte >> 4U];
            out += Digits[byte & 15U];
        }
        out += ';';
    }
    struct Reader final
    {
        std::string_view remaining;
        std::optional<std::string_view> field()
        {
            const auto end = remaining.find(';');
            if (end == std::string_view::npos)
                return std::nullopt;
            const auto value = remaining.substr(0, end);
            remaining.remove_prefix(end + 1);
            return value;
        }
        bool integer(std::uint64_t &value)
        {
            const auto text = field();
            if (!text || text->empty() || text->size() > 20 ||
                (text->size() > 1 && text->front() == '0'))
                return false;
            const auto parsed = std::from_chars(text->data(), text->data() + text->size(), value);
            return parsed.ec == std::errc{} && parsed.ptr == text->data() + text->size();
        }
        static int nibble(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        }
        bool real(double &value)
        {
            const auto text = field();
            if (!text || text->size() != 16)
                return false;
            std::uint64_t bits = 0;
            for (const auto c : *text) {
                const auto digit = nibble(c);
                if (digit < 0)
                    return false;
                bits = (bits << 4U) | static_cast<unsigned>(digit);
            }
            value = std::bit_cast<double>(bits);
            return std::isfinite(value) && (value != 0 || bits == 0);
        }
        bool hex(std::string &value, std::size_t maximum)
        {
            const auto text = field();
            if (!text || text->size() > maximum * 2 || text->size() % 2 != 0)
                return false;
            value.clear();
            value.reserve(text->size() / 2);
            for (std::size_t i = 0; i < text->size(); i += 2) {
                const auto hi = nibble((*text)[i]), lo = nibble((*text)[i + 1]);
                if (hi < 0 || lo < 0)
                    return false;
                value += static_cast<char>((hi << 4) | lo);
            }
            return true;
        }
    };
};

} // namespace Linura::HyprlandDisplay
