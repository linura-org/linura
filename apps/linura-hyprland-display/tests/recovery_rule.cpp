#include "recovery_rule.h"

#include <cassert>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

using namespace Linura::HyprlandDisplay;

namespace {
// Explicit component fixture only; actual SDK projection is separately tested
// in pinned_rule_overlay.cpp. This fixture never supplies native acceptance.
struct Rule final
{
    struct Point final
    {
        double x = 0, y = 0;
    };
    struct Mode final
    {
        std::uint32_t clock = 0;
        std::uint16_t hdisplay = 0, hsync_start = 0, hsync_end = 0, htotal = 0, hskew = 0,
                      vdisplay = 0, vsync_start = 0, vsync_end = 0, vtotal = 0, vscan = 0;
        std::uint32_t vrefresh = 0, flags = 0, type = 0;
        char name[32]{};
    };
    bool m_disabled = false;
    Point m_resolution{}, m_offset{};
    float m_refreshRate = 60, m_scale = -1;
    std::uint8_t m_autoDir = 0;
    std::uint32_t m_transform = 0;
    std::string m_mirrorOf;
    Mode m_drmMode;
    std::string m_name = "live selector", m_iccFile = "live profile";
    int m_vrr = 2;
};
const std::string Golden = "LNDR:1;0;0000000000000000;0000000000000000;404e000000000000;"
                           "0000000000000000;0000000000000000;bff0000000000000;0;0;;"
                           "0;0;0;0;0;0;0;0;0;0;0;0;0;0;"
                           "0000000000000000000000000000000000000000000000000000000000000000;";

std::string replaced(std::string text, std::size_t field, const std::string &value)
{
    std::size_t start = 7;
    for (std::size_t i = 0; i < field; ++i)
        start = text.find(';', start) + 1;
    text.replace(start, text.find(';', start) - start, value);
    return text;
}
void malformed()
{
    for (std::size_t size = 0; size < Golden.size(); ++size)
        assert(!RecoveryRule::decode(std::string_view(Golden).substr(0, size)));
    for (const auto &text : {"", "LNDR:2;", "LNDR:01;", "LNDR:1;", "LNDR:1;0;"})
        assert(!RecoveryRule::decode(text));
    for (const auto &suffix : {";", "0;", "\n", "garbage"})
        assert(!RecoveryRule::decode(Golden + suffix));
    for (const auto &bad : {"2", "-1", "00", "+0", "0 ", "18446744073709551616"})
        assert(!RecoveryRule::decode(replaced(Golden, 0, bad)));
    for (const auto &bad : {"8000000000000000", "7ff8000000000000", "7ff0000000000000",
                            "fff0000000000000", "000000000000000", "00000000000000000",
                            "404E000000000000", "+000000000000000", "000000000000000g"})
        assert(!RecoveryRule::decode(replaced(Golden, 1, bad)));
    // A finite double that rounds to a different native float is not a preimage.
    assert(!RecoveryRule::decode(replaced(Golden, 3, "3ff0000000000001")));
    assert(!RecoveryRule::decode(replaced(Golden, 6, "47efffffe0000001")));
    assert(!RecoveryRule::decode(replaced(Golden, 7, "9")));
    assert(!RecoveryRule::decode(replaced(Golden, 8, "8")));
    for (const auto &bad : {"0", "GG", "61;62", "-1"})
        assert(!RecoveryRule::decode(replaced(Golden, 9, bad)));
    assert(!RecoveryRule::decode(replaced(Golden, 9, std::string(8194, '0'))));
    for (std::size_t field = 10; field <= 23; ++field) {
        assert(!RecoveryRule::decode(replaced(Golden, field, "4294967296")));
        assert(!RecoveryRule::decode(replaced(Golden, field, "-1")));
        if (field >= 11 && field <= 20)
            assert(!RecoveryRule::decode(replaced(Golden, field, "65536")));
    }
    assert(!RecoveryRule::decode(replaced(Golden, 24, std::string(62, '0'))));
    assert(!RecoveryRule::decode(replaced(Golden, 24, std::string(66, '0'))));
    assert(!RecoveryRule::decode(std::string(RecoveryRule::MaxBytes + 1, '0')));
}
void roundTrip()
{
    const auto basic = RecoveryRule::capture(Rule{});
    assert(basic && basic->encode() == Golden);
    const auto decoded = RecoveryRule::decode(Golden);
    assert(decoded && decoded->encode() == Golden);
    for (unsigned direction = 0; direction <= 8; ++direction)
        for (unsigned transform = 0; transform <= 7; ++transform) {
            Rule original;
            original.m_resolution = {-2, -1};
            original.m_offset = {-2147483647.0, -0.0};
            original.m_refreshRate = 59.94F;
            original.m_scale = -1.F;
            original.m_disabled = direction % 2 == 0;
            original.m_autoDir = static_cast<std::uint8_t>(direction);
            original.m_transform = transform;
            original.m_mirrorOf = std::string("desc:original;mirror\0bytes", 26);
            original.m_drmMode.clock = std::numeric_limits<std::uint32_t>::max();
            original.m_drmMode.hdisplay = std::numeric_limits<std::uint16_t>::max();
            original.m_drmMode.name[31] = static_cast<char>(0xff);
            const auto saved = RecoveryRule::capture(original);
            assert(saved);
            const auto restored = RecoveryRule::decode(saved->encode());
            assert(restored && restored->encode() == saved->encode());
            Rule current;
            current.m_name = "new selector";
            current.m_iccFile = "new profile";
            current.m_vrr = 1;
            const auto merged = restored->mergeOwnedFields(current);
            const auto after = RecoveryRule::capture(merged);
            assert(after && after->encode() == saved->encode());
            assert(merged.m_name == current.m_name && merged.m_iccFile == current.m_iccFile &&
                   merged.m_vrr == current.m_vrr);
            assert(current.m_resolution.x == 0); // Merge never mutates its input.
        }
    Rule bounded;
    bounded.m_mirrorOf = std::string(4096, 'x');
    const auto max = RecoveryRule::capture(bounded);
    assert(max && max->encode().size() <= RecoveryRule::MaxBytes);
    assert(RecoveryRule::decode(max->encode()));
    bounded.m_mirrorOf += 'x';
    assert(!RecoveryRule::capture(bounded));
    bounded = Rule{};
    bounded.m_scale = std::numeric_limits<float>::quiet_NaN();
    assert(!RecoveryRule::capture(bounded));
    bounded = Rule{};
    bounded.m_autoDir = 9;
    assert(!RecoveryRule::capture(bounded));
    bounded = Rule{};
    bounded.m_transform = 8;
    assert(!RecoveryRule::capture(bounded));
}
} // namespace

int main()
{
    malformed();
    roundTrip();
}
