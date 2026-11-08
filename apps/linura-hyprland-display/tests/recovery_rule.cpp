#include "recovery_rule.h"
#include "recovery_lineage.h"

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
    std::string m_name = "", m_iccFile = "live profile";
    int m_vrr = 2;
};
const std::string Golden = "LNDR:2;0;0000000000000000;0000000000000000;404e000000000000;"
                           "0000000000000000;0000000000000000;bff0000000000000;0;0;;"
                           "0;0;0;0;0;0;0;0;0;0;0;0;0;0;"
                           "0000000000000000000000000000000000000000000000000000000000000000;;";

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
    for (const auto &text : {"", "LNDR:2;", "LNDR:01;", "LNDR:2;", "LNDR:2;0;"})
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
    for (const auto &bad : {"0", "GG", "61;62", "-1"})
        assert(!RecoveryRule::decode(replaced(Golden, 25, bad)));
    assert(!RecoveryRule::decode(replaced(Golden, 25, std::string(8194, '0'))));
    auto legacy = Golden;
    legacy.replace(0, 7, "LNDR:1;");
    legacy.pop_back(); // Old complete owned-field preimage had no selector.
    assert(!RecoveryRule::decode(legacy));
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
            original.m_name = "desc:original;selector";
            original.m_mirrorOf = std::string("desc:original;mirror\0bytes", 26);
            original.m_drmMode.clock = std::numeric_limits<std::uint32_t>::max();
            original.m_drmMode.hdisplay = std::numeric_limits<std::uint16_t>::max();
            original.m_drmMode.name[31] = static_cast<char>(0xff);
            const auto saved = RecoveryRule::capture(original);
            assert(saved);
            const auto restored = RecoveryRule::decode(saved->encode());
            assert(restored && restored->encode() == saved->encode());
            Rule current;
            current.m_name = original.m_name;
            current.m_iccFile = "new profile";
            current.m_vrr = 1;
            const auto merged = restored->mergeOwnedFields(current);
            assert(merged);
            const auto after = RecoveryRule::capture(*merged);
            assert(after && after->encode() == saved->encode());
            assert(merged->m_name == current.m_name && merged->m_iccFile == current.m_iccFile &&
                   merged->m_vrr == current.m_vrr);
            current.m_name += "different selector";
            assert(!restored->mergeOwnedFields(current));
            assert(current.m_resolution.x == 0); // Merge never mutates its input.
        }
    Rule bounded;
    bounded.m_mirrorOf = std::string(4096, 'x');
    bounded.m_name = std::string(4096, 's');
    const auto max = RecoveryRule::capture(bounded);
    assert(max && max->encode().size() <= RecoveryRule::MaxBytes);
    assert(RecoveryRule::decode(max->encode()));
    bounded.m_mirrorOf += 'x';
    assert(!RecoveryRule::capture(bounded));
    bounded = Rule{};
    bounded.m_name = std::string(4097, 's');
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

void lineage()
{
    Rule native;
    native.m_name = "desc:original;selector";
    const auto base = RecoveryRule::capture(native);
    assert(base);
    const std::vector<std::string> selectors{"", native.m_name, "unrelated"};
    const auto saved = RecoveryLineage::capture(*base, *base, selectors, 1, false, 0);
    assert(saved && saved->native().encode() == base->encode() && !saved->wlr());
    const auto bytes = saved->encode();
    assert(RecoveryLineage::decode(bytes));
    assert(bytes.starts_with("LNRL:2;") && saved->wlrSource() == RecoveryLineage::WlrSource::None);
    auto historical = bytes;
    historical.replace(0, 7, "LNRL:1;");
    historical.pop_back();
    const auto old = RecoveryLineage::decode(historical);
    assert(old && old->encode() == historical && !old->wlr());

    for (std::size_t i = 0; i < bytes.size(); ++i)
        assert(!RecoveryLineage::decode(std::string_view(bytes).substr(0, i)));
    for (const auto &suffix : {";", "0;", "\n", "extra"})
        assert(!RecoveryLineage::decode(bytes + suffix));
    assert(!RecoveryLineage::decode("LNRL:01;" + bytes.substr(7)));
    assert(!RecoveryLineage::decode("LNRL:2;02;" + bytes.substr(bytes.find(';', 7) + 1)));
    assert(!RecoveryLineage::capture(*base, *base, selectors, 0, false, 0));
    assert(!RecoveryLineage::capture(*base, *base, selectors, 3, false, 0));
    assert(!RecoveryLineage::capture(*base, *base, selectors, std::nullopt, false, 0));
    assert(!RecoveryLineage::capture(*base, *base, selectors, 1, false, 1));
    assert(!RecoveryLineage::capture(*base, *base, selectors, 1, true, 32));
    auto reordered = selectors;
    std::swap(reordered[0], reordered[2]);
    const auto reorderedSaved = RecoveryLineage::capture(*base, *base, reordered, 1, false, 0);
    assert(reorderedSaved && reorderedSaved->encode() != bytes);
    assert(saved->sameOverlayCompensationSources(*reorderedSaved));
    for (std::uint32_t mask = 0; mask <= 31; ++mask) {
        auto effective = native;
        effective.m_disabled = true; // wlr enabled state is unconditional.
        if (mask & 3U) {
            effective.m_resolution = {1920, 1080};
            effective.m_refreshRate = 59.94F;
        }
        if (mask & 4U)
            effective.m_offset = {-1920, 1080};
        if (mask & 8U)
            effective.m_transform = 3;
        if (mask & 16U)
            effective.m_scale = 1.25F;
        const auto projected = RecoveryRule::capture(effective);
        assert(projected);
        const auto withWlr = RecoveryLineage::capture(*base, *projected, selectors, 1, true, mask,
                                                      (mask & 3U) ? 59940U : 0U);
        assert(withWlr && withWlr->wlr() && withWlr->wlrMask() == mask);
        const auto recovered = withWlr->replacementProjection(std::string(64, 'a'));
        assert(recovered && !recovered->wlr() && recovered->hasWlrProjection() &&
               recovered->wlrSource() == RecoveryLineage::WlrSource::RestoredProjection &&
               recovered->restoredOrigin() == std::string(64, 'a'));
        assert(recovered->encode() != withWlr->encode() &&
               !recovered->sameOverlayCompensationSources(*withWlr));
        const auto recoveredRead = RecoveryLineage::decode(recovered->encode());
        assert(recoveredRead && recoveredRead->encode() == recovered->encode() &&
               !recoveredRead->wlr() && recoveredRead->wlrMask() == mask);
        assert(!withWlr->replacementProjection("") &&
               !withWlr->replacementProjection(std::string(64, '0')) &&
               !withWlr->replacementProjection(std::string(64, 'A')));
        assert(!withWlr->replacementSourceCompatible(*recovered));
        auto oldLive = withWlr->encode();
        oldLive.replace(0, 7, "LNRL:1;");
        oldLive.pop_back();
        const auto originalLive = RecoveryLineage::decode(oldLive);
        assert(originalLive && originalLive->wlr() && originalLive->encode() == oldLive);
        assert(originalLive->replacementProjection(std::string(64, 'a'))->encode() ==
               recovered->encode());
        auto counterfeit = recovered->encode();
        counterfeit.replace(0, 7, "LNRL:1;");
        assert(!RecoveryLineage::decode(counterfeit));
        const auto decoded = RecoveryLineage::decode(withWlr->encode());
        assert(decoded && decoded->encode() == withWlr->encode());
        assert(decoded->native().encode() == base->encode());
        assert(decoded->effective().encode() == projected->encode());
        assert(!RecoveryLineage::capture(*base, *projected, selectors, 1, false, 0));
    }
    // Even a purported complete wlr geometry projection cannot change native
    // automatic placement, mirror source, selector or custom modeline lineage.
    for (int field = 0; field < 4; ++field) {
        auto changed = native;
        if (field == 0)
            changed.m_autoDir = 1;
        if (field == 1)
            changed.m_mirrorOf = "another";
        if (field == 2)
            changed.m_name = "different";
        if (field == 3)
            changed.m_drmMode.clock = 1;
        const auto projected = RecoveryRule::capture(changed);
        assert(projected &&
               !RecoveryLineage::capture(*base, *projected, selectors, 1, true, 31, 60000));
    }
    const auto automatic = RecoveryRule::capture(Rule{});
    // Native float projection is lossy at large source values. Both exact
    // integer states must survive distinctly, without a rounded reconstruction.
    auto quantized = native;
    const auto raw = std::numeric_limits<std::uint32_t>::max();
    quantized.m_refreshRate = static_cast<float>(raw) / 1000.F;
    const auto projected = RecoveryRule::capture(quantized);
    assert(projected && projected->hasWlrRefresh(raw) && projected->hasWlrRefresh(raw - 1));
    const auto first = RecoveryLineage::capture(*base, *projected, selectors, 1, true, 1, raw);
    const auto second = RecoveryLineage::capture(*base, *projected, selectors, 1, true, 1, raw - 1);
    assert(first && second && first->encode() != second->encode());
    assert(!first->sameOverlayCompensationSources(*second));
    assert(RecoveryLineage::decode(first->encode())->wlrRefreshMilliHz() == raw);
    assert(RecoveryLineage::decode(second->encode())->wlrRefreshMilliHz() == raw - 1);
    assert(!RecoveryLineage::capture(*base, *projected, selectors, 1, true, 1, 60000));
    assert(automatic &&
           RecoveryLineage::capture(*automatic, *automatic, {}, std::nullopt, false, 0));
    assert(!RecoveryLineage::capture(*automatic, *automatic, {""}, std::nullopt, false, 0));
    assert(
        !RecoveryLineage::capture(*base, *base, std::vector<std::string>(257, "x"), 0, false, 0));
    auto oversized = selectors;
    oversized[0] = std::string(4097, 'x');
    assert(!RecoveryLineage::capture(*base, *base, oversized, 1, false, 0));
    assert(!RecoveryLineage::decode(std::string(RecoveryLineage::MaxBytes + 1, '0')));
    // Reading old immutable bytes must not first expand them into version 2
    // and reject a record that was valid at the old exact size limit.
    const auto body = automatic->encode().substr(7);
    const auto tail = body + body + "0;0;0;";
    auto prefix = [](unsigned count) { return "LNRL:1;0;" + std::to_string(count) + ';'; };
    unsigned count = 3;
    if ((RecoveryLineage::MaxBytes - (prefix(count).size() + count + tail.size())) % 2)
        count = 4;
    const auto fixed =
        prefix(count).size() + count + tail.size() + 2 * 8192 + (count == 4 ? 2U : 0U);
    assert(fixed < RecoveryLineage::MaxBytes && (RecoveryLineage::MaxBytes - fixed) % 2 == 0);
    auto limit = prefix(count) + std::string(8192, 'a') + ';' + std::string(8192, 'b') + ';' +
                 std::string(RecoveryLineage::MaxBytes - fixed, 'c') + ';';
    if (count == 4)
        limit += "64;";
    limit += tail;
    const auto retainedLimit = RecoveryLineage::decode(limit);
    assert(limit.size() == RecoveryLineage::MaxBytes && retainedLimit &&
           retainedLimit->encode() == limit && !retainedLimit->wlr());
    assert(!RecoveryLineage::decode(limit + ';'));
}
void replacementProjection()
{
    Rule native;
    native.m_name = "DP-1";
    native.m_resolution = {1920, 1080};
    native.m_scale = 1;
    native.m_offset = {0, 0};
    const auto base = RecoveryRule::capture(native);
    assert(base);
    const std::vector<std::string> selectors{"", "DP-1"};
    const auto replacement = RecoveryLineage::capture(*base, *base, selectors, 1, false, 0);
    assert(replacement);
    for (std::uint32_t mask = 0; mask <= 31; ++mask) {
        auto effective = native;
        effective.m_disabled = true;
        if (mask & 3U) {
            effective.m_resolution = {1280, 720};
            effective.m_refreshRate = 59.94F;
        }
        if (mask & 4U)
            effective.m_offset = {-1920, 100};
        if (mask & 8U)
            effective.m_transform = 3;
        if (mask & 16U)
            effective.m_scale = 1.25F;
        const auto saved = RecoveryRule::capture(effective);
        assert(saved);
        const auto original = RecoveryLineage::capture(*base, *saved, selectors, 1, true, mask,
                                                       (mask & 3U) ? 59940 : 0);
        assert(original && original->replacementSourceCompatible(*replacement));
        assert(!original->replacementSourceCompatible(*original)); // Never adopt a new wlr owner.
        auto current = native;
        current.m_iccFile = "new live profile";
        current.m_vrr = 7;
        // Uncommitted fields continue to follow current native rules after
        // restoration. Old effective geometry cannot freeze those semantics.
        current.m_scale = 2;
        current.m_offset = {800, 900};
        current.m_transform = 6;
        current.m_resolution = {3840, 2160};
        current.m_refreshRate = 120;
        const auto projected = original->restoredWlrProjection(current);
        const auto retained = original->replacementProjection(std::string(64, 'b'));
        assert(projected && retained);
        const auto retainedRule = retained->restoredWlrProjection(current);
        assert(retainedRule && !retained->wlr() &&
               RecoveryRule::capture(*retainedRule)->encode() ==
                   RecoveryRule::capture(*projected)->encode() &&
               retainedRule->m_iccFile == current.m_iccFile && retainedRule->m_vrr == 7);
        assert(projected && projected->m_disabled && projected->m_iccFile == current.m_iccFile &&
               projected->m_vrr == 7);
        assert(projected->m_resolution.x == ((mask & 3U) ? 1280 : 3840));
        assert(projected->m_refreshRate == ((mask & 3U) ? 59.94F : 120));
        assert(projected->m_offset.x == ((mask & 4U) ? -1920 : 800));
        assert(projected->m_transform == ((mask & 8U) ? 3 : 6));
        assert(projected->m_scale == ((mask & 16U) ? 1.25F : 2));
        auto foreign = current;
        foreign.m_name = "DP-2";
        assert(!original->restoredWlrProjection(foreign));
        const auto reordered = RecoveryLineage::capture(*base, *base, {"DP-1", ""}, 0, false, 0);
        assert(reordered && !original->replacementSourceCompatible(*reordered));
    }
    assert(!replacement->restoredWlrProjection(native));
}

} // namespace

int main()
{
    malformed();
    roundTrip();
    lineage();
    replacementProjection();
}
