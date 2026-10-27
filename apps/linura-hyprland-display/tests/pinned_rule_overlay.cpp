// Compiled only by the exact-source Hyprland SDK build, never the generic
// mechanism build. These are actual upstream rule types, not stand-in structs.
#include "rule_overlay.h"
#include "src/config/shared/monitor/MonitorRule.hpp"

#include <gtest/gtest.h>

using namespace Linura::HyprlandDisplay;

namespace {
Config::CMonitorRule originalRule()
{
    Config::CMonitorRule rule;
    rule.m_name = "description:fixture monitor";
    rule.m_resolution = {1920, 1080};
    rule.m_refreshRate = 75.F;
    rule.m_offset = {10, 20};
    rule.m_autoDir = Config::DIR_AUTO_LEFT;
    rule.m_scale = -1.F;
    rule.m_transform = WL_OUTPUT_TRANSFORM_FLIPPED;
    rule.m_mirrorOf = "fixture-original-mirror";
    rule.m_drmMode.clock = 148500;
    rule.m_drmMode.hdisplay = 1920;
    rule.m_enable10bit = true;
    rule.m_cmType = NCMType::CM_HDR;
    rule.m_sdrEotf = NTransferFunction::TF_FORCED_GAMMA22;
    rule.m_sdrSaturation = 1.2F;
    rule.m_sdrBrightness = 1.3F;
    rule.m_reservedArea = Desktop::CReservedArea(11, 12, 13, 14);
    rule.m_iccFile = "fixture/icc/profile.icc";
    rule.m_supportsWideColor = 1;
    rule.m_supportsHDR = -1;
    rule.m_sdrMinLuminance = 0.4F;
    rule.m_sdrMaxLuminance = 100;
    rule.m_minLuminance = 0.1F;
    rule.m_maxLuminance = 1200;
    rule.m_maxAvgLuminance = 400;
    rule.m_vrr = 2;
    return rule;
}
void unmanagedFieldsEqual(const Config::CMonitorRule &actual, const Config::CMonitorRule &before)
{
    EXPECT_EQ(actual.m_name, before.m_name);
    EXPECT_EQ(actual.m_enable10bit, before.m_enable10bit);
    EXPECT_EQ(actual.m_cmType, before.m_cmType);
    EXPECT_EQ(actual.m_sdrEotf, before.m_sdrEotf);
    EXPECT_EQ(actual.m_sdrSaturation, before.m_sdrSaturation);
    EXPECT_EQ(actual.m_sdrBrightness, before.m_sdrBrightness);
    EXPECT_EQ(actual.m_reservedArea, before.m_reservedArea);
    EXPECT_EQ(actual.m_iccFile, before.m_iccFile);
    EXPECT_EQ(actual.m_supportsWideColor, before.m_supportsWideColor);
    EXPECT_EQ(actual.m_supportsHDR, before.m_supportsHDR);
    EXPECT_EQ(actual.m_sdrMinLuminance, before.m_sdrMinLuminance);
    EXPECT_EQ(actual.m_sdrMaxLuminance, before.m_sdrMaxLuminance);
    EXPECT_EQ(actual.m_minLuminance, before.m_minLuminance);
    EXPECT_EQ(actual.m_maxLuminance, before.m_maxLuminance);
    EXPECT_EQ(actual.m_maxAvgLuminance, before.m_maxAvgLuminance);
    EXPECT_EQ(actual.m_vrr, before.m_vrr);
}
TEST(LinuraDisplayPinnedRule, OverlayPreservesAllUnmanagedNativeProperties)
{
    const auto before = originalRule();
    const Target target{OutputKey{1, 1}, true, Mode{1280, 720, 60000}, 1200, 1, 50, 60, {}};
    const auto actual = overlayDisplayFields(before, target, "fixture-native-root");
    unmanagedFieldsEqual(actual, before);
    EXPECT_EQ(actual.m_resolution, Vector2D(1280, 720));
    EXPECT_FLOAT_EQ(actual.m_refreshRate, 60.F);
    EXPECT_EQ(actual.m_offset, Vector2D(50, 60));
    EXPECT_EQ(actual.m_autoDir, Config::DIR_AUTO_NONE);
    EXPECT_FLOAT_EQ(actual.m_scale, 1.2F);
    EXPECT_EQ(actual.m_transform, WL_OUTPUT_TRANSFORM_90);
    EXPECT_EQ(actual.m_mirrorOf, "fixture-native-root");
    EXPECT_FALSE(actual.m_disabled);
    EXPECT_EQ(actual.m_drmMode.clock, 0U);
    EXPECT_EQ(actual.m_drmMode.hdisplay, 0U);
    // The copied baseline remains unchanged as well.
    EXPECT_EQ(before.m_autoDir, Config::DIR_AUTO_LEFT);
    EXPECT_EQ(before.m_drmMode.clock, 148500U);
}
TEST(LinuraDisplayPinnedRule, DisableChangesOnlyTheDisabledField)
{
    const auto before = originalRule();
    Target disabled;
    disabled.output = {1, 1};
    const auto actual = overlayDisplayFields(before, disabled, "");
    auto expected = before;
    expected.m_disabled = true;
    EXPECT_EQ(actual.compare(expected), Config::COMPARISON_FULL_MATCH);
    // Native compare omits these fields; check them independently.
    unmanagedFieldsEqual(actual, before);
    EXPECT_EQ(actual.m_drmMode.clock, before.m_drmMode.clock);
    EXPECT_EQ(actual.m_mirrorOf, before.m_mirrorOf);
}
} // namespace
