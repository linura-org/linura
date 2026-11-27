// Compiled only by the exact-source Hyprland SDK build, never the generic
// mechanism build. These are actual upstream rule types, not stand-in structs.
#include "rule_overlay.h"
#include "recovery_witness.h"
#include "recovery_lineage.h"
#include "src/config/shared/monitor/MonitorRule.hpp"
#include "src/protocols/OutputManagement.hpp"

#include <gtest/gtest.h>
#include <limits>

using namespace Linura::HyprlandDisplay;

static_assert(OUTPUT_HEAD_COMMITTED_MODE == 1 && OUTPUT_HEAD_COMMITTED_CUSTOM_MODE == 2 &&
              OUTPUT_HEAD_COMMITTED_POSITION == 4 && OUTPUT_HEAD_COMMITTED_TRANSFORM == 8 &&
              OUTPUT_HEAD_COMMITTED_SCALE == 16 && OUTPUT_HEAD_COMMITTED_ADAPTIVE_SYNC == 32);

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
TEST(LinuraDisplayPinnedRule, RestorationResumesAutomaticRulesAndRetainsUnrelatedDrift)
{
    using Checkpoint = RuleOverlayCheckpoint<int, Config::CMonitorRule>;
    const auto before = originalRule();
    const Target baseline{OutputKey{1, 1}, true, Mode{1920, 1080, 75000}, 2000, 0, 0, 0, {}};
    const Target desired{OutputKey{1, 1}, true, Mode{1280, 720, 60000}, 1250, 1, 50, 60, {}};
    const Checkpoint::Identities identities{{10, baseline.output}};
    Checkpoint checkpoint;
    ASSERT_TRUE(checkpoint.capture({}, {{10, before}}, {baseline}, identities));
    EXPECT_EQ(overlayDisplayFields(before, desired, "").m_autoDir, Config::DIR_AUTO_NONE);
    auto current = before;
    current.m_iccFile = "fixture/new-profile.icc";
    current.m_vrr = 1;
    current.m_sdrBrightness = 1.1F;
    auto restored = checkpoint.restoration({baseline}, {{10, current}}, identities,
                                           sameRecoveryRule<Config::CMonitorRule>);
    ASSERT_TRUE(restored);
    EXPECT_TRUE(restored->empty()); // Empty ownership resumes the live native rule.
    EXPECT_EQ(current.m_autoDir, before.m_autoDir);
    EXPECT_EQ(current.m_scale, -1.F);
    EXPECT_EQ(current.m_drmMode.clock, before.m_drmMode.clock);
    EXPECT_EQ(current.m_mirrorOf, before.m_mirrorOf);
    EXPECT_NE(current.m_iccFile, before.m_iccFile);
    EXPECT_NE(current.m_vrr, before.m_vrr);
    EXPECT_TRUE(checkpoint.restored(*restored, {{10, current}}, identities,
                                    sameRecoveryRule<Config::CMonitorRule>));
    Checkpoint priorOwned;
    const Checkpoint::Overlay previous{{10, baseline}};
    ASSERT_TRUE(priorOwned.capture(previous, {{10, before}}, {baseline}, identities));
    restored = priorOwned.restoration({baseline}, {{10, current}}, identities,
                                      sameRecoveryRule<Config::CMonitorRule>);
    ASSERT_TRUE(restored);
    EXPECT_EQ(*restored, previous);
    const auto effective = overlayDisplayFields(current, restored->at(10), "");
    EXPECT_EQ(effective.m_iccFile, current.m_iccFile);
    EXPECT_EQ(effective.m_vrr, current.m_vrr);
}
TEST(LinuraDisplayPinnedRule, OwnedRuleDriftAndCustomModelineChangesRefuseRestoration)
{
    using Checkpoint = RuleOverlayCheckpoint<int, Config::CMonitorRule>;
    const auto before = originalRule();
    const Target baseline{OutputKey{1, 1}, true, Mode{1920, 1080, 75000}, 2000, 0, 0, 0, {}};
    const Checkpoint::Identities identities{{10, baseline.output}};
    Checkpoint checkpoint;
    ASSERT_TRUE(checkpoint.capture({}, {{10, before}}, {baseline}, identities));
    for (int field = 0; field != 26; ++field) {
        auto changed = before;
        switch (field) {
        case 25:
            changed.m_name = "different resolved selector";
            break;
        case 0:
            changed.m_disabled = true;
            break;
        case 1:
            changed.m_resolution.x += 1;
            break;
        case 2:
            changed.m_refreshRate += 1;
            break;
        case 3:
            changed.m_offset.x += 1;
            break;
        case 4:
            changed.m_autoDir = Config::DIR_AUTO_RIGHT;
            break;
        case 5:
            changed.m_scale = 1;
            break;
        case 6:
            changed.m_transform = WL_OUTPUT_TRANSFORM_NORMAL;
            break;
        case 7:
            changed.m_mirrorOf.clear();
            break;
        case 8:
            ++changed.m_drmMode.clock;
            break;
        case 9:
            ++changed.m_drmMode.hdisplay;
            break;
        case 10:
            ++changed.m_drmMode.hsync_start;
            break;
        case 11:
            ++changed.m_drmMode.hsync_end;
            break;
        case 12:
            ++changed.m_drmMode.htotal;
            break;
        case 13:
            ++changed.m_drmMode.hskew;
            break;
        case 14:
            ++changed.m_drmMode.vdisplay;
            break;
        case 15:
            ++changed.m_drmMode.vsync_start;
            break;
        case 16:
            ++changed.m_drmMode.vsync_end;
            break;
        case 17:
            ++changed.m_drmMode.vtotal;
            break;
        case 18:
            ++changed.m_drmMode.vscan;
            break;
        case 19:
            ++changed.m_drmMode.vrefresh;
            break;
        case 20:
            ++changed.m_drmMode.flags;
            break;
        case 21:
            ++changed.m_drmMode.type;
            break;
        case 22:
            ++changed.m_drmMode.name[31];
            break;
        case 23:
            changed.m_resolution.y += 1;
            break;
        case 24:
            changed.m_offset.y += 1;
            break;
        }
        EXPECT_FALSE(checkpoint.restoration({baseline}, {{10, changed}}, identities,
                                            sameRecoveryRule<Config::CMonitorRule>))
            << field;
        EXPECT_NE(RecoveryWitness::rule(before), RecoveryWitness::rule(changed)) << field;
    }
}

TEST(LinuraDisplayPinnedRule, CompleteLineageKeepsUnderlyingRuleAndExactWlrSourceDistinct)
{
    const auto original = originalRule();
    const auto native = RecoveryRule::capture(original);
    ASSERT_TRUE(native);
    SWlrManagerSavedOutputState state;
    state.committedProperties =
        OUTPUT_HEAD_COMMITTED_MODE | OUTPUT_HEAD_COMMITTED_POSITION | OUTPUT_HEAD_COMMITTED_SCALE;
    state.resolution = {2560, 1440};
    state.refresh = 59940;
    state.position = {-2560, 0};
    state.scale = 1.25F;
    state.enabled = true;
    auto resolved = original;
    resolved.m_disabled = !state.enabled;
    resolved.m_resolution = state.resolution;
    resolved.m_refreshRate = state.refresh / 1000.F;
    resolved.m_offset = state.position;
    resolved.m_scale = state.scale;
    const auto effective = RecoveryRule::capture(resolved);
    ASSERT_TRUE(effective);
    const std::vector<std::string> selectors{"", original.m_name};
    const auto lineage = RecoveryLineage::capture(*native, *effective, selectors, 1, true,
                                                  state.committedProperties, state.refresh);
    ASSERT_TRUE(lineage);
    const auto restored = RecoveryLineage::decode(lineage->encode());
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->native().encode(), native->encode());
    EXPECT_EQ(restored->effective().encode(), effective->encode());
    EXPECT_EQ(restored->wlrRefreshMilliHz(), state.refresh);
    auto changed = original;
    changed.m_scale = 2.F; // Hidden under the same effective wlr scale.
    const auto changedNative = RecoveryRule::capture(changed);
    ASSERT_TRUE(changedNative);
    const auto drifted = RecoveryLineage::capture(*changedNative, *effective, selectors, 1, true,
                                                  state.committedProperties, state.refresh);
    ASSERT_TRUE(drifted);
    EXPECT_NE(drifted->encode(), lineage->encode());
    EXPECT_FALSE(lineage->sameOverlayCompensationSources(*drifted));
    // Unrelated native fields remain live and absent from owned restoration.
    changed = original;
    changed.m_vrr = 1;
    changed.m_iccFile = "new live profile";
    const auto unrelated = RecoveryRule::capture(changed);
    ASSERT_TRUE(unrelated);
    const auto same = RecoveryLineage::capture(*unrelated, *effective, selectors, 1, true,
                                               state.committedProperties, state.refresh);
    ASSERT_TRUE(same);
    EXPECT_EQ(same->encode(), lineage->encode());
}

TEST(LinuraDisplayPinnedRule, RecoveryWitnessPreservesAutomaticSemanticsAndExcludesUnmanagedDrift)
{
    const auto before = originalRule();
    const auto encoded = RecoveryWitness::rule(before);
    ASSERT_TRUE(encoded);
    const auto recovered = RecoveryRule::decode(*encoded);
    ASSERT_TRUE(recovered);
    auto live = before;
    live.m_name = before.m_name;
    live.m_iccFile = "new live profile";
    live.m_vrr = 1;
    live.m_scale = 1.F;
    const auto merged = recovered->mergeOwnedFields(live);
    ASSERT_TRUE(merged);
    EXPECT_TRUE(sameOwnedDisplayFields(*merged, before));
    unmanagedFieldsEqual(*merged, live);
    EXPECT_EQ(RecoveryWitness::rule(*merged), encoded);
    live.m_name = "new live selector";
    EXPECT_FALSE(recovered->mergeOwnedFields(live));
    EXPECT_EQ(encoded, RecoveryWitness::rule(before));
    EXPECT_TRUE(encoded->starts_with("LNDR:2;"));
    auto changed = before;
    changed.m_enable10bit = false;
    changed.m_cmType = NCMType::CM_SRGB;
    changed.m_sdrSaturation = 0.9F;
    changed.m_sdrBrightness = 1.1F;
    changed.m_reservedArea = Desktop::CReservedArea(1, 2, 3, 4);
    changed.m_iccFile = "new/profile.icc";
    changed.m_supportsWideColor = -1;
    changed.m_supportsHDR = 1;
    changed.m_minLuminance = 0.3F;
    changed.m_vrr = 1;
    EXPECT_TRUE(sameOwnedDisplayFields(before, changed));
    EXPECT_EQ(encoded, RecoveryWitness::rule(changed));
    changed.m_name = "changed selector";
    EXPECT_TRUE(sameOwnedDisplayFields(before, changed));
    EXPECT_FALSE(sameRecoveryRule(before, changed));
    EXPECT_NE(encoded, RecoveryWitness::rule(changed));
    changed = before;
    changed.m_scale = 1.F;
    EXPECT_NE(encoded, RecoveryWitness::rule(changed));
}

TEST(LinuraDisplayPinnedRule, RecoveryWitnessNormalizesSignedZeroAndRejectsUnboundedOrNonfiniteData)
{
    auto a = originalRule(), b = a;
    a.m_offset.x = 0.0;
    b.m_offset.x = -0.0;
    EXPECT_EQ(RecoveryWitness::rule(a), RecoveryWitness::rule(b));
    b.m_scale = std::numeric_limits<float>::quiet_NaN();
    EXPECT_FALSE(RecoveryWitness::rule(b));
    b = a;
    b.m_refreshRate = std::numeric_limits<float>::infinity();
    EXPECT_FALSE(RecoveryWitness::rule(b));
    b = a;
    b.m_mirrorOf = std::string(4097, 'x');
    EXPECT_FALSE(RecoveryWitness::rule(b));
    NativeOutputIdentity identity{};
    identity.text[0] = "DP-1";
    const auto first = RecoveryWitness::identity(identity);
    ASSERT_TRUE(first);
    EXPECT_TRUE(first->starts_with("LNDF:2;0;0;0;"));
    identity.kernelDrm = {226, 0, 1};
    const auto drm = RecoveryWitness::identity(identity);
    ASSERT_TRUE(drm);
    EXPECT_TRUE(drm->starts_with("LNDF:2;226;0;1;"));
    EXPECT_NE(first, drm);
    for (const auto key : {std::array<std::uint32_t, 3>{0, 0, 1}, {226, 64, 1}, {226, 0, 0}}) {
        identity.kernelDrm = key;
        EXPECT_FALSE(RecoveryWitness::identity(identity));
    }
    identity.kernelDrm = {226, 0, 1};
    identity.text[4] = "another native serial";
    EXPECT_NE(first, RecoveryWitness::identity(identity));
    identity.text[1] = std::string(4097, 'x');
    EXPECT_FALSE(RecoveryWitness::identity(identity));
}
} // namespace
