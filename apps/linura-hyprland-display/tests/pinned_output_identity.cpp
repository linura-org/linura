// Exercise actual pinned Aquamarine metadata, including in-place updates of
// one unchanged output object. No native output, service or effect is created.
#include "native_output_identity.h"

#include <gtest/gtest.h>
#include <limits>

using namespace Linura::HyprlandDisplay;

namespace {
class Output final : public Aquamarine::IOutput
{
  public:
    bool commit() override
    {
        ADD_FAILURE() << "identity observation attempted a write";
        return false;
    }
    bool test() override
    {
        ADD_FAILURE() << "identity observation attempted a native test";
        return false;
    }
    Hyprutils::Memory::CSharedPointer<Aquamarine::IBackendImplementation> getBackend() override
    {
        return nullptr;
    }
    std::vector<Aquamarine::SDRMFormat> getRenderFormats() override
    {
        ADD_FAILURE() << "identity observation performed an additional native query";
        return {};
    }
    bool pendingPageFlip() override
    {
        return false;
    }
    bool pendingIdleFrame() override
    {
        return false;
    }
};

void initialize(Output &output)
{
    output.name = "DP-1";
    output.description = "Fixture panel";
    output.make = "Fixture";
    output.model = "Panel";
    output.serial = "serial-one";
    output.physicalSize = {600, 340};
    output.parsedEDID.make = "EDID fixture";
    output.parsedEDID.model = "EDID panel";
    output.parsedEDID.serial = "EDID serial-one";
}

TEST(LinuraDisplayPinnedIdentity, InPlaceConnectorAndEdidChangesInvalidateIdentity)
{
    Output output;
    initialize(output);
    const auto baseline = nativeOutputIdentity(output);
    ASSERT_TRUE(baseline);
    EXPECT_EQ(baseline, nativeOutputIdentity(output));
    for (auto *field :
         {&output.name, &output.description, &output.make, &output.model, &output.serial,
          &output.parsedEDID.make, &output.parsedEDID.model, &output.parsedEDID.serial}) {
        const auto saved = *field;
        *field += "-replacement";
        EXPECT_NE(baseline, nativeOutputIdentity(output));
        *field = saved;
    }
    output.physicalSize.x += 1;
    EXPECT_NE(baseline, nativeOutputIdentity(output));
    output.physicalSize.x -= 1;
    output.parsedEDID.supportsBT2020 = true;
    EXPECT_NE(baseline, nativeOutputIdentity(output));
}

TEST(LinuraDisplayPinnedIdentity, CapabilityChangesAreDistinctFromLayoutEffects)
{
    Output output;
    initialize(output);
    output.parsedEDID.hdrMetadata = Aquamarine::IOutput::SHDRMetadata{1000, 400, 0.1F, true};
    output.parsedEDID.chromaticityCoords =
        Aquamarine::IOutput::SChromaticityCoords{{0.6, 0.3}, {0.3, 0.6}, {0.1, 0.1}, {0.3, 0.3}};
    const auto baseline = nativeOutputIdentity(output);
    ASSERT_TRUE(baseline);
    output.enabled = !output.enabled;
    output.vrrActive = !output.vrrActive;
    output.state->setEnabled(true);
    EXPECT_EQ(baseline, nativeOutputIdentity(output));
    output.parsedEDID.hdrMetadata->supportsPQ = false;
    EXPECT_NE(baseline, nativeOutputIdentity(output));
    output.parsedEDID.hdrMetadata->supportsPQ = true;
    output.parsedEDID.hdrMetadata->desiredContentMinLuminance = 0.2F;
    EXPECT_NE(baseline, nativeOutputIdentity(output));
    output.parsedEDID.hdrMetadata->desiredContentMinLuminance = 0.1F;
    output.parsedEDID.chromaticityCoords->white.y += 0.01;
    EXPECT_NE(baseline, nativeOutputIdentity(output));
    output.parsedEDID.chromaticityCoords.reset();
    EXPECT_NE(baseline, nativeOutputIdentity(output));
}

TEST(LinuraDisplayPinnedIdentity, MissingOptionalEdidIsSupportedButMalformedFactsAreNot)
{
    Output output;
    initialize(output);
    output.physicalSize = {};
    output.parsedEDID = {};
    ASSERT_TRUE(nativeOutputIdentity(output)); // Real headless outputs have no EDID.
    output.name.clear();
    EXPECT_FALSE(nativeOutputIdentity(output));
    initialize(output);
    output.description = std::string(4097, 'x');
    EXPECT_FALSE(nativeOutputIdentity(output));
    for (const char invalid : {'\0', '\n', '\x7f'}) {
        initialize(output);
        output.serial += invalid;
        EXPECT_FALSE(nativeOutputIdentity(output));
    }
    for (const auto invalid : {-1.0, 32769.0, std::numeric_limits<double>::infinity(),
                               std::numeric_limits<double>::quiet_NaN()}) {
        initialize(output);
        output.physicalSize.x = invalid;
        EXPECT_FALSE(nativeOutputIdentity(output));
    }
    initialize(output);
    output.parsedEDID.hdrMetadata = Aquamarine::IOutput::SHDRMetadata{};
    output.parsedEDID.hdrMetadata->desiredContentMinLuminance =
        std::numeric_limits<float>::quiet_NaN();
    EXPECT_FALSE(nativeOutputIdentity(output));
    output.parsedEDID.hdrMetadata.reset();
    output.parsedEDID.chromaticityCoords = Aquamarine::IOutput::SChromaticityCoords{};
    output.parsedEDID.chromaticityCoords->red.x = 1.01;
    EXPECT_FALSE(nativeOutputIdentity(output));
}
} // namespace
