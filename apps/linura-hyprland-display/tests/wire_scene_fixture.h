#pragma once

#include "protected_wire.h"
#include "mutation_fixture.h"

namespace Linura::HyprlandDisplay::Test {
// A transport-only scene. Explicit consumption models a private resource, not
// authentication, renderer completion or a production continuation decision.
class WireSceneFixture final : public ProtectedScene
{
  public:
    bool consumed = false, reserved = false, closed = false;
    bool attach(OutputKey, wl_resource *, Configure) override
    {
        return false;
    }
    bool acknowledge(OutputKey, std::uint32_t) override
    {
        return false;
    }
    std::optional<ProtectedSceneStatus> status() override
    {
        return ProtectedSceneStatus{"74e3ca24-b38b-4b62-9671-ae32dc38fd57", 1, 1,
                                    consumed ? ProtectedInteraction::Phase::Consumed
                                             : ProtectedInteraction::Phase::Arming};
    }
    bool refreshPresentation() override
    {
        return false;
    }
    bool consume(const std::string &, std::uint64_t epoch) override
    {
        if (closed || consumed || epoch != 1)
            return false;
        consumed = true;
        return true;
    }
    std::shared_ptr<MutationProtection>
    reserveOriginalRestoration(const Correlation &, const Layout &, const Layout &,
                               const Snapshot &, ClockSample,
                               const std::map<OutputKey, std::string> &, const std::string &,
                               std::function<bool()>) override
    {
        return {}; // This fixture has no authenticated original-Root recovery.
    }
    std::shared_ptr<MutationProtection> reserveMutation(const Correlation &, const Layout &,
                                                        const Layout &, const Snapshot &,
                                                        ClockSample) override
    {
        if (closed || !consumed || reserved)
            return {};
        reserved = true;
        return std::make_shared<MutationFixture>();
    }
    bool beginFinalization(const ProtectedInteraction::Scope &, const std::string &) override
    {
        return false; // No original Root witness in this transport fixture.
    }
    bool quiesceFinalization(OwnedNativeFd, const Correlation &, std::uint64_t) override
    {
        return false; // No actual Root channel or native safety-frame proof.
    }
    bool spendNativeRelease(OwnedNativeFd, const Correlation &, std::uint64_t, std::uint64_t,
                            std::string_view, std::string_view) override
    {
        return false; // No original Root or Control authority in this fixture.
    }
    bool retireCurrent(OwnedNativeFd, std::string_view) override
    {
        return false;
    }
    bool commitCurrent(OwnedNativeFd, std::string_view) override
    {
        return false;
    } // No real Root grant in this fixture.
    bool retirePower(OwnedNativeFd, std::string_view) override
    {
        return false;
    }
    bool transferCompletion(OwnedNativeFd, std::string_view) override
    {
        return false; // No authenticated Root completion in this fixture.
    }
    bool beginDecision(const ProtectedInteraction::Scope &) override
    {
        return false;
    }
    void close() noexcept override
    {
        closed = true;
    }
};
} // namespace Linura::HyprlandDisplay::Test
