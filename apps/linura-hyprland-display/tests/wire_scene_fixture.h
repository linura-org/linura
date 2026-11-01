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
    std::shared_ptr<MutationProtection> reserveMutation(const Correlation &, const Layout &,
                                                        const Layout &, const Snapshot &,
                                                        ClockSample) override
    {
        if (closed || !consumed || reserved)
            return {};
        reserved = true;
        return std::make_shared<MutationFixture>();
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
