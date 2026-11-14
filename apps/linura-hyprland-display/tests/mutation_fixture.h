#pragma once

#include "display_transaction.h"
#include <utility>
#include <functional>

namespace Linura::HyprlandDisplay::Test {
// Explicit component fixture. No native frame, input or human proof is inferred
// from this value; real presentation and admission have separate native gates.
class MutationFixture final : public MutationProtection
{
  public:
    bool live = true, allowApply = true, allowRestore = true;
    bool applyPresented = true, restorePresented = true, keepDecision = true;
    unsigned applies = 0, restores = 0, ends = 0, releases = 0;
    std::function<void()> onApply;
    bool healthy() override
    {
        return live;
    }
    bool beginWrite(Write kind, const Snapshot &) override
    {
        if (kind == Write::Apply) {
            ++applies;
            if (onApply)
                onApply();
            return allowApply;
        }
        ++restores;
        return allowRestore;
    }
    void endWrite(Write) noexcept override
    {
        ++ends;
    }
    bool presented(Write kind) override
    {
        return kind == Write::Apply ? applyPresented : restorePresented;
    }
    bool consumeKeepDecision() override
    {
        return std::exchange(keepDecision, false);
    }
    bool consumeRevertDecision() override
    {
        return std::exchange(revertDecision, false);
    }
    bool revertDecision = true;
    void release() noexcept override
    {
        ++releases;
    }
};
} // namespace Linura::HyprlandDisplay::Test
