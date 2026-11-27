#pragma once

#include <functional>
#include <memory>
#include <utility>

namespace Linura::HyprlandDisplay {
// Compositor-thread comparison state only. Tokens identify objects already
// owned by authenticated, non-copyable Root grants. This class authenticates no
// peer and creates no execution, restoration, retirement or startup permission.
// The live StartupFence keeps its instance private to those grants.
class CurrentLifetimeChain final
{
  public:
    using Token = std::shared_ptr<void>;
    CurrentLifetimeChain() = default;
    CurrentLifetimeChain(const CurrentLifetimeChain &) = delete;
    CurrentLifetimeChain &operator=(const CurrentLifetimeChain &) = delete;

    [[nodiscard]] bool attempted() const noexcept
    {
        return phase_ != Phase::Initial;
    }
    [[nodiscard]] bool available() const noexcept
    {
        if (phase_ == Phase::Initial || phase_ == Phase::Failed)
            return false;
        if (owner_.expired() || (phase_ == Phase::Successor && successor_.expired()) ||
            !check(alive_))
            return poison();
        return true;
    }
    [[nodiscard]] bool retired() const noexcept
    {
        return phase_ == Phase::Current && retiredAlive_ && available() &&
               (check(retiredAlive_) || poison());
    }
    [[nodiscard]] bool hasRetirement() const noexcept
    {
        return static_cast<bool>(retiredAlive_);
    }
    [[nodiscard]] bool admitInitial(const Token &owner, std::function<bool()> alive)
    {
        if (phase_ != Phase::Initial)
            return false;
        phase_ = Phase::Failed; // A failed first admission cannot be retried.
        if (!owner || !check(alive))
            return false;
        owner_ = owner;
        alive_ = std::move(alive);
        phase_ = Phase::Current;
        return available();
    }
    [[nodiscard]] bool markRetired(const Token &owner, std::function<bool()> alive)
    {
        if (phase_ != Phase::Current || !same(owner_, owner) || retiredAlive_)
            return false;
        if (!available() || !check(alive))
            return poison();
        retiredAlive_ = std::move(alive);
        return true;
    }
    [[nodiscard]] bool transfer(const Token &owner, const Token &successor,
                                std::function<bool()> alive)
    {
        if (phase_ != Phase::Current || !same(owner_, owner) || !retiredAlive_)
            return false;
        // The predecessor scene has intentionally moved its grant before this
        // call. Do not call its obsolete scene callback: compare the actual
        // retired grant and newly established protected successor instead.
        if (!successor || same(owner_, successor) || !check(retiredAlive_) || !check(alive))
            return poison();
        successor_ = successor;
        alive_ = std::move(alive);
        retiredAlive_ = {};
        phase_ = Phase::Successor;
        return available();
    }
    [[nodiscard]] bool admitSuccessor(const Token &successor, const Token &owner,
                                      std::function<bool()> alive)
    {
        if (phase_ != Phase::Successor || !same(successor_, successor))
            return false;
        if (!owner || same(owner_, owner) || same(successor_, owner) || !available() ||
            !check(alive))
            return poison();
        owner_ = owner;
        alive_ = std::move(alive);
        successor_.reset();
        phase_ = Phase::Current;
        return available();
    }

  private:
    enum class Phase { Initial, Current, Successor, Failed };
    static bool same(const std::weak_ptr<void> &expected, const Token &actual) noexcept
    {
        const auto retained = expected.lock();
        return retained && actual && retained == actual && !retained.owner_before(actual) &&
               !actual.owner_before(retained);
    }
    static bool check(const std::function<bool()> &alive) noexcept
    {
        try {
            return alive && alive();
        } catch (...) {
            return false;
        }
    }
    bool poison() const noexcept
    {
        phase_ = Phase::Failed;
        return false;
    }
    mutable Phase phase_ = Phase::Initial;
    std::weak_ptr<void> owner_, successor_;
    std::function<bool()> alive_, retiredAlive_;
};
} // namespace Linura::HyprlandDisplay
