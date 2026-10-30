#pragma once

#include <cstdint>

namespace Linura::HyprlandDisplay {

// One actual native output, not wire assertions. A rendered safety frame may
// hide the ordinary scene, but can NEVER attest the owner's review/PAM content.
// The adapter supplies buffer identity, queued commit result and hardware event
// independently. Reconfiguration retires all in-flight evidence, not highWater.
class ProtectedFrame final
{
  public:
    enum class Kind { Safety, Content };
    enum class Presentation { Ignored, Safety, Content, Failed };

    [[nodiscard]] bool rendered(const void *buffer, Kind kind) noexcept
    {
        if (failed_ || !buffer)
            return false;
        pending_ = buffer;
        pendingKind_ = kind;
        return true;
    }
    [[nodiscard]] bool prepared(const void *buffer) const noexcept
    {
        return !failed_ && buffer && pending_ == buffer;
    }
    [[nodiscard]] bool queued(const void *buffer, std::uint64_t id) noexcept
    {
        if (!prepared(buffer) || id == 0 || id <= highWater_) {
            fail();
            return false;
        }
        pending_ = nullptr;
        kind_ = pendingKind_;
        id_ = highWater_ = id;
        submitted_ = presented_ = false;
        return true;
    }
    [[nodiscard]] bool submitted(std::uint64_t id, bool accepted) noexcept
    {
        if (failed_)
            return false;
        if (id == 0 || id != id_)
            return true; // A retired configure/commit cannot change this frame.
        if (!accepted) {
            fail();
            return false;
        }
        submitted_ = true;
        return true;
    }
    [[nodiscard]] Presentation presented(std::uint64_t id, bool hardwareCompleted) noexcept
    {
        if (failed_)
            return Presentation::Failed;
        if (id == 0 || id != id_ || presented_)
            return Presentation::Ignored;
        if (!submitted_ || !hardwareCompleted) {
            fail();
            return Presentation::Failed;
        }
        presented_ = true;
        return kind_ == Kind::Content ? Presentation::Content : Presentation::Safety;
    }
    [[nodiscard]] Kind queuedKind() const noexcept
    {
        return kind_;
    }
    [[nodiscard]] Kind pendingKind() const noexcept
    {
        return pendingKind_;
    }
    void invalidate() noexcept
    {
        pending_ = nullptr;
        id_ = 0;
        submitted_ = presented_ = false;
        // Failure is terminal for this native output lifetime.
    }

  private:
    void fail() noexcept
    {
        failed_ = true;
        invalidate();
    }
    const void *pending_ = nullptr;
    Kind pendingKind_ = Kind::Safety, kind_ = Kind::Safety;
    std::uint64_t id_ = 0, highWater_ = 0;
    bool submitted_ = false, presented_ = false, failed_ = false;
};

} // namespace Linura::HyprlandDisplay
