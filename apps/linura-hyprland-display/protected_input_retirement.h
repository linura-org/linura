#pragma once

namespace Linura::HyprlandDisplay {
// Native input routing lifetime only. This cannot release ext-session-lock,
// authenticate anyone, approve a plan or issue any display operation.
class ProtectedInputRetirement final
{
  public:
    ProtectedInputRetirement() = default;
    ProtectedInputRetirement(const ProtectedInputRetirement &) = delete;
    ProtectedInputRetirement &operator=(const ProtectedInputRetirement &) = delete;
    ProtectedInputRetirement(ProtectedInputRetirement &&) = delete;
    ProtectedInputRetirement &operator=(ProtectedInputRetirement &&) = delete;
    enum class Phase { Open, Private, Quarantined, Draining };
    struct Held final
    {
        bool any = false;
        bool escape = false;
        bool other = false;
    };
    [[nodiscard]] Phase phase() const noexcept;
    [[nodiscard]] bool blocked() const noexcept;
    [[nodiscard]] bool begin(Held) noexcept;
    // The pinned adapter supplies a fresh physical exit witness, never a wire
    // boolean. Unknown closure quarantines subsequent typing as well as held keys.
    void close(bool freshPhysicalExit, Held) noexcept;
    // True means this event is consumed by retirement. Even the final release
    // must not escape into the next ordinary focus.
    [[nodiscard]] bool key(bool physical, bool escape, bool pressed, Held) noexcept;
    void poll(Held) noexcept;

  private:
    Phase phase_ = Phase::Open;
    bool escapeReleased_ = false;
};
} // namespace Linura::HyprlandDisplay
