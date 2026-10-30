#pragma once

#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Linura::HyprlandDisplay {

// These are private compositor-adapter values. They are neither Linura resource
// IDs nor executable plans, credentials, approval or policy decisions.
struct OutputKey final
{
    std::uint64_t handle = 0, generation = 0;
    auto operator<=>(const OutputKey &) const = default;
};
struct Mode final
{
    std::int32_t width = 0, height = 0, refreshMilliHz = 0;
    auto operator<=>(const Mode &) const = default;
};
struct Target final
{
    OutputKey output;
    bool enabled = false;
    Mode mode;
    std::uint32_t scaleMilli = 0, transform = 0;
    std::int32_t x = 0, y = 0;
    std::optional<OutputKey> mirror;
    bool operator==(const Target &) const = default;
};
using Layout = std::vector<Target>;

struct Head final
{
    OutputKey key;
    std::vector<Mode> modes;
    Target current;
    // Facts acquired by the compositor from the actual output and session-lock
    // resources, never booleans supplied by a protocol client.
    bool powered = false, covered = false;
    // Bounded native comparison data, never permission or an executable plan.
    bool linuraOwned = false;
    std::string baseRuleWitness{}, outputIdentityWitness{}, ownedTargetWitness{};
    bool operator==(const Head &) const = default;
};
enum class Coverage { Unlocked, Secure, Transitioning, Unknown };
struct Snapshot final
{
    std::uint64_t generation = 0;
    // Changes on native lock release or a coverage gap, including a release
    // and reacquisition between two snapshots. Acquiring protection may retain
    // this epoch; losing it may not.
    std::uint64_t securityEpoch = 0;
    std::vector<Head> heads;
    Coverage coverage = Coverage::Unknown;
    bool operator==(const Snapshot &) const = default;
};
struct Correlation final
{
    std::string transaction, effectDigest, dispatchDigest;
    std::uint64_t deadlineUnixMs = 0;
    bool operator==(const Correlation &) const = default;
};
struct ClockSample final
{
    std::uint64_t unixMs = 0, bootMs = 0;
};

// The implementation lives inside the pinned compositor. applyOwnedLayout must
// revalidate native object lifetimes and merge ONLY the fields in Target into
// current monitor rules. It must never replace rules or interpret commands.
// A return value is only a transport/mechanism acknowledgement.
class Backend
{
  public:
    virtual ~Backend() = default;
    [[nodiscard]] virtual std::optional<Snapshot> snapshot() = 0;
    // Production reads the kernel clocks directly. Sampling after potentially
    // expensive native work prevents a pre-probe timestamp extending authority.
    [[nodiscard]] virtual std::optional<ClockSample> clock() = 0;
    [[nodiscard]] virtual bool applyOwnedLayout(const Layout &, const Snapshot &) = 0;
    // Compensation restores the previous ownership/automatic-rule semantics.
    // Re-applying numeric baseline targets would leave new explicit overrides.
    [[nodiscard]] virtual bool restoreOwnedLayout(const Layout &, const Snapshot &) = 0;
    // Independent native property check in addition to fresh layout geometry.
    [[nodiscard]] virtual bool restoredOwnedState() = 0;
    // The compositor retains the actual native sleep/shutdown inhibitor, not
    // its client. Denial, an already preparing transition or unknown service
    // state must refuse BEFORE a display write. A failed recovery keeps it.
    [[nodiscard]] virtual bool inhibitPowerTransitions() = 0;
    virtual void releasePowerInhibitor() noexcept = 0;
};

// A single bounded native mechanism attempt. Rust owns admission, authorization,
// durable prepare, independent verification and final transaction retirement.
// The compositor owns this object and its timer independently of every client.
class DisplayTransaction final
{
  public:
    enum class Phase { Pending, Restoring, Confirmed, Restored, RecoveryFailed };
    static constexpr std::uint64_t WindowMs = 15'000;
    static constexpr std::size_t MaxHeads = 16, MaxModes = 128;

    DisplayTransaction(const DisplayTransaction &) = delete;
    DisplayTransaction &operator=(const DisplayTransaction &) = delete;
    ~DisplayTransaction();
    // Caller must arm the compositor's independent timer before calling start.
    // Failure after the object is returned can be ambiguous; never call start
    // again for that durable dispatch, even if its reply was lost.
    [[nodiscard]] static std::unique_ptr<DisplayTransaction>
    start(Backend &, const Correlation &, const Layout &baseline, const Layout &desired,
          const Snapshot &captured, ClockSample now);
    [[nodiscard]] bool confirm(const Correlation &, ClockSample now);
    void restore();
    void tick(std::optional<ClockSample> now);
    [[nodiscard]] Phase phase() const noexcept;
    [[nodiscard]] bool fenced() const noexcept;
    [[nodiscard]] const Correlation &correlation() const noexcept;
    [[nodiscard]] static bool validLayout(const Layout &, const Snapshot &);

  private:
    DisplayTransaction(Backend &, Correlation, Layout baseline, Layout desired, Snapshot,
                       ClockSample armed, std::uint64_t deadlineBootMs);
    [[nodiscard]] bool scopeMatches(const Snapshot &);
    [[nodiscard]] bool expired(ClockSample now) const;
    [[nodiscard]] bool matches(const Layout &, const Snapshot &) const;
    void verifyRestoration();
    Backend &backend_;
    Correlation correlation_;
    Layout baseline_, desired_;
    Snapshot inventory_;
    ClockSample armed_;
    std::uint64_t deadlineBootMs_ = 0;
    Phase phase_ = Phase::Pending;
    bool secureSeen_ = false;
};

} // namespace Linura::HyprlandDisplay
