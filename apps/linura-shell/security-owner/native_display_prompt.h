#pragma once

#include <QString>
#include <QtGlobal>

namespace Linura::SecurityOwner {
// Adapter-private comparison scope. This never selects a principal, supplies
// human approval or authorizes an effect. Control creates the canonical challenge.
struct NativeDisplayPromptScope final
{
    enum class Purpose : quint32 { Apply = 0, Keep = 1, Revert = 2 };
    QString digest;
    Purpose purpose = Purpose::Apply;
    // Both original Control deadlines; never remapped at owner/native admission.
    quint64 deadlineUnixMs = 0, deadlineBootMs = 0;
    [[nodiscard]] bool valid() const noexcept;
    bool operator==(const NativeDisplayPromptScope &) const = default;
};
struct NativeDisplayPromptStatus final
{
    enum class Phase : quint32 { Arming = 0, Ready = 1, Consumed = 2, Cancelled = 3 };
    quint64 topology = 0, epoch = 0;
    Phase phase = Phase::Cancelled;
};
} // namespace Linura::SecurityOwner
