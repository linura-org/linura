#pragma once

#include <QString>
#include <QtGlobal>

#include <optional>

namespace Linura::SecurityOwner {

// Adapter identity only. This is not an independently executable plan or a
// policy decision: Control still owns canonical planning, review and prepare.
struct NativeLockIdentity final
{
    QString resource;
    QString boot;
    quint32 uid = 0;
    QString session;
    quint64 createdMonotonicUs = 0;
    QString ownerInvocation;
    quint64 generation = 0;

    [[nodiscard]] static std::optional<NativeLockIdentity> parse(const QString &resource);
    // Within one invocation generations advance ONLY after durable release
    // acknowledgement. Historical acknowledgement is idempotent, not evidence
    // that the CURRENT generation is unlocked or permission to dispatch it.
    [[nodiscard]] bool wasRetiredBy(const NativeLockIdentity &current) const;
    bool operator==(const NativeLockIdentity &) const = default;
};

enum class ApprovalPurpose {
    ConfirmLock = 0,
    AuthenticateUnlock = 1,
    AuthenticateSuspend = 2,
    AuthenticateLogout = 3,
    AuthenticateReboot = 4,
    AuthenticatePowerOff = 5,
    EnableProtectiveLock = 6,
    RevokeProtectiveLock = 7,
};

enum class NativeSessionTransition { Suspend, Logout, Reboot, PowerOff };

// Exact read-only transition identity, not permission or an executable plan.
struct NativeTransitionIdentity final
{
    QString resource;
    NativeLockIdentity lock;
    NativeSessionTransition transition;
    quint64 successfulCyclesBefore = 0;
    [[nodiscard]] static std::optional<NativeTransitionIdentity> parse(const QString &resource);
    [[nodiscard]] const char *powerPermissionAction() const noexcept;
    bool operator==(const NativeTransitionIdentity &) const = default;
};

// Private bounded native mirror of the sealed Control challenge. Its transport
// handler MUST attest the Control sender before constructing it. Digests bind
// the conversation; none of these fields authorize privileged execution.
struct NativeApprovalScope final
{
    NativeLockIdentity lock;
    QString principal;
    QString request;
    QString plan;
    QString requestDigest;
    QString observationDigest;
    QString reviewDigest;
    ApprovalPurpose purpose = ApprovalPurpose::ConfirmLock;
    std::optional<NativeTransitionIdentity> transition = std::nullopt;

    [[nodiscard]] bool valid() const;
    [[nodiscard]] const char *authenticationAction() const noexcept;
    [[nodiscard]] bool requiresSessionOwnerAuthentication() const noexcept;
    bool operator==(const NativeApprovalScope &) const = default;
};

} // namespace Linura::SecurityOwner
