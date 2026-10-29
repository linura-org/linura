#include "lock_mechanism.h"
#include "native_approval.h"
#include "native_scope.h"
#include "secret_buffer.h"
#include "process_guard.h"
#include "native_launch.h"
#include "peer_guard.h"
#include "session_bootstrap.h"
#include "native_deadline.h"
#include "compositor_probe.h"

#include <QCoreApplication>
#include <QChar>
#include <QString>

#include <cstring>
#include <cerrno>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <sys/wait.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

using namespace Linura::SecurityOwner;

namespace {

std::size_t checks = 0;
void check(bool condition)
{
    ++checks;
    if (!condition)
        throw std::runtime_error("native component assertion failed (no secret data)");
}

NativeLockIdentity identity()
{
    const auto parsed = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:1"));
    check(parsed.has_value());
    return *parsed;
}

NativeApprovalScope scope(ApprovalPurpose purpose = ApprovalPurpose::AuthenticateUnlock)
{
    return {identity(),
            QStringLiteral("unix:uid:1000"),
            QStringLiteral("request:v010:session-lock:unit-test"),
            QStringLiteral("request:v010:session-lock:unit-test"),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
            purpose};
}

void scopeBounds()
{
    auto valid = scope();
    check(valid.valid());
    const auto original = valid.lock.resource;
    for (const QString &resource :
         {original + QLatin1Char(':'),
          original.left(original.lastIndexOf(QLatin1Char(':')) + 1) + QStringLiteral("01"),
          QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:1"),
          QString(257, QLatin1Char('x')),
          QString(original).replace(QStringLiteral(":1000:"), QStringLiteral(":01000:")),
          QString(original).replace(QStringLiteral(":1000:"), QStringLiteral(":0:")),
          QString(original).replace(QStringLiteral(":1000:"), QStringLiteral(":4294967296:")),
          QString(original).replace(QStringLiteral(":42:"), QStringLiteral(":0:")),
          QString(original).replace(QStringLiteral(":42:"), QStringLiteral(":+42:")),
          QString(original).replace(QStringLiteral(":42:"),
                                    QStringLiteral(":18446744073709551616:")),
          QString(original).replace(QStringLiteral("abcd"), QStringLiteral("ABCD")),
          QString(original).replace(QStringLiteral("98765432-1234-4567-89ab-0123456789ab"),
                                    QStringLiteral("00000000-0000-0000-0000-000000000000")),
          QString(original).replace(QStringLiteral(":2:"), QStringLiteral(":a/b:"))})
        check(!NativeLockIdentity::parse(resource));
    const QString canonical =
        QString(original).replace(QStringLiteral(":2:"), QStringLiteral(":seat_0-a:"));
    const auto canonicalIdentity = NativeLockIdentity::parse(canonical);
    check(canonicalIdentity && canonicalIdentity->session == QLatin1String("seat_0-a"));
    for (const char *alias : {"self", "auto", "current"}) {
        check(!NativeLockIdentity::parse(
            QString(original).replace(QStringLiteral(":2:"), QLatin1String(alias))));
    }
    valid.principal = QStringLiteral("unix:uid:0");
    check(!valid.valid());
    valid = scope();
    valid.lock.uid = 1001;
    check(!valid.valid());
    valid = scope();
    valid.plan += QLatin1Char('x');
    check(!valid.valid());
    valid = scope();
    valid.reviewDigest = QString(71, QLatin1Char('f'));
    check(!valid.valid());
    valid = scope();
    valid.observationDigest[7] = QLatin1Char('A');
    check(!valid.valid());
    valid = scope();
    valid.request = valid.plan = QStringLiteral("request:v010:session-lock:");
    check(!valid.valid());
    valid.request = valid.plan =
        QStringLiteral("request:v010:session-lock:") + QString(65, QLatin1Char('a'));
    check(!valid.valid());
    // The private mirror must share Control's canonical operation-id grammar,
    // not accidentally accept an alias unavailable to the durable lifecycle.
    for (const QString &slug :
         {QStringLiteral("Unit-test"), QStringLiteral("unit_test"), QStringLiteral("unit.test"),
          QStringLiteral("-unit"), QStringLiteral("unit-"), QStringLiteral("unit--test"),
          QStringLiteral("unit/test"), QStringLiteral("unit:test")}) {
        valid = scope();
        valid.request = valid.plan = QStringLiteral("request:v010:session-lock:") + slug;
        check(!valid.valid());
    }
}

void approvalNeverUnlocks()
{
    quint64 time = 100;
    auto reviewed = scope();
    NativeApproval approval(identity(), [&time] { return time; });
    LockMechanism lock(identity());
    check(lock.dispatch(identity(), true));
    check(lock.requestedSecure() && !lock.secureCoverage());
    check(!approval.begin(reviewed, false));
    lock.compositorCoverage(true);
    check(approval.begin(reviewed, lock.secureCoverage()));
    check(approval.nativePrompt(reviewed));
    check(approval.nativeCompleted(reviewed, true));
    check(lock.requestedSecure() && lock.secureCoverage());
    check(approval.consume(reviewed));
    check(!approval.consume(reviewed));
    check(lock.requestedSecure() && lock.secureCoverage());
    check(approval.state() == NativeApproval::State::Idle);
}

void displayApprovalRequiresItsOwnPresentedPurposeAndOriginalDeadline()
{
    const auto lock = identity();
    const QString topology =
        QStringLiteral("display:topology:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:seat0:"
                       "33333333-3333-4333-8333-333333333333:3");
    const auto layout = [&](int x) {
        return QStringLiteral("LNDL:1;") + topology +
               QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:%1:0:-;").arg(x);
    };
    for (const auto purpose : {ApprovalPurpose::ApplyDisplay, ApprovalPurpose::KeepDisplay,
                               ApprovalPurpose::RevertDisplay}) {
        auto reviewed = scope(purpose);
        reviewed.request = reviewed.plan = QStringLiteral("request:v010:display-layout:unit-test");
        reviewed.display = NativeDisplayApprovalBinding{
            QStringLiteral("LNDI:1;") + lock.resource + QLatin1Char(';') + layout(0) + layout(100),
            purpose == ApprovalPurpose::ApplyDisplay
                ? QString{}
                : QStringLiteral("sha256:") + QString(64, QLatin1Char('4')),
            1000, QStringLiteral("Arrange the current session displays"), 1000};
        check(reviewed.valid() && reviewed.isDisplay());
        check(!reviewed.requiresSessionOwnerAuthentication());
        check(std::strcmp(reviewed.authenticationAction(),
                          purpose == ApprovalPurpose::ApplyDisplay
                              ? "org.linura.authority.apply-display-layout"
                          : purpose == ApprovalPurpose::KeepDisplay
                              ? "org.linura.authority.keep-display-layout"
                              : "org.linura.authority.revert-display-layout") == 0);
        const auto bound = reviewed.protectedDisplayDigest();
        check(bound.size() == 64);
        auto substitute = reviewed;
        substitute.reviewDigest[7] = QLatin1Char('4');
        check(substitute.protectedDisplayDigest() != bound);
        substitute = reviewed;
        ++substitute.display->deadlineUnixMs;
        check(substitute.protectedDisplayDigest() != bound);
        substitute = reviewed;
        substitute.display->material.replace(QStringLiteral(":100:0:-;"),
                                             QStringLiteral(":101:0:-;"));
        check(substitute.valid() && substitute.protectedDisplayDigest() != bound);
        substitute = reviewed;
        substitute.display.reset();
        check(!substitute.valid() && substitute.protectedDisplayDigest().isEmpty());
        quint64 time = 100;
        NativeApproval approval(lock, [&] { return time; });
        check(!approval.begin(reviewed, false) && !approval.begin(reviewed, true));
        NativeDisplayPromptStatus ready{3, 7, NativeDisplayPromptStatus::Phase::Ready};
        auto stale = ready;
        stale.phase = NativeDisplayPromptStatus::Phase::Arming;
        check(!approval.beginDisplay(reviewed, stale, 1000));
        stale = ready;
        stale.epoch = 0;
        check(!approval.beginDisplay(reviewed, stale, 1000));
        stale = ready;
        ++stale.topology;
        check(!approval.beginDisplay(reviewed, stale, 1000));
        check(!approval.beginDisplay(scope(), ready, 1000));
        check(!approval.beginDisplay(reviewed, ready, 0));
        check(!approval.beginDisplay(reviewed, ready,
                                     purpose == ApprovalPurpose::ApplyDisplay ? 60'001 : 15'001));
        check(approval.beginDisplay(reviewed, ready, 1000));
        check(!approval.confirmHuman(reviewed) && !approval.consume(reviewed));
        check(approval.nativePrompt(reviewed));
        time = 1099;
        check(approval.nativeCompleted(reviewed, true));
        check(!approval.consume(substitute));
        time = 1100;
        check(!approval.consume(reviewed)); // Proof never renews the original window.
        check(approval.state() == NativeApproval::State::Idle);
        check(approval.beginDisplay(reviewed, ready, 1000));
        check(approval.nativePrompt(reviewed) && approval.nativeCompleted(reviewed, true));
        substitute = reviewed;
        substitute.purpose = purpose == ApprovalPurpose::KeepDisplay
                                 ? ApprovalPurpose::RevertDisplay
                                 : ApprovalPurpose::KeepDisplay;
        substitute.display->decisionDigest =
            QStringLiteral("sha256:") + QString(64, QLatin1Char('5'));
        check(substitute.valid() && !approval.consume(substitute));
        check(approval.consume(reviewed) && !approval.consume(reviewed));
    }
}

void protectiveSettingApprovalIsPurposeBound()
{
    for (auto purpose :
         {ApprovalPurpose::EnableProtectiveLock, ApprovalPurpose::RevokeProtectiveLock}) {
        auto reviewed = scope(purpose);
        check(!reviewed.valid());
        reviewed.request = reviewed.plan =
            QStringLiteral("request:v010:protective-lock-setting:unit-test");
        check(reviewed.valid() && reviewed.requiresSessionOwnerAuthentication());
        check(std::strcmp(reviewed.authenticationAction(),
                          purpose == ApprovalPurpose::EnableProtectiveLock
                              ? "org.linura.authority.enable-protective-lock"
                              : "org.linura.authority.revoke-protective-lock") == 0);
        quint64 time = 100;
        NativeApproval approval(identity(), [&time] { return time; });
        check(!approval.begin(reviewed, false));
        check(approval.begin(reviewed, true));
        check(!approval.confirmHuman(reviewed) && !approval.consume(reviewed));
        check(approval.nativePrompt(reviewed) && approval.nativeCompleted(reviewed, true));
        auto substituted = reviewed;
        substituted.purpose = purpose == ApprovalPurpose::EnableProtectiveLock
                                  ? ApprovalPurpose::RevokeProtectiveLock
                                  : ApprovalPurpose::EnableProtectiveLock;
        check(substituted.valid() && !approval.consume(substituted));
        substituted.purpose = ApprovalPurpose::AuthenticateUnlock;
        check(!substituted.valid() && !approval.consume(substituted));
        check(approval.consume(reviewed) && !approval.consume(reviewed));
    }
}

void transitionApprovalIsPurposeBound()
{
    const std::array purposes{
        ApprovalPurpose::AuthenticateSuspend, ApprovalPurpose::AuthenticateLogout,
        ApprovalPurpose::AuthenticateReboot, ApprovalPurpose::AuthenticatePowerOff};
    const std::array actions{"suspend", "logout", "reboot", "power-off"};
    const std::array authenticationActions{
        "org.linura.authority.suspend-session", "org.linura.authority.logout-session",
        "org.linura.authority.reboot-session", "org.linura.authority.power-off-session"};
    for (std::size_t index = 0; index < purposes.size(); ++index) {
        auto reviewed = scope(purposes[index]);
        check(!reviewed.valid()); // No implicit action/resource conversion.
        reviewed.request = reviewed.plan =
            QStringLiteral("request:v010:session-transition:unit-test");
        reviewed.transition = NativeTransitionIdentity::parse(
            QStringLiteral("session:transition:%1:0:%2")
                .arg(QLatin1String(actions[index]), reviewed.lock.resource.mid(13)));
        check(reviewed.transition.has_value() && reviewed.valid());
        check(std::strcmp(reviewed.authenticationAction(), authenticationActions[index]) == 0);
        quint64 time = 100;
        NativeApproval approval(identity(), [&time] { return time; });
        check(!approval.begin(reviewed, false)); // Never authenticate on an uncovered desktop.
        check(approval.begin(reviewed, true));
        check(!approval.consume(reviewed)); // Permission alone is not native proof.
        check(approval.nativePrompt(reviewed));
        check(approval.nativeCompleted(reviewed, true));
        auto substituted = reviewed;
        substituted.purpose = ApprovalPurpose::AuthenticateUnlock;
        check(!substituted.valid() && !approval.consume(substituted));
        // Only the exact original scope can consume the proof, once.
        check(approval.consume(reviewed) && !approval.consume(reviewed));
        check(approval.begin(reviewed, true));
        check(approval.nativePrompt(reviewed));
        check(approval.nativeCompleted(reviewed, true));
        check(approval.consume(reviewed) && !approval.consume(reviewed));
        for (auto other : purposes) {
            if (other == purposes[index])
                continue;
            substituted = reviewed;
            substituted.purpose = other;
            check(!substituted.valid());
        }
        substituted = reviewed;
        if (!substituted.transition)
            throw std::runtime_error("native transition fixture must be initialized");
        ++substituted.transition->lock.generation;
        check(!substituted.valid());
        substituted = reviewed;
        substituted.request = substituted.plan =
            QStringLiteral("request:v010:session-lock:unit-test");
        check(!substituted.valid());
    }
    auto invalid = scope(static_cast<ApprovalPurpose>(99));
    check(!invalid.valid() && invalid.authenticationAction() == nullptr);
}

void scopeSubstitution()
{
    quint64 time = 100;
    const auto reviewed = scope();
    NativeApproval approval(identity(), [&time] { return time; });
    check(approval.begin(reviewed, true));
    check(approval.nativePrompt(reviewed));
    check(approval.nativeCompleted(reviewed, true));
    std::vector<NativeApprovalScope> substitutions;
    auto other = reviewed;
    other.principal = QStringLiteral("unix:uid:1001");
    substitutions.push_back(other);
    other = reviewed;
    other.lock.generation = 2;
    substitutions.push_back(other);
    other = reviewed;
    other.lock.ownerInvocation = QStringLiteral("12345678-1234-4567-89ab-0123456789ab");
    substitutions.push_back(other);
    other = reviewed;
    other.request += QLatin1Char('x');
    substitutions.push_back(other);
    other = reviewed;
    other.plan += QLatin1Char('x');
    substitutions.push_back(other);
    other = reviewed;
    other.requestDigest[7] = QLatin1Char('f');
    substitutions.push_back(other);
    other = reviewed;
    other.observationDigest[7] = QLatin1Char('f');
    substitutions.push_back(other);
    other = reviewed;
    other.reviewDigest[7] = QLatin1Char('f');
    substitutions.push_back(other);
    other = reviewed;
    other.purpose = ApprovalPurpose::ConfirmLock;
    substitutions.push_back(other);
    for (const auto &substitution : substitutions) {
        check(!approval.consume(substitution));
        check(approval.state() == NativeApproval::State::Confirmed);
    }
    check(approval.consume(reviewed));
}

void approvalDenialsAndDeadlines()
{
    quint64 time = 100;
    const auto reviewed = scope();
    NativeApproval approval(identity(), [&time] { return time; });
    check(approval.begin(reviewed, true));
    check(!approval.confirmHuman(reviewed));
    // A retained native OS authorization without a fresh prompt is insufficient.
    check(!approval.nativeCompleted(reviewed, true));
    check(!approval.consume(reviewed));
    check(!approval.begin(reviewed, true));
    time += NativeApproval::FailureCooldownMs;
    check(approval.begin(reviewed, true));
    check(approval.nativePrompt(reviewed));
    check(!approval.nativeCompleted(reviewed, false));
    check(!approval.consume(reviewed));
    time += NativeApproval::FailureCooldownMs;
    check(approval.begin(reviewed, true));
    approval.cancel();
    check(!approval.nativeCompleted(reviewed, true));
    time += NativeApproval::FailureCooldownMs;
    check(approval.begin(reviewed, true));
    for (quint32 index = 0; index < NativeApproval::MaximumConversationPrompts; ++index)
        check(approval.nativePrompt(reviewed));
    check(!approval.nativePrompt(reviewed));
    check(!approval.nativeCompleted(reviewed, true));
    time += NativeApproval::FailureCooldownMs;
    check(approval.begin(reviewed, true));
    time += NativeApproval::ConversationMs;
    check(!approval.nativePrompt(reviewed));
    check(!approval.nativeCompleted(reviewed, true));
    check(approval.state() == NativeApproval::State::Cooldown);
    time += NativeApproval::FailureCooldownMs;
    check(approval.begin(reviewed, true));
    check(approval.nativePrompt(reviewed));
    check(approval.nativeCompleted(reviewed, true));
    time += NativeApproval::ProofMs - 1;
    check(approval.state() == NativeApproval::State::Confirmed);
    ++time;
    check(!approval.consume(reviewed));
    check(approval.begin(reviewed, true));
    approval.ownerLost();
    check(!approval.nativeCompleted(reviewed, true));
    check(!approval.begin(reviewed, true));
    check(approval.state() == NativeApproval::State::Faulted);
}

void confirmationAndClockFailure()
{
    quint64 time = 100;
    const auto reviewed = scope(ApprovalPurpose::ConfirmLock);
    NativeApproval approval(identity(), [&time] { return time; });
    check(!approval.begin(reviewed, true));
    check(approval.begin(reviewed, false));
    check(!approval.nativePrompt(reviewed));
    check(!approval.nativeCompleted(reviewed, true));
    check(!approval.consume(reviewed));
    check(approval.confirmHuman(reviewed));
    check(approval.consume(reviewed));
    check(!approval.consume(reviewed));
    check(approval.begin(reviewed, false));
    --time;
    check(!approval.confirmHuman(reviewed));
    check(approval.state() == NativeApproval::State::Faulted);
    NativeApproval overflow(identity(), [] { return std::numeric_limits<quint64>::max(); });
    check(!overflow.begin(reviewed, false));
    check(overflow.state() == NativeApproval::State::Faulted);
}

void compositorTransitions()
{
    const auto original = identity();
    LockMechanism lock(original);
    check(!lock.retainedVerifiedRelease(original)); // Ready is NOT release proof.
    check(!lock.dispatch(original, false));
    check(lock.dispatch(original, true));
    check(!lock.dispatch(original, true));
    check(!lock.dispatch(original, false));
    check(!lock.secureCoverage());
    check(!lock.retainedVerifiedRelease(original)); // Acquiring.
    lock.compositorCoverage(true);
    check(lock.secureCoverage());
    check(!lock.retainedVerifiedRelease(original)); // Secure.
    auto replacement = original;
    ++replacement.generation;
    check(!lock.dispatch(replacement, false));
    check(lock.dispatch(original, false));
    check(!lock.dispatch(original, false));
    check(lock.identity() == original);
    lock.compositorCoverage(false);
    check(lock.state() == LockMechanism::State::Releasing);
    check(!lock.retainedVerifiedRelease(original)); // Observation is not the proof.
    // Protocol event/ack is not verification.
    check(lock.identity() == original);
    check(!lock.independentlyVerifiedReleased(replacement));
    check(lock.independentlyVerifiedReleased(original));
    check(lock.state() == LockMechanism::State::Released);
    check(lock.retainedVerifiedRelease(original));
    check(!lock.retainedVerifiedRelease(replacement));
    check(lock.identity() == original); // Recovery still has its original resource.
    check(!lock.dispatch(original, true));
    check(!lock.dispatch(original, false));
    check(!lock.independentlyVerifiedReleased(original)); // One-shot MUST stay false.
    // Read-only repeat has no effect.
    check(lock.retainedVerifiedRelease(original));
    check(!lock.commitVerifiedRelease(replacement));
    check(lock.commitVerifiedRelease(original));
    check(!lock.commitVerifiedRelease(original));
    check(lock.identity().generation == 2);
    check(!lock.retainedVerifiedRelease(original));
    check(!lock.retainedVerifiedRelease(lock.identity()));
    check(NativeLockIdentity::parse(lock.identity().resource) == lock.identity());
    check(!lock.dispatch(original, true));
    check(lock.dispatch(lock.identity(), true));
    lock.compositorCoverage(true);
    lock.compositorCoverage(false);
    check(lock.state() == LockMechanism::State::Faulted);
    check(lock.requestedSecure() && !lock.secureCoverage());
    check(!lock.dispatch(lock.identity(), false));
    LockMechanism lost(original);
    lost.ownerLost();
    check(lost.requestedSecure() && !lost.secureCoverage());
    check(!lost.dispatch(original, false));
}

void generationCommitFence()
{
    const auto original = identity();
    LockMechanism lock(original);
    check(!lock.commitVerifiedRelease(original));
    check(lock.dispatch(original, true));
    check(!lock.independentlyVerifiedReleased(original));
    lock.compositorCoverage(true);
    check(!lock.commitVerifiedRelease(original));
    check(lock.dispatch(original, false));
    // Independent release while local native coverage is still secure is not
    // accepted: both mechanisms must agree before the commit fence can advance.
    check(!lock.independentlyVerifiedReleased(original));
    lock.compositorCoverage(false);
    check(lock.independentlyVerifiedReleased(original));
    lock.compositorCoverage(true); // Unexpected relock invalidates release state.
    check(lock.state() == LockMechanism::State::Faulted);
    check(!lock.retainedVerifiedRelease(original)); // Relock invalidates retained proof.
    check(!lock.commitVerifiedRelease(original));

    quint64 time = 100;
    NativeApproval approval(original, [&time] { return time; });
    const auto next = *NativeLockIdentity::parse(original.resource.chopped(1) + QLatin1Char('2'));
    check(!approval.advanceIdentity(original));
    auto skipped = next;
    skipped.resource = original.resource.chopped(1) + QLatin1Char('3');
    skipped.generation = 3;
    check(!approval.advanceIdentity(skipped));
    auto replaced = next;
    replaced.ownerInvocation = QStringLiteral("12345678-1234-4567-89ab-0123456789ab");
    replaced.resource.replace(original.ownerInvocation, replaced.ownerInvocation);
    check(!approval.advanceIdentity(replaced));
    auto reviewed = scope(ApprovalPurpose::ConfirmLock);
    check(approval.begin(reviewed, false));
    check(!approval.advanceIdentity(next));
    check(approval.confirmHuman(reviewed));
    check(!approval.advanceIdentity(next));
    check(approval.consume(reviewed));
    check(approval.advanceIdentity(next));
    check(!approval.begin(reviewed, false));
    reviewed.lock = next;
    check(approval.begin(reviewed, false));
    approval.cancel();
    check(!approval.advanceIdentity(skipped)); // Do not reset denial/cooldown.
    time += NativeApproval::FailureCooldownMs;
    check(approval.advanceIdentity(skipped));
    approval.ownerLost();
    check(!approval.advanceIdentity(skipped));

    auto exhausted = original;
    exhausted.generation = std::numeric_limits<quint64>::max();
    exhausted.resource =
        original.resource.left(original.resource.lastIndexOf(QLatin1Char(':')) + 1) +
        QString::number(exhausted.generation);
    LockMechanism overflow(exhausted);
    check(overflow.dispatch(exhausted, true));
    overflow.compositorCoverage(true);
    check(overflow.dispatch(exhausted, false));
    overflow.compositorCoverage(false);
    check(overflow.independentlyVerifiedReleased(exhausted));
    check(!overflow.commitVerifiedRelease(exhausted));
    check(overflow.state() == LockMechanism::State::Faulted);
}

void protectedStorage()
{
    SecretBuffer secret;
    // Component qualification must actually establish the protected mapping.
    // An unavailable mlock is a failed test, not a skipped/pass input fallback.
    check(secret.available());
    check(secret.length() == 0);
    const QString generated(SecretBuffer::MaximumScalars, QChar(char16_t(0x61)));
    check(secret.append(QStringView(generated)));
    check(secret.length() == SecretBuffer::MaximumScalars);
    check(!secret.append(QStringView(generated).first(1)));
    check(secret.length() == SecretBuffer::MaximumScalars);
    secret.eraseLast();
    check(secret.length() == SecretBuffer::MaximumScalars - 1);
    check(secret.respond([&](const char *response) {
        check(std::strlen(response) == SecretBuffer::MaximumScalars - 1);
    }));
    check(secret.length() == 0);
    const QString multibyte =
        QString::fromUcs4(std::array<char32_t, 3>{0x41, 0x20ac, 0x1f642}.data(), 3);
    check(secret.append(QStringView(multibyte)));
    check(secret.length() == 3);
    secret.eraseLast();
    check(secret.length() == 2);
    check(secret.respond([](const char *response) { check(std::strlen(response) == 4); }));
    const QString malformed(1, QChar(char16_t(0xd800)));
    check(!secret.append(QStringView(malformed)));
    check(secret.length() == 0);
    const QString control(1, QChar(char16_t(0)));
    check(!secret.append(QStringView(control)));
    check(secret.append(QStringView(generated).first(1)));
    try {
        (void)secret.respond(
            [](const char *) { throw std::runtime_error("synthetic callback failure"); });
        check(false);
    } catch (const std::runtime_error &) {
        check(secret.length() == 0);
    }
    secret.clear();
    secret.eraseLast();
    check(secret.length() == 0);
    check(secret.respond([](const char *response) { check(response[0] == '\0'); }));
    check(secret.append(QStringView(generated).first(1)));
    check(!secret.respond({}));
    check(secret.length() == 0);
}

void protectedUtf8Storage()
{
    SecretBuffer buffer;
    check(buffer.available());
    // Generated Unicode scalars, never credentials or account fixtures.
    for (char32_t scalar : std::array<char32_t, 9>{0x7e, 0xa0, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff,
                                                   0x10000, 0x10ffff}) {
        const auto encoded = QString::fromUcs4(&scalar, 1).toUtf8();
        check(buffer.appendUtf8(
            std::string_view(encoded.constData(), static_cast<std::size_t>(encoded.size()))));
        check(buffer.length() == 1);
        check(buffer.respond([&](const char *response) {
            check(std::memcmp(response, encoded.constData(),
                              static_cast<std::size_t>(encoded.size())) == 0);
            check(response[encoded.size()] == '\0');
        }));
        check(buffer.length() == 0);
    }
    const char prefix = static_cast<char>(0x20 + 17);
    for (const auto invalid : std::array<std::string_view, 15>{
             std::string_view("\0", 1), "\x1f", "\x7f", "\xc2\x80", "\xc2\x9f", "\x80", "\xc0\xaf",
             "\xc2", "\xe0\x80\xaf", "\xed\xa0\x80", "\xef\xbf", "\xf0\x80\x80\x80",
             "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff"}) {
        check(buffer.appendUtf8(std::string_view(&prefix, 1)));
        check(!buffer.appendUtf8(invalid));
        check(buffer.length() == 1);
        check(buffer.respond(
            [&](const char *response) { check(response[0] == prefix && response[1] == '\0'); }));
    }
    check(!buffer.appendUtf8({}));
    const char32_t scalar = 0x10000;
    const auto full =
        QString::fromUcs4(&scalar, 1).repeated(int(SecretBuffer::MaximumScalars)).toUtf8();
    check(static_cast<std::size_t>(full.size()) == SecretBuffer::MaximumBytes);
    check(buffer.appendUtf8(
        std::string_view(full.constData(), static_cast<std::size_t>(full.size()))));
    check(buffer.length() == SecretBuffer::MaximumScalars);
    check(!buffer.appendUtf8(std::string_view(&prefix, 1)));
    buffer.eraseLast();
    check(buffer.length() == SecretBuffer::MaximumScalars - 1);
    check(buffer.appendUtf8(std::string_view(&prefix, 1)));
    check(!buffer.appendUtf8(std::string_view(&prefix, 1)));
    buffer.clear();
    check(buffer.length() == 0);
}

void supervisedPeerBinding()
{
    const NativeServiceFacts valid{
        QStringLiteral(":1.42"),
        QStringLiteral(":1.42"),
        999,
        2048,
        2048,
        QStringLiteral("98765432-1234-4567-89ab-0123456789ab"),
        QStringLiteral("active"),
        QStringLiteral("running"),
        QStringLiteral("/usr/lib/systemd/system/linura-authorityd.service"),
        false,
        true,
        true,
        true};
    const auto peer = bindNativeService(NativePeerPurpose::ControlApproval, 999, valid);
    check(peer.has_value());
    std::vector<NativeServiceFacts> substitutions;
    auto other = valid;
    other.sender = QStringLiteral(":1.43");
    substitutions.push_back(other);
    other = valid;
    other.nativeUid = 0; // Root/local identity is not the supervised Control peer.
    substitutions.push_back(other);
    other = valid;
    ++other.nativePid;
    substitutions.push_back(other);
    other = valid;
    other.mainPid = 0;
    substitutions.push_back(other);
    other = valid;
    other.sender = other.namedOwner = QStringLiteral("org.linura.Authority1");
    substitutions.push_back(other);
    other = valid;
    other.invocation = QStringLiteral("00000000-0000-0000-0000-000000000000");
    substitutions.push_back(other);
    other = valid;
    other.activeState = QStringLiteral("inactive");
    substitutions.push_back(other);
    other = valid;
    other.subState = QStringLiteral("start");
    substitutions.push_back(other);
    other = valid;
    other.fragment = QStringLiteral("/tmp/linura-authorityd.service");
    substitutions.push_back(other);
    other = valid;
    other.dropInsPresent = true;
    substitutions.push_back(other);
    other = valid;
    other.rootImmutableFragment = false;
    substitutions.push_back(other);
    other = valid;
    other.rootImmutableImage = false;
    substitutions.push_back(other);
    other = valid;
    other.exactNativeExecStart = false;
    substitutions.push_back(other);
    for (const auto &substitution : substitutions)
        check(!bindNativeService(NativePeerPurpose::ControlApproval, 999, substitution));
    check(!bindNativeService(NativePeerPurpose::ControlApproval, 0, valid));
    check(!bindNativeService(NativePeerPurpose::PreparedSessionDispatch, 999, valid));
    other = valid;
    other.nativeUid = 0;
    other.fragment = QStringLiteral("/usr/lib/systemd/system/linura-executor-session.service");
    check(bindNativeService(NativePeerPurpose::PreparedSessionDispatch, 999, other).has_value());
    other.fragment = QStringLiteral("/usr/lib/systemd/system/polkit.service");
    check(!bindNativeService(NativePeerPurpose::NativeAuthenticationDaemon, 998, other));
    other.nativeUid = 998;
    check(bindNativeService(NativePeerPurpose::NativeAuthenticationDaemon, 998, other).has_value());
    check(!bindNativeService(NativePeerPurpose::NativeAuthenticationDaemon, 0, other));
}

void supervisedLaunchBinding()
{
    const QString image = QStringLiteral("/usr/lib/linura/linura-security-owner");
    const NativeLaunchFacts valid{image, {image}, false, 1234, 5678, 0, 0, 2048, 0, 0};
    check(exactNativeLaunch(valid, image, {image}, 2048));
    std::vector<NativeLaunchFacts> substitutions;
    auto other = valid;
    other.image = QStringLiteral("/tmp/linura-security-owner");
    substitutions.push_back(other);
    other = valid;
    other.arguments.append(QStringLiteral("--load-user-ui"));
    substitutions.push_back(other);
    other = valid;
    other.arguments.clear();
    substitutions.push_back(other);
    other = valid;
    other.arguments[0] = QStringLiteral("linura-security-owner");
    substitutions.push_back(other);
    other = valid;
    other.ignoreFailure = true;
    substitutions.push_back(other);
    other = valid;
    other.startedReal = 0;
    substitutions.push_back(other);
    other = valid;
    other.startedMonotonic = 0;
    substitutions.push_back(other);
    other = valid;
    other.exitedReal = 1;
    substitutions.push_back(other);
    other = valid;
    other.exitedMonotonic = 1;
    substitutions.push_back(other);
    other = valid;
    ++other.pid;
    substitutions.push_back(other);
    other = valid;
    other.code = 1;
    substitutions.push_back(other);
    other = valid;
    other.status = 1;
    substitutions.push_back(other);
    for (const auto &substitution : substitutions)
        check(!exactNativeLaunch(substitution, image, {image}, 2048));
    check(!exactNativeLaunch(valid, image, {image}, 0));
    check(!exactNativeLaunch(valid, image, {}, 2048));
    check(!exactNativeExecStart(QVariant{}, image, {image}, 2048));
    check(!exactNativeExecStart(QVariant(image), image, {image}, 2048));
    check(!exactNativeExecStart(QVariant(QStringList{image}), image, {image}, 2048));
    // The pinned Arch polkit 127 unit uses exactly two audited flags. The
    // third word is never a generic argument-list or daemon-identity bypass.
    other = valid;
    other.image = QStringLiteral("/usr/lib/polkit-1/polkitd");
    other.arguments = {other.image};
    other.arguments.append(QStringLiteral("--no-debug"));
    other.arguments.append(QStringLiteral("--log-level=notice"));
    check(exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments = {other.image};
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments.append(QStringLiteral("--no-debug"));
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments = {other.image};
    other.arguments.append(QStringLiteral("--log-level=notice"));
    other.arguments.append(QStringLiteral("--no-debug"));
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments = {other.image};
    other.arguments.append(QStringLiteral("--no-debug"));
    other.arguments.append(QStringLiteral("--log-level=debug"));
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments.append(QStringLiteral("--replace"));
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other = valid;
    other.arguments.append(QStringLiteral("--no-debug"));
    check(!exactNativeLaunch(other, image, other.arguments, 2048));

    // The historical protective-sleep helper is a separate exact two-word
    // profile. Do not suppress its positive or negative CTest coverage.
    other = valid;
    other.image = QStringLiteral("/usr/lib/linura/linura-executor-session");
    other.arguments = {other.image};
    other.arguments.append(QStringLiteral("--protect-before-sleep"));
    check(exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments[1] = QStringLiteral("--unknown");
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
    other.arguments[1] = QStringLiteral("--protect-before-sleep");
    other.image = QStringLiteral("/usr/lib/linura/linura-authorityd");
    check(!exactNativeLaunch(other, other.image, other.arguments, 2048));
}

void actualCompositorBinding()
{
    const auto nativeLock = identity();
    const NativeSessionFacts facts{nativeLock.boot,
                                   nativeLock.uid,
                                   nativeLock.session,
                                   nativeLock.createdMonotonicUs,
                                   QStringLiteral("wayland"),
                                   QStringLiteral("user"),
                                   QStringLiteral("active"),
                                   QStringLiteral("seat0"),
                                   true,
                                   false,
                                   2048};
    check(bindNativeSession(facts, nativeLock.uid, 2048, nativeLock.ownerInvocation) == nativeLock);
    check(!bindNativeSession(facts, 0, 2048, nativeLock.ownerInvocation));
    check(!bindNativeSession(facts, nativeLock.uid + 1, 2048, nativeLock.ownerInvocation));
    check(!bindNativeSession(facts, nativeLock.uid, 2049, nativeLock.ownerInvocation));
    check(!bindNativeSession(facts, nativeLock.uid, 0, nativeLock.ownerInvocation));
    std::vector<NativeSessionFacts> invalid;
    auto other = facts;
    other.type = QStringLiteral("tty");
    invalid.push_back(other);
    other = facts;
    other.sessionClass = QStringLiteral("greeter");
    invalid.push_back(other);
    other = facts;
    other.state = QStringLiteral("closing");
    invalid.push_back(other);
    other = facts;
    other.remote = true;
    invalid.push_back(other);
    other = facts;
    other.active = false;
    invalid.push_back(other);
    other = facts;
    other.seat.clear();
    invalid.push_back(other);
    other = facts;
    other.seat = QString(65, QLatin1Char('a'));
    invalid.push_back(other);
    other = facts;
    other.createdMonotonicUs = 0;
    invalid.push_back(other);
    for (const auto &substitution : invalid)
        check(!bindNativeSession(substitution, nativeLock.uid, 2048, nativeLock.ownerInvocation));
}

void nativeBoundaryTimeout()
{
    {
        NativeDeadline completed(std::chrono::milliseconds(1'000));
        // Destruction cancels/joins the timer promptly; it cannot outlive owner.
    }
    const auto exited = [](pid_t child) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        int status = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = waitpid(child, &status, WNOHANG);
            if (result == child)
                return status;
            check(result == 0);
            usleep(1'000);
        }
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        check(false); // Diagnostic backpressure must not stall the original exit.
        return status;
    };
    std::array<int, 2> journal{};
    check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, journal.data()) == 0);
    const pid_t child = fork();
    check(child >= 0);
    if (child == 0) {
        close(journal[0]);
        if (dup2(journal[1], STDERR_FILENO) != STDERR_FILENO)
            _exit(2);
        close(journal[1]);
        NativeDeadline stalled(std::chrono::milliseconds(100), NativeDeadline::Stage::WaylandPump);
        // Emulate a non-cancellable native authentication handshake. The native
        // deadline exits without any Qt/lock destructor, not a false success.
        usleep(500'000);
        _exit(0);
    }
    close(journal[1]);
    int status = exited(child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == NativeDeadline::NativeBoundaryTimeoutExit);
    std::array<char, 128> diagnostic{};
    const auto count = recv(journal[0], diagnostic.data(), diagnostic.size(), MSG_DONTWAIT);
    constexpr std::string_view expected = "native-owner-timeout stage=wayland-pump\n";
    check(count == static_cast<ssize_t>(expected.size()));
    check(std::string_view(diagnostic.data(), expected.size()) == expected);
    close(journal[0]);

    check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, journal.data()) == 0);
    const pid_t congested = fork();
    check(congested >= 0);
    if (congested == 0) {
        close(journal[0]);
        std::array<char, 4096> padding{};
        while (send(journal[1], padding.data(), padding.size(), MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {
        }
        if ((errno != EAGAIN && errno != EWOULDBLOCK) ||
            dup2(journal[1], STDERR_FILENO) != STDERR_FILENO)
            _exit(2);
        close(journal[1]);
        NativeDeadline stalled(std::chrono::milliseconds(100), NativeDeadline::Stage::WaylandPump);
        usleep(500'000);
        _exit(0);
    }
    close(journal[1]);
    status = exited(congested); // Intentionally do not drain the full journal socket.
    close(journal[0]);
    check(WIFEXITED(status) && WEXITSTATUS(status) == NativeDeadline::NativeBoundaryTimeoutExit);
    for (const bool closed : {false, true}) {
        std::array<int, 2> pipe{};
        check(pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK) == 0);
        const pid_t unavailable = fork();
        check(unavailable >= 0);
        if (unavailable == 0) {
            close(pipe[0]);
            if (dup2(pipe[1], STDERR_FILENO) != STDERR_FILENO)
                _exit(2);
            close(pipe[1]);
            if (closed)
                close(STDERR_FILENO);
            NativeDeadline stalled(std::chrono::milliseconds(100),
                                   NativeDeadline::Stage::WaylandPump);
            usleep(500'000);
            _exit(0);
        }
        close(pipe[1]);
        status = exited(unavailable);
        std::array<char, 128> output{};
        check(read(pipe[0], output.data(), output.size()) == 0);
        close(pipe[0]);
        check(WIFEXITED(status) &&
              WEXITSTATUS(status) == NativeDeadline::NativeBoundaryTimeoutExit);
    }
}

void suspendCannotExtendConfirmation()
{
    quint64 bootTime = 100;
    const auto reviewed = scope();
    NativeApproval approval(identity(), [&bootTime] { return bootTime; });
    check(approval.begin(reviewed, true));
    check(approval.nativePrompt(reviewed));
    check(approval.nativeCompleted(reviewed, true));
    // A simulated BOOTTIME advance across suspend expires proof even if normal
    // event-loop timers have not run. Real suspend remains native qualification.
    bootTime += 8 * 60 * 60 * 1'000;
    check(!approval.consume(reviewed));
    const auto nativeClock = NativeApproval::nativeBootTimeClock();
    const auto first = nativeClock();
    check(first < std::numeric_limits<quint64>::max() - NativeApproval::ConversationMs);
    check(nativeClock() >= first);
    NativeApproval nativeDefault(identity());
    check(nativeDefault.state() == NativeApproval::State::Idle);
}

void boundedCompositorReply()
{
    check(decodeNativeHyprlandLock("{\"locked\":true}") == NativeCompositorLockState::Locked);
    check(decodeNativeHyprlandLock(" \n{ \"locked\" : false }\r\t") ==
          NativeCompositorLockState::Unlocked);
    for (const QByteArray &invalid :
         {QByteArray(), QByteArray(65, ' '), QByteArrayLiteral("{}"),
          QByteArrayLiteral("{\"locked\":0}"), QByteArrayLiteral("{\"locked\":\"false\"}"),
          QByteArrayLiteral("{\"locked\":null}"), QByteArrayLiteral("{\"locked\":False}"),
          QByteArrayLiteral("{\"locked\":false,\"locked\":true}"),
          QByteArrayLiteral("{\"locked\":false,\"extra\":true}"),
          QByteArrayLiteral("{\"lo cked\":false}"), QByteArrayLiteral("{\"locked\":f alse}"),
          QByteArrayLiteral("{\"locked\":false}true"), QByteArrayLiteral("{\"locked\":false"),
          QByteArrayLiteral("[{\"locked\":false}]"), QByteArray("{\"locked\":false}\0", 17)})
        check(!decodeNativeHyprlandLock(invalid));
    const NativeSessionBinding binding{identity(), 2048};
    for (const QString &path :
         {QStringLiteral("/tmp/linura-component-missing.socket"),
          QStringLiteral("/run/user/1001/hypr/native/.socket.sock"),
          QStringLiteral("/run/user/1000/hypr/../.socket.sock"),
          QStringLiteral("/run/user/1000/hypr/a/b/.socket.sock"),
          QStringLiteral("/run/user/1000/hypr/") + QString(81, QLatin1Char('a')) +
              QStringLiteral("/.socket.sock"),
          QStringLiteral("/run/user/1000/hypr/linura-component-missing/.socket.sock")})
        check(!observeNativeHyprlandLock(path, binding));
    auto invalid = binding;
    invalid.compositorPid = 0;
    NativeCompositorProbeFailure failure = NativeCompositorProbeFailure::None;
    check(!observeNativeHyprlandLock(QStringLiteral("/run/user/1000/hypr/native/.socket.sock"),
                                     invalid, &failure));
    check(failure == NativeCompositorProbeFailure::Binding);
}

void rejectUnprotectedStartup()
{
    check(!ProcessGuardDetail::protectedExecDumpability(-1));
    check(ProcessGuardDetail::protectedExecDumpability(0));
    check(!ProcessGuardDetail::protectedExecDumpability(1));
    check(ProcessGuardDetail::protectedExecDumpability(2));
    check(!ProcessGuardDetail::protectedExecDumpability(3));
    check(protectNativeProcess(0) == ProcessProtection::WrongIdentity);
    if (getuid() == 0)
        return; // Root is never a supported security-owner identity.
    // This ordinary component executable is deliberately not installed with
    // capabilities. It cannot furnish positive secure-exec qualification.
    check(getauxval(AT_SECURE) == 0);
    check(protectNativeProcess(getuid()) == ProcessProtection::UnprotectedStartup);
    const pid_t child = fork();
    check(child >= 0);
    if (child == 0) {
        // A caller setting dumpable=0 after startup must remain rejected.
        if (prctl(PR_SET_DUMPABLE, 0) != 0)
            _exit(1);
        _exit(protectNativeProcess(getuid()) == ProcessProtection::UnprotectedStartup ? 0 : 1);
    }
    int status = 0;
    check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    try {
        scopeBounds();
        approvalNeverUnlocks();
        displayApprovalRequiresItsOwnPresentedPurposeAndOriginalDeadline();
        transitionApprovalIsPurposeBound();
        protectiveSettingApprovalIsPurposeBound();
        scopeSubstitution();
        approvalDenialsAndDeadlines();
        confirmationAndClockFailure();
        compositorTransitions();
        generationCommitFence();
        protectedStorage();
        protectedUtf8Storage();
        supervisedPeerBinding();
        supervisedLaunchBinding();
        actualCompositorBinding();
        nativeBoundaryTimeout();
        suspendCannotExtendConfirmation();
        boundedCompositorReply();
        rejectUnprotectedStartup();
        std::cout << "native mechanisms: " << checks << " checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        // Only our fixed, synthetic test error messages; no password contents.
        std::cerr << error.what() << " (check " << checks << ")\n";
        return 1;
    }
}
