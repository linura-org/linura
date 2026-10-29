#include "native_display_flow.h"
#include "native_wayland_lock.h"
#include "native_presentation.h"
#include "authentication_agent.h"

#include <QCryptographicHash>
#include <QThread>
#include <QtEndian>
#include <algorithm>

namespace Linura::SecurityOwner {
namespace {
QString transaction(const NativeApprovalScope &scope)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    for (const auto &value :
         {QStringLiteral("linura.transaction.id.v1"), scope.principal, scope.request}) {
        const auto bytes = value.toUtf8();
        const auto size = qToBigEndian(static_cast<quint64>(bytes.size()));
        hash.addData(QByteArrayView(reinterpret_cast<const char *>(&size), sizeof(size)));
        hash.addData(bytes);
    }
    return QStringLiteral("transaction:v1:") + QString::fromLatin1(hash.result().toHex());
}
} // namespace

std::unique_ptr<NativeDisplayFlow>
NativeDisplayFlow::create(NativeApprovalScope scope, NativeWaylandLock &backend,
                          NativePresentation &presentation, AuthenticationAgent &authentication,
                          NativePeerIdentity control, Revalidate revalidate)
{
    if (backend.thread() != QThread::currentThread() ||
        presentation.thread() != QThread::currentThread() ||
        authentication.thread() != QThread::currentThread() ||
        scope.purpose != ApprovalPurpose::ApplyDisplay || !scope.valid() || !revalidate ||
        !revalidate() || !backend.available() || !presentation.ready() ||
        !authentication.registered())
        return {};
    const auto intent = NativeDisplayIntent::parse(scope.display->material);
    const auto snapshot = backend.observeDisplayTopology();
    const auto clock = NativeDisplayClock::sample();
    if (!intent || !snapshot || !clock || scope.display->deadlineUnixMs <= clock->unixMs ||
        scope.display->deadlineBootMs <= clock->bootMs ||
        scope.display->deadlineUnixMs - clock->unixMs > 60'000 ||
        scope.display->deadlineBootMs - clock->bootMs > 60'000)
        return {};
    const auto pages = nativeDisplayReviewPages(scope, *snapshot);
    if (!pages || pages->empty())
        return {};
    auto flow = std::unique_ptr<NativeDisplayFlow>(
        new NativeDisplayFlow(std::move(scope), *intent, *snapshot, backend, presentation,
                              authentication, std::move(control), std::move(revalidate)));
    flow->last_ = *clock;
    flow->deadlineBoot_ = flow->scope_.display->deadlineBootMs;
    flow->pageCount_ = pages->size();
    if (!flow->refreshPresentation() ||
        !backend.showProtectedDisplay(flow->prompt_, flow->intent_)) {
        flow->cancel();
        return {};
    }
    flow->ownsPresentation_ = true;
    flow->timer_.start();
    return flow;
}

NativeDisplayFlow::NativeDisplayFlow(NativeApprovalScope scope, NativeDisplayIntent intent,
                                     NativeDisplaySnapshot snapshot, NativeWaylandLock &backend,
                                     NativePresentation &presentation,
                                     AuthenticationAgent &authentication,
                                     NativePeerIdentity control, Revalidate revalidate)
    : scope_(std::move(scope)), intent_(std::move(intent)), snapshot_(std::move(snapshot)),
      prompt_{scope_.protectedDisplayDigest(), NativeDisplayPromptScope::Purpose::Apply,
              scope_.display->deadlineUnixMs},
      backend_(backend), presentation_(presentation), authentication_(authentication),
      revalidate_(std::move(revalidate)), control_(std::move(control))
{
    timer_.setInterval(50);
    connect(&timer_, &QTimer::timeout, this, &NativeDisplayFlow::pulse);
    connect(&authentication_, &AuthenticationAgent::scopeRetired, this,
            [this](const NativeApprovalScope &retired) {
                if (matches(retired))
                    cancel();
            });
    connect(&authentication_, &AuthenticationAgent::confirmationAvailable, this, [this] {
        if (!failed_ && authenticationArmed_ && !consumed_ && !pending_)
            proofGeneration_ = backend_.protectedInteractionGeneration();
    });
}
NativeDisplayFlow::~NativeDisplayFlow()
{
    cancel();
}
bool NativeDisplayFlow::matches(const NativeApprovalScope &scope) const
{
    return scope_ == scope;
}
bool NativeDisplayFlow::fenced() const noexcept
{
    return !failed_;
}
void NativeDisplayFlow::revalidateOrigin()
{
    if (!failed_ && (!window() || !revalidate_()))
        cancel();
}
bool NativeDisplayFlow::window()
{
    const auto now = NativeDisplayClock::sample();
    if (failed_ || !now || now->unixMs < last_.unixMs || now->bootMs < last_.bootMs ||
        now->unixMs >= scope_.display->deadlineUnixMs || now->bootMs >= deadlineBoot_)
        return false;
    last_ = *now;
    return true;
}
bool NativeDisplayFlow::refreshPresentation()
{
    return presentation_.presentDisplayReview(scope_, snapshot_, page_, authenticateSelected_);
}

void NativeDisplayFlow::pulse()
{
    if (!window()) {
        cancel();
        return;
    }
    const auto status = backend_.protectedDisplayStatus();
    if (!status) {
        cancel();
        return;
    }
    if (consumed_) {
        if (status->phase != NativeDisplayPromptStatus::Phase::Consumed || status->epoch != epoch_)
            cancel();
        return;
    }
    if (status->phase != NativeDisplayPromptStatus::Phase::Ready)
        return;
    if (awaitingRevision_) {
        epoch_ = status->epoch;
        awaitingRevision_ = false;
    } else if (epoch_ != status->epoch) {
        cancel();
        return;
    }
    if (!backend_.protectedInputFocused()) {
        cancel();
        return;
    }
    if (pending_) {
        auto pending = std::move(*pending_);
        pending_.reset();
        const bool valid = revalidate_() && window();
        const auto fresh = valid ? backend_.protectedDisplayStatus() : std::nullopt;
        const bool current =
            fresh && fresh->phase == NativeDisplayPromptStatus::Phase::Ready &&
            fresh->epoch == epoch_ && backend_.protectedInputFocused() && window() &&
            presentation_.protectedEntry().preparedNativePromptMatches(pending.token);
        pending.completed(current);
        if (!current)
            cancel();
        return;
    }
    if (!authenticateSelected_ && !reviewArmed_) {
        reviewArmed_ = true;
        const auto page = page_;
        const auto epoch = epoch_;
        QPointer<NativeDisplayFlow> live(this);
        if (!backend_.armProtectedDisplayReview(prompt_, epoch, [live, page, epoch](bool accepted) {
                if (live)
                    live->reviewed(page, epoch, accepted);
            }))
            cancel();
    } else if (authenticateSelected_ && !authenticationArmed_) {
        if (!revalidate_() || !window()) {
            cancel();
            return;
        }
        const auto current = backend_.protectedDisplayStatus();
        if (!current || current->phase != NativeDisplayPromptStatus::Phase::Ready ||
            current->epoch != status->epoch || !backend_.protectedInputFocused() || !window()) {
            cancel();
            return;
        }
        const auto remaining =
            std::min(scope_.display->deadlineUnixMs - last_.unixMs, deadlineBoot_ - last_.bootMs);
        if (!authentication_.armDisplay(scope_, *current, remaining, control_))
            cancel();
        else if (!failed_)
            authenticationArmed_ = true;
    }
}

void NativeDisplayFlow::reviewed(std::size_t page, quint64 epoch, bool accepted)
{
    if (failed_ || consumed_ || !reviewArmed_ || page != page_ || epoch != epoch_)
        return;
    reviewArmed_ = false;
    if (!accepted || !revalidate_() || !window()) {
        cancel();
        return;
    }
    if (page_ + 1 == pageCount_)
        authenticateSelected_ = true;
    else
        ++page_;
    awaitingRevision_ = true;
    if (!refreshPresentation() || !backend_.refreshProtectedDisplay(prompt_, epoch))
        cancel();
}

bool NativeDisplayFlow::readyForPolkit(const NativeApprovalScope &scope)
{
    if (!matches(scope) || !revalidate_() || !window())
        return false;
    pulse();
    return !failed_ && authenticateSelected_ && authenticationArmed_ && !consumed_;
}
void NativeDisplayFlow::presentPrompt(const NativeApprovalScope &scope, quint64 token,
                                      Presented completed)
{
    QTimer::singleShot(0, this, [this, scope, token, completed = std::move(completed)] {
        if (!completed) {
            cancel();
            return;
        }
        const auto status = backend_.protectedDisplayStatus();
        if (!matches(scope) || !authenticationArmed_ || consumed_ || pending_ || !window() ||
            !revalidate_() || !status || status->phase != NativeDisplayPromptStatus::Phase::Ready ||
            !presentation_.protectedEntry().preparedNativePromptMatches(token)) {
            completed(false);
            cancel();
            return;
        }
        pending_ = Pending{token, completed};
        awaitingRevision_ = true;
        if (!refreshPresentation() || !backend_.refreshProtectedDisplay(prompt_, status->epoch))
            cancel();
    });
}
bool NativeDisplayFlow::consume(const NativeApprovalScope &scope)
{
    if (!matches(scope) || consumed_ || pending_ || proofGeneration_ == 0 || !revalidate_() ||
        !window())
        return false;
    const auto status = backend_.protectedDisplayStatus();
    if (!status || status->phase != NativeDisplayPromptStatus::Phase::Ready ||
        status->epoch != epoch_ || proofGeneration_ != backend_.protectedInteractionGeneration() ||
        !authentication_.consume(scope_) ||
        !backend_.consumeProtectedDisplay(prompt_, status->epoch)) {
        cancel();
        return false;
    }
    consumed_ = true;
    epoch_ = status->epoch;
    inputGeneration_ = backend_.protectedInputGeneration();
    return true;
}
bool NativeDisplayFlow::redeem(const NativeDisplayIntent &intent,
                               const NativeDisplayCorrelation &correlation)
{
    if (!consumed_ || spent_ || !window() || !revalidate_() || !correlation.valid() ||
        intent.encode() != scope_.display->material ||
        correlation.transaction != transaction(scope_))
        return false;
    const auto status = backend_.protectedDisplayStatus();
    if (!status || status->phase != NativeDisplayPromptStatus::Phase::Consumed || !window() ||
        status->epoch != epoch_ || inputGeneration_ != backend_.protectedInputGeneration() ||
        proofGeneration_ != backend_.protectedInteractionGeneration())
        return false;
    spent_ = true;
    return true;
}
void NativeDisplayFlow::cancel()
{
    if (failed_)
        return;
    failed_ = true;
    timer_.stop();
    auto pending = std::move(pending_);
    pending_.reset();
    if (ownsPresentation_)
        backend_.cancelProtectedDisplay();
    authentication_.cancelScopedInteraction(scope_);
    if (pending && pending->completed)
        pending->completed(false);
    Q_EMIT closed();
}
} // namespace Linura::SecurityOwner
