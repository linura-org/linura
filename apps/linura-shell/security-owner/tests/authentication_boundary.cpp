#include "authentication_agent.h"
#include "lock_mechanism.h"

#include <QGuiApplication>
#include <QKeyEvent>
#include <QMetaProperty>
#include <QUuid>

#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <gio/gio.h>

#include <iostream>
#include <stdexcept>

using namespace Linura::SecurityOwner;

namespace {

std::size_t checks = 0;
void check(bool condition)
{
    ++checks;
    if (!condition)
        throw std::runtime_error(
            "native authentication boundary assertion failed (no secret data)");
}

NativeLockIdentity identity()
{
    const auto value = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:1"));
    check(value.has_value());
    return *value;
}

NativeApprovalScope scope()
{
    return {identity(),
            QStringLiteral("unix:uid:1000"),
            QStringLiteral("request:v010:session-lock:auth-component"),
            QStringLiteral("request:v010:session-lock:auth-component"),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
            QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
            ApprovalPurpose::AuthenticateUnlock};
}

void unregisteredAgentCannotConfirm()
{
    SecretEntry entry;
    check(entry.storageAvailable());
    quint64 time = 100;
    AuthenticationAgent agent(identity(), [&time] { return time; }, &entry);
    check(!agent.registered());
    const auto reviewed = scope();
    check(!agent.arm(reviewed, true, {}));
    agent.confirmLock();
    check(!agent.consume(reviewed));
    check(!agent.confirmationPending() && !agent.authenticationPending());
    check(!entry.acceptsInput());
    for (const char *name : {"registered", "confirmationPending", "authenticationPending"}) {
        const int property = agent.metaObject()->indexOfProperty(name);
        check(property >= 0 && !agent.metaObject()->property(property).isWritable());
    }
    check(agent.metaObject()->indexOfMethod("nativeCompleted(bool)") == -1);
    check(agent.metaObject()->indexOfMethod("consume()") == -1);
    check(agent.metaObject()->indexOfMethod("advanceIdentity()") == -1);
    check(agent.metaObject()->indexOfMethod("armDisplay()") == -1);
    check(agent.metaObject()->indexOfMethod("bindDisplayPromptPresentation()") == -1);
    check(!agent.bindDisplayPromptPresentation({}));
    check(!agent.armDisplay(reviewed, {3, 7, NativeDisplayPromptStatus::Phase::Ready}, 1000, {}));
    agent.cancelInteraction();
    agent.ownerLost();
    check(!agent.registerNativeSession(0));
    check(!agent.arm(reviewed, true, {}));
    check(!agent.consume(reviewed));
}

void officialTaskReceivesDenialWithoutArmedScope()
{
    SecretEntry entry;
    AuthenticationAgent agent(identity(), &entry);
    struct Result final
    {
        bool delivered = false;
        bool authorized = true;
        bool cancelled = false;
    } result;
    GMainContext *context = g_main_context_new();
    g_main_context_push_thread_default(context);
    GCancellable *cancellable = g_cancellable_new();
    GTask *task = g_task_new(
        nullptr, cancellable,
        +[](GObject *, GAsyncResult *reply, gpointer data) {
            auto *outcome = static_cast<Result *>(data);
            GError *error = nullptr;
            outcome->authorized = g_task_propagate_boolean(G_TASK(reply), &error) != FALSE;
            outcome->cancelled =
                error && error->domain == POLKIT_ERROR && error->code == POLKIT_ERROR_CANCELLED;
            if (error)
                g_error_free(error); // No native diagnostics/credential payloads logged.
            outcome->delivered = true;
        },
        &result);
    agent.initiateNative(nullptr, "org.linura.authority.unlock-session", nullptr, nullptr, nullptr,
                         cancellable, task);
    // This exact official GTask is complete already; one nonblocking iteration
    // delivers it on the captured native context, with no daemon/helper mock.
    check(g_main_context_pending(context));
    (void)g_main_context_iteration(context, FALSE);
    check(result.delivered && !result.authorized && result.cancelled);
    check(!agent.authenticationPending() && !entry.acceptsInput());
    g_object_unref(task);
    g_object_unref(cancellable);
    g_main_context_pop_thread_default(context);
    g_main_context_unref(context);
}

void officialAgentDetailsBindNativeOriginNotInventedForwardedFields()
{
    PolkitDetails *details = polkit_details_new();
    check(!nativeAuthenticationOriginMatches(nullptr, 42, 51));
    check(!nativeAuthenticationOriginMatches(details, 42, 51));
    // Merely passing canonical-looking client details is never native origin.
    polkit_details_insert(details, "linura.request_id", "request:v010:session-lock:auth-component");
    check(!nativeAuthenticationOriginMatches(details, 42, 51));
    polkit_details_insert(details, "polkit.caller-pid", "42");
    polkit_details_insert(details, "polkit.subject-pid", "51");
    check(nativeAuthenticationOriginMatches(details, 42, 51));
    for (const char *wrong : {"", "0", "042", "43", "+42", "42 "}) {
        polkit_details_insert(details, "polkit.caller-pid", wrong);
        check(!nativeAuthenticationOriginMatches(details, 42, 51));
    }
    polkit_details_insert(details, "polkit.caller-pid", "42");
    polkit_details_insert(details, "polkit.subject-pid", "52");
    check(!nativeAuthenticationOriginMatches(details, 42, 51));
    check(!nativeAuthenticationOriginMatches(details, 0, 52));
    g_object_unref(details);
}

void multipleNativeAdministratorsRequireExplicitProtectedSelection()
{
    GList *identities = nullptr;
    for (const gint uid : {0, 1001, 1002})
        identities = g_list_append(identities, polkit_unix_user_new(uid));
    auto owner = scope();
    const auto own = nativeAuthenticationChoices(owner, identities);
    check(!own); // No alternate administrator may unlock the session owner.
    auto admin = owner;
    admin.purpose = ApprovalPurpose::AuthenticateSuspend;
    const auto choices = nativeAuthenticationChoices(admin, identities);
    check(choices && *choices == QVector<quint32>({0, 1001, 1002}));
    SecretEntry entry;
    check(entry.beginNativeIdentitySelection(*choices));
    check(entry.acceptsInput() && entry.maskedLength() == 0);
    check(entry.nativeAccessibleName().contains(QStringLiteral("UID 0")));
    quint32 chosen = 9999;
    int selections = 0;
    QObject::connect(&entry, &SecretEntry::identitySelected, &entry, [&](quint32 uid) {
        ++selections;
        chosen = uid;
        entry.cancelNativePrompt();
    });
    QKeyEvent next(QEvent::KeyPress, Qt::Key_Down, Qt::NoModifier);
    QGuiApplication::sendEvent(&entry, &next);
    check(entry.nativeAccessibleName().contains(QStringLiteral("UID 1001")));
    QKeyEvent confirm(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
    QGuiApplication::sendEvent(&entry, &confirm);
    check(selections == 1 && chosen == 1001 && !entry.acceptsInput());
    check(entry.maskedLength() == 0);
    g_list_free_full(identities, g_object_unref);

    GList *ownerOnly = g_list_append(nullptr, polkit_unix_user_new(1000));
    const auto ownerChoices = nativeAuthenticationChoices(owner, ownerOnly);
    check(ownerChoices && *ownerChoices == QVector<quint32>({1000}));
    const auto ownerAdminChoices = nativeAuthenticationChoices(admin, ownerOnly);
    check(ownerAdminChoices && *ownerAdminChoices == QVector<quint32>({1000}));
    g_list_free_full(ownerOnly, g_object_unref);

    GList *duplicate = nullptr;
    duplicate = g_list_append(duplicate, polkit_unix_user_new(0));
    duplicate = g_list_append(duplicate, polkit_unix_user_new(0));
    check(!nativeAuthenticationChoices(admin, duplicate));
    g_list_free_full(duplicate, g_object_unref);
    GList *oversized = nullptr;
    for (gint uid = 0; uid < 9; ++uid)
        oversized = g_list_append(oversized, polkit_unix_user_new(uid));
    check(!nativeAuthenticationChoices(admin, oversized));
    g_list_free_full(oversized, g_object_unref);
    check(!nativeAuthenticationChoices(admin, nullptr));
}

void wrongNativeIdentityAndCancellationNeverUnlock(ApprovalPurpose purpose)
{
    SecretEntry entry;
    quint64 time = 100;
    auto reviewed = scope();
    reviewed.purpose = purpose;
    if (purpose != ApprovalPurpose::AuthenticateUnlock)
        reviewed.request = reviewed.plan =
            QStringLiteral("request:v010:protective-lock-setting:auth-component");
    check(reviewed.valid() && reviewed.requiresSessionOwnerAuthentication());
    NativeApproval approval(identity(), [&time] { return time; });
    PolkitConversation conversation(approval);
    LockMechanism lock(identity());
    check(lock.dispatch(identity(), true));
    lock.compositorCoverage(true);
    check(approval.begin(reviewed, true));
    PolkitIdentity *wrongOwner = polkit_unix_user_new(1001);
    GCancellable *cancellable = g_cancellable_new();
    // Generated synthetic native correlation material, never recorded or logged.
    const QByteArray cookie = QUuid::createUuid().toByteArray(QUuid::WithoutBraces);
    check(!conversation.begin(reviewed, wrongOwner, cookie.constData(), cancellable, &entry));
    check(!conversation.active() && !entry.acceptsInput());
    check(!approval.consume(reviewed));
    g_object_unref(wrongOwner);
    PolkitIdentity *owner = polkit_unix_user_new(1000);
    g_cancellable_cancel(cancellable);
    check(!conversation.begin(reviewed, owner, cookie.constData(), cancellable, &entry));
    check(!conversation.active() && !entry.acceptsInput());
    conversation.ownerLost();
    check(approval.state() == NativeApproval::State::Faulted);
    check(!approval.consume(reviewed));
    check(lock.requestedSecure() && lock.secureCoverage());
    g_object_unref(owner);
    g_object_unref(cancellable);
}

} // namespace

int main(int argc, char **argv)
{
    QGuiApplication application(argc, argv);
    try {
        unregisteredAgentCannotConfirm();
        officialTaskReceivesDenialWithoutArmedScope();
        officialAgentDetailsBindNativeOriginNotInventedForwardedFields();
        multipleNativeAdministratorsRequireExplicitProtectedSelection();
        for (auto purpose :
             {ApprovalPurpose::AuthenticateUnlock, ApprovalPurpose::EnableProtectiveLock,
              ApprovalPurpose::RevokeProtectiveLock})
            wrongNativeIdentityAndCancellationNeverUnlock(purpose);
        std::cout << "official native authentication boundary: " << checks
                  << " component checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << " (check " << checks << ")\n";
        return 1;
    }
}
