#include "session_receipt.h"

#include <QRegularExpression>
#include <limits>

namespace Linura::ShellClient {
namespace {
bool digest(const QString &value)
{
    static const QRegularExpression expression(QStringLiteral("^[0-9a-f]{64}$"));
    return expression.match(value).hasMatch();
}

bool resourceShape(const QString &value, bool transition, bool epoch = false)
{
    if (value.size() > 256)
        return false;
    // Presentation-side contract validation only. The authority independently
    // parses exact IDs and authenticates owner identity; regex is no authority.
    const auto fields = value.split(QLatin1Char(':'));
    if (fields.size() != (epoch        ? 6
                          : transition ? 10
                                       : 8) ||
        fields[0] != QStringLiteral("session") ||
        fields[1] != (epoch        ? QStringLiteral("epoch")
                      : transition ? QStringLiteral("transition")
                                   : QStringLiteral("lock")))
        return false;
    const auto number = [](const QString &text, quint64 minimum, quint64 maximum) {
        static const QRegularExpression digits(QStringLiteral("^(?:0|[1-9][0-9]{0,19})$"));
        bool ok = false;
        const quint64 parsed = text.toULongLong(&ok, 10);
        return digits.match(text).hasMatch() && ok && parsed >= minimum && parsed <= maximum;
    };
    if (transition) {
        if (fields[2] == QStringLiteral("suspend")) {
            if (!number(fields[3], 0, std::numeric_limits<quint64>::max() - 1))
                return false;
        } else if ((fields[2] != QStringLiteral("logout") &&
                    fields[2] != QStringLiteral("reboot") &&
                    fields[2] != QStringLiteral("power-off")) ||
                   fields[3] != QStringLiteral("0"))
            return false;
    }
    const int offset = transition ? 4 : 2;
    static const QRegularExpression uuid(
        QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));
    static const QRegularExpression session(QStringLiteral("^[A-Za-z0-9_-]{1,64}$"));
    const auto validUuid = [&](const QString &text) {
        return uuid.match(text).hasMatch() &&
               text != QStringLiteral("00000000-0000-0000-0000-000000000000");
    };
    return validUuid(fields[offset]) &&
           number(fields[offset + 1], transition ? 1 : 0, std::numeric_limits<quint32>::max()) &&
           session.match(fields[offset + 2]).hasMatch() &&
           fields[offset + 2] != QStringLiteral("self") &&
           fields[offset + 2] != QStringLiteral("auto") &&
           fields[offset + 2] != QStringLiteral("current") &&
           number(fields[offset + 3], 1, std::numeric_limits<quint64>::max()) &&
           (epoch || (validUuid(fields[offset + 4]) &&
                      number(fields[offset + 5], 1, std::numeric_limits<quint64>::max())));
}
} // namespace

bool validNativeSleepGateStatus(const QString &epoch, const QString &state)
{
    return resourceShape(epoch, false, true) &&
           epoch.split(QLatin1Char(':')).at(3) != QStringLiteral("0") &&
           (state == QStringLiteral("unobserved") || state == QStringLiteral("checking") ||
            state == QStringLiteral("coverage-fenced") || state == QStringLiteral("denied"));
}

bool validSessionReceipt(const SessionReceipt &r, const QString &request, const QString &resource,
                         bool transition)
{
    const auto prefix = transition ? QStringLiteral("request:v010:session-transition:")
                                   : QStringLiteral("request:v010:session-lock:");
    static const QRegularExpression slug(QStringLiteral("^[a-z0-9]+(?:-[a-z0-9]+)*$"));
    const auto operation = request.mid(prefix.size());
    const QStringList stages = {"request-intent", "observe", "plan",     "validate",
                                "authorize",      "prepare", "execute",  "verify",
                                "commit",         "audit",   "reconcile"};
    return request.startsWith(prefix) && operation.size() <= 64 &&
           slug.match(operation).hasMatch() && r.request == request &&
           r.transaction.startsWith(QStringLiteral("transaction:v1:")) &&
           digest(r.transaction.mid(15)) && resourceShape(r.resource, transition) &&
           (resource.isEmpty() || r.resource == resource) && r.desired == QStringLiteral("true") &&
           digest(r.effect) && (r.dispatch.isEmpty() || digest(r.dispatch)) &&
           (r.dispatch.isEmpty() == r.disposition.isEmpty()) &&
           (r.disposition.isEmpty() || r.disposition == QStringLiteral("dispatched") ||
            r.disposition == QStringLiteral("indeterminate")) &&
           (r.recovered || !r.disposition.isEmpty()) &&
           r.verification == QStringLiteral("satisfied") &&
           r.state == QStringLiteral("committed") && r.stages == stages;
}

bool validSessionLockResource(const QString &resource)
{
    return resourceShape(resource, false);
}

bool validSessionTransitionResource(const QString &resource, const QString &action)
{
    return resourceShape(resource, true) &&
           resource.startsWith(QStringLiteral("session:transition:") + action + QLatin1Char(':'));
}

bool validProtectiveLockSettingReceipt(const ProtectiveLockSettingReceipt &r,
                                       const QString &request, const QString &resource,
                                       bool enabled)
{
    const auto prefix = QStringLiteral("request:v010:protective-lock-setting:");
    const auto operation = request.mid(prefix.size());
    static const QRegularExpression slug(QStringLiteral("^[a-z0-9]+(?:-[a-z0-9]+)*$"));
    const auto lineage = [](const QString &value, const QString &prefix) {
        const auto suffix = value.mid(prefix.size());
        return value.startsWith(prefix) && digest(suffix) && suffix != QString(64, '0');
    };
    return request.startsWith(prefix) && operation.size() <= 64 &&
           slug.match(operation).hasMatch() && r.request == request &&
           validSessionLockResource(resource) && r.resource == resource && r.enabled == enabled &&
           lineage(r.intent, QStringLiteral("intent:s17:protective-lock:")) &&
           lineage(r.revision, QStringLiteral("policy:protective-lock:v1:")) && r.confirmedAt > 0 &&
           r.confirmedAt <= quint64(std::numeric_limits<qint64>::max());
}
} // namespace Linura::ShellClient
