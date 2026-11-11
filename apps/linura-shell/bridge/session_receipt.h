#pragma once

#include <QString>
#include <QStringList>

namespace Linura::ShellClient {
// Public Authority1 wire value, not policy or execution authority.
struct SessionReceipt
{
    QString transaction;
    QString request;
    QString resource;
    QString desired;
    QString effect;
    QString dispatch;
    QString disposition;
    QString verification;
    QString state;
    bool recovered = false;
    QStringList stages;
};

[[nodiscard]] bool validSessionReceipt(const SessionReceipt &receipt, const QString &request,
                                       const QString &resource, bool transition);
[[nodiscard]] bool validNativeSleepGateStatus(const QString &epoch, const QString &state);
[[nodiscard]] bool validNativeIdleStatus(const QString &epoch, const QString &seat, bool idle,
                                         quint64 changedMonotonicUs);

// Retained owner-consent history only; never current protection or an effect.
struct ProtectiveLockSettingReceipt
{
    QString request;
    QString resource;
    bool enabled = false;
    QString intent;
    QString revision;
    quint64 confirmedAt = 0;
    bool latest = false;
};

[[nodiscard]] bool validSessionLockResource(const QString &resource);
[[nodiscard]] bool validSessionTransitionResource(const QString &resource, const QString &action);
[[nodiscard]] bool validProtectiveLockSettingReceipt(const ProtectiveLockSettingReceipt &receipt,
                                                     const QString &request,
                                                     const QString &resource, bool enabled);
} // namespace Linura::ShellClient
