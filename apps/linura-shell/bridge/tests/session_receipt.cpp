#include "session_receipt.h"

#include <QCoreApplication>
#include <iostream>
#include <functional>
#include <limits>

using Linura::ShellClient::SessionReceipt;
using Linura::ShellClient::validNativeSleepGateStatus;
using Linura::ShellClient::validSessionLockResource;
using Linura::ShellClient::validSessionReceipt;
using Linura::ShellClient::validSessionTransitionResource;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString epoch =
        QStringLiteral("session:epoch:12345678-1234-1234-1234-123456789abc:1000:c1:9");
    for (const auto &state : {"unobserved", "checking", "coverage-fenced", "denied"}) {
        if (!Linura::ShellClient::validNativeSleepGateStatus(epoch, QString::fromLatin1(state)))
            return 6;
    }
    for (const auto &state :
         {"", "secure", "sleeping", "allowed", "committed", "DENIED", "denied\n"}) {
        if (Linura::ShellClient::validNativeSleepGateStatus(epoch, QString::fromLatin1(state)))
            return 7;
    }
    for (const auto &bad :
         {QString(epoch).replace(":1000:", ":0:"), QString(epoch).replace(":1000:", ":01000:"),
          QString(epoch).replace(":9", ":0"), QString(epoch).replace(":c1:", ":../:"),
          epoch + QStringLiteral(":extra"),
          QStringLiteral("session:epoch:00000000-0000-0000-0000-000000000000:1000:c1:9"),
          QString(257, 'x')}) {
        if (Linura::ShellClient::validNativeSleepGateStatus(bad, QStringLiteral("denied")))
            return 8;
    }
    const QString suffix = QStringLiteral(
        "12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1");
    const QString lock = QStringLiteral("session:lock:") + suffix;
    // Mirror canonical SessionEpoch IDs without accepting ambient aliases.
    const QString deniedState = QStringLiteral("denied");
    const QString suspendAction = QStringLiteral("suspend");
    QStringList canonicalSessionIds;
    canonicalSessionIds.append(QStringLiteral("c_2"));
    canonicalSessionIds.append(QStringLiteral("c-2"));
    canonicalSessionIds.append(QStringLiteral("a_b-c"));
    canonicalSessionIds.append(QStringLiteral("_"));
    canonicalSessionIds.append(QStringLiteral("-"));
    canonicalSessionIds.append(QStringLiteral("A_Z-9"));
    canonicalSessionIds.append(QString(64, 's'));
    for (const auto &sessionId : canonicalSessionIds) {
        QString canonicalEpoch =
            QStringLiteral("session:epoch:12345678-1234-1234-1234-123456789abc:1000:");
        canonicalEpoch += sessionId;
        canonicalEpoch += QStringLiteral(":9");
        QString canonicalLock =
            QStringLiteral("session:lock:12345678-1234-1234-1234-123456789abc:1000:");
        canonicalLock += sessionId;
        canonicalLock += QStringLiteral(":9:12345678-1234-1234-1234-123456789abc:1");
        QString canonicalPower = QStringLiteral("session:transition:suspend:10:");
        canonicalPower += canonicalLock.mid(QStringLiteral("session:lock:").size());
        const bool validEpoch = validNativeSleepGateStatus(canonicalEpoch, deniedState);
        const bool validLock = validSessionLockResource(canonicalLock);
        const bool validPower = validSessionTransitionResource(canonicalPower, suspendAction);
        if (!validEpoch || !validLock || !validPower)
            return 12;
    }

    QStringList invalidSessionIds;
    invalidSessionIds.append(QStringLiteral("self"));
    invalidSessionIds.append(QStringLiteral("auto"));
    invalidSessionIds.append(QStringLiteral("current"));
    invalidSessionIds.append(QStringLiteral("c.2"));
    invalidSessionIds.append(QStringLiteral("c/2"));
    invalidSessionIds.append(QStringLiteral("c 2"));
    invalidSessionIds.append(QStringLiteral("c:2"));
    invalidSessionIds.append(QStringLiteral("é"));
    invalidSessionIds.append(QString(65, 's'));
    for (const auto &sessionId : invalidSessionIds) {
        QString badEpoch =
            QStringLiteral("session:epoch:12345678-1234-1234-1234-123456789abc:1000:");
        badEpoch += sessionId;
        badEpoch += QStringLiteral(":9");
        QString badLock = QStringLiteral("session:lock:12345678-1234-1234-1234-123456789abc:1000:");
        badLock += sessionId;
        badLock += QStringLiteral(":9:12345678-1234-1234-1234-123456789abc:1");
        QString badPower = QStringLiteral("session:transition:suspend:10:");
        badPower += badLock.mid(QStringLiteral("session:lock:").size());
        const bool validEpoch = validNativeSleepGateStatus(badEpoch, deniedState);
        const bool validLock = validSessionLockResource(badLock);
        const bool validPower = validSessionTransitionResource(badPower, suspendAction);
        if (validEpoch || validLock || validPower)
            return 13;
    }

    QString invalidSuspend = QStringLiteral("session:transition:suspend:18446744073709551615:");
    invalidSuspend += suffix;
    QString invalidSuspendBaseline = QStringLiteral("session:transition:suspend:010:");
    invalidSuspendBaseline += suffix;
    QString invalidLogout = QStringLiteral("session:transition:logout:1:");
    invalidLogout += suffix;
    QString invalidLogoutSuffix = QStringLiteral("session:transition:logout:0:");
    invalidLogoutSuffix += suffix;
    invalidLogoutSuffix += QLatin1Char(':');
    const QString invalidAmbient = QStringLiteral("session:transition:logout:0:current");
    if (validSessionTransitionResource(invalidSuspend, suspendAction))
        return 14;
    if (validSessionTransitionResource(invalidSuspendBaseline, suspendAction))
        return 14;
    if (validSessionTransitionResource(invalidLogout, suspendAction))
        return 14;
    if (validSessionTransitionResource(invalidLogoutSuffix, suspendAction))
        return 14;
    if (validSessionTransitionResource(invalidAmbient, suspendAction))
        return 14;
    QString invalidReboot = QStringLiteral("session:transition:reboot:00:");
    invalidReboot += suffix;
    QString invalidPowerOff = QStringLiteral("session:transition:power-off:0:");
    invalidPowerOff += suffix;
    invalidPowerOff += QLatin1Char(':');
    if (validSessionTransitionResource(invalidLogout, QStringLiteral("logout")) ||
        validSessionTransitionResource(invalidReboot, QStringLiteral("reboot")) ||
        validSessionTransitionResource(invalidPowerOff, QStringLiteral("power-off")))
        return 17;

    for (const auto &action : {"logout", "reboot", "power-off"}) {
        QString resource = QStringLiteral("session:transition:");
        resource += QString::fromLatin1(action);
        resource += QStringLiteral(":0:");
        resource += suffix;
        const bool expected = validSessionTransitionResource(resource, QString::fromLatin1(action));
        const bool substituted = validSessionTransitionResource(resource, suspendAction);
        if (!expected || substituted)
            return 15;
    }

    const QString rootEpoch =
        QStringLiteral("session:epoch:12345678-1234-1234-1234-123456789abc:0:c1:9");
    QString rootLock = QStringLiteral("session:lock:12345678-1234-1234-1234-123456789abc:0:c1:9:");
    rootLock += QStringLiteral("12345678-1234-1234-1234-123456789abc:1");
    QString rootTransition = QStringLiteral("session:transition:suspend:10:");
    rootTransition += rootLock.mid(QStringLiteral("session:lock:").size());
    const bool rootDiagnostic = validNativeSleepGateStatus(rootEpoch, QStringLiteral("unobserved"));
    const bool rootLockIdentity = validSessionLockResource(rootLock);
    const bool rootPower = validSessionTransitionResource(rootTransition, suspendAction);
    if (rootDiagnostic || !rootLockIdentity || rootPower)
        return 16;
    const QString settingRequest =
        QStringLiteral("request:v010:protective-lock-setting:shell-setting");
    const Linura::ShellClient::ProtectiveLockSettingReceipt setting = {
        settingRequest,
        lock,
        true,
        QStringLiteral("intent:s17:protective-lock:") + QString(64, 'a'),
        QStringLiteral("policy:protective-lock:v1:") + QString(64, 'b'),
        42,
        true};
    if (!Linura::ShellClient::validProtectiveLockSettingReceipt(setting, settingRequest, lock,
                                                                true))
        return 9;
    for (const auto &mutate : std::initializer_list<
             std::function<void(Linura::ShellClient::ProtectiveLockSettingReceipt &)>>{
             [](auto &r) { r.request += "-substituted"; },
             [](auto &r) { r.resource += ":extra"; },
             [](auto &r) { r.enabled = false; },
             [](auto &r) { r.intent = "intent:other"; },
             [](auto &r) { r.revision = "policy:other"; },
             [](auto &r) { r.confirmedAt = 0; },
             [](auto &r) { r.confirmedAt = quint64(std::numeric_limits<qint64>::max()) + 1; },
             [](auto &r) { r.intent = "intent:s17:protective-lock:" + QString(64, '0'); },
             [](auto &r) { r.revision = "policy:protective-lock:v1:" + QString(64, 'Z'); },
         }) {
        auto bad = setting;
        mutate(bad);
        if (Linura::ShellClient::validProtectiveLockSettingReceipt(bad, settingRequest, lock, true))
            return 10;
    }
    auto historicalSetting = setting;
    historicalSetting.latest = false;
    if (!Linura::ShellClient::validProtectiveLockSettingReceipt(historicalSetting, settingRequest,
                                                                lock, true))
        return 11;
    const QString power = QStringLiteral("session:transition:suspend:10:") + suffix;
    for (const bool transition : {false, true}) {
        const QString request = (transition ? QStringLiteral("request:v010:session-transition:")
                                            : QStringLiteral("request:v010:session-lock:")) +
                                "shell-test";
        const QString resource = transition ? power : lock;
        const SessionReceipt sample = {"transaction:v1:" + QString(64, 'a'),
                                       request,
                                       resource,
                                       "true",
                                       QString(64, 'b'),
                                       QString(64, 'c'),
                                       "dispatched",
                                       "satisfied",
                                       "committed",
                                       false,
                                       {"request-intent", "observe", "plan", "validate",
                                        "authorize", "prepare", "execute", "verify", "commit",
                                        "audit", "reconcile"}};
        if (!validSessionReceipt(sample, request, resource, transition))
            return 1;
        for (const auto &mutate : std::initializer_list<std::function<void(SessionReceipt &)>>{
                 [](auto &r) { r.transaction = "transaction:v1:bad"; },
                 [](auto &r) { r.request += "-substituted"; },
                 [=](auto &r) { r.resource = transition ? lock : power; },
                 [](auto &r) { r.resource += "\n"; },
                 [](auto &r) { r.desired = "false"; },
                 [](auto &r) { r.effect = "sha256:" + r.effect; },
                 [](auto &r) { r.dispatch = "bad"; },
                 [](auto &r) { r.dispatch.clear(); },
                 [](auto &r) { r.disposition = "applied"; },
                 [](auto &r) { r.verification = "inconclusive"; },
                 [](auto &r) { r.state = "indeterminate"; },
                 [](auto &r) { r.stages.removeLast(); },
                 [](auto &r) { r.stages.swapItemsAt(0, 1); },
             }) {
            auto bad = sample;
            mutate(bad);
            if (validSessionReceipt(bad, request, resource, transition))
                return 2;
        }
        auto recovered = sample;
        recovered.recovered = true;
        recovered.dispatch.clear();
        recovered.disposition.clear();
        if (!validSessionReceipt(recovered, request, {}, transition))
            return 3;
        recovered.recovered = false;
        if (validSessionReceipt(recovered, request, {}, transition))
            return 4;
        for (const auto &badSuffix : {
                 QString(suffix).replace(":1000:", ":4294967296:"),
                 QString(suffix).replace(":1000:", ":01000:"),
                 QString(suffix).replace(":c1:", ":../:"),
                 QString(suffix).replace(":9:", ":18446744073709551616:"),
                 QString(suffix).replace("12345678-1234-1234-1234-123456789abc",
                                         "00000000-0000-0000-0000-000000000000"),
             }) {
            auto bad = sample;
            bad.resource = (transition ? QStringLiteral("session:transition:suspend:10:")
                                       : QStringLiteral("session:lock:")) +
                           badSuffix;
            if (validSessionReceipt(bad, request, {}, transition))
                return 5;
        }
    }
    std::cout << "session client completion and negative receipt checks passed; not native "
                 "qualification\n";
}
