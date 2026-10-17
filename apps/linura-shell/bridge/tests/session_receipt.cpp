#include "session_receipt.h"

#include <QCoreApplication>
#include <iostream>
#include <functional>
#include <limits>

using Linura::ShellClient::SessionReceipt;
using Linura::ShellClient::validSessionReceipt;

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
