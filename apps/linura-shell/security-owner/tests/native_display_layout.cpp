// Strict native adapter data/formatter fixtures only. No command is dispatched.
#include "native_display_layout.h"
#include <cassert>

using namespace Linura::SecurityOwner;
int main()
{
    const auto lock = NativeLockIdentity::parse(
        QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-"
                       "4222-8222-222222222222:1"));
    assert(lock);
    const QString scope = QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:"
                                         "1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3");
    NativeDisplaySnapshot observed;
    observed.generation = 3;
    NativeDisplayHead root;
    root.handle = 1;
    root.generation = 2;
    root.name = QStringLiteral("DP-1");
    root.enabled = true;
    root.modes = {{1920, 1080, 60000}, {1280, 720, 59940}};
    root.current = root.modes[0];
    root.scaleFixed = 256;
    observed.heads.push_back(root);
    const auto baseline = QStringLiteral("LNDL:1;") + scope +
                          QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:0:0:-;");
    const auto desired = QStringLiteral("LNDL:1;") + scope +
                         QStringLiteral(";1:2:enabled:1280:720:59940:1250:1:-100:20:-;");
    const auto text =
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + baseline + desired;
    const auto intent = NativeDisplayIntent::parse(text);
    assert(intent && intent->encode() == text && intent->nativeOptions(observed, scope, *lock));
    assert(intent->baseline.matchesGeometry(observed));
    assert(!intent->desired.matchesGeometry(observed));
    const auto commands = intent->desired.commands(observed);
    assert(commands.size() == 1 &&
           commands[0] == "/keyword monitor DP-1,1280x720@59.940,-100x20,1.250,transform,1");
    for (const auto &bad :
         {QString(text).replace(QStringLiteral("LNDI:1;"), QStringLiteral("LNDI:2;")),
          text + QLatin1Char('\n'), text + QStringLiteral("extra;"),
          QString(text).replace(QStringLiteral("1:2:enabled"), QStringLiteral("01:2:enabled")),
          QString(text).replace(QStringLiteral(":1250:"), QStringLiteral(":1251:")),
          QString(text).replace(QStringLiteral(":-100:"), QStringLiteral(":-0:")),
          QString(text).replace(QStringLiteral(":-100:"), QStringLiteral(":-65537:"))}) {
        assert(!NativeDisplayIntent::parse(bad));
    }
    auto replaced = observed;
    replaced.heads[0].generation++;
    assert(!intent->nativeOptions(replaced, scope, *lock));
    replaced = observed;
    replaced.heads[0].name = QStringLiteral("DP-1;keyword unsafe");
    assert(intent->desired.commands(replaced).empty());
    replaced = observed;
    replaced.heads[0].modes = {{1024, 768, 60000}};
    assert(intent->desired.commands(replaced).empty());
    assert(!intent->nativeOptions(observed, scope + QStringLiteral("0"), *lock));
    auto different = *lock;
    different.generation++;
    assert(!intent->nativeOptions(observed, scope, different));

    auto second = root;
    second.handle = 2;
    second.generation = 4;
    second.name = QStringLiteral("HDMI-A-1");
    observed.heads.push_back(second);
    observed.generation = 4;
    const auto twoBaseline =
        QString(baseline).append(QStringLiteral("2:4:enabled:1920:1080:60000:1000:0:1920:0:-;"));
    const auto mirrored =
        QString(baseline).append(QStringLiteral("2:4:enabled:1920:1080:60000:1000:0:0:0:1,2;"));
    const auto mirrorIntent = NativeDisplayIntent::parse(
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + twoBaseline + mirrored);
    assert(mirrorIntent && mirrorIntent->nativeOptions(observed, scope, *lock));
    const auto mirrorCommands = mirrorIntent->desired.commands(observed);
    assert(mirrorCommands.size() == 2 && mirrorCommands[1].endsWith(",mirror,DP-1"));
    auto repeated = mirrorIntent->desired;
    repeated.outputs[1] = repeated.outputs[0];
    assert(!repeated.nativeOptions(observed));
    assert(repeated.commands(observed).empty());
    auto ambiguous = observed;
    ambiguous.heads[1].name = ambiguous.heads[0].name;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.heads[1].handle = ambiguous.heads[0].handle;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.heads[1].generation = observed.generation + 1;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    ambiguous = observed;
    ambiguous.generation = 0;
    assert(mirrorIntent->desired.commands(ambiguous).empty());
    const auto cyclic = NativeDisplayIntent::parse(
        QString(mirrorIntent->encode())
            .replace(QStringLiteral("1:2:enabled:1920:1080:60000:1000:0:0:0:-;"),
                     QStringLiteral("1:2:enabled:1920:1080:60000:1000:0:0:0:2,4;")));
    assert(cyclic && !cyclic->nativeOptions(observed, scope, *lock));
    const auto disabled = QString(baseline).append(QStringLiteral("2:4:disabled;"));
    const auto disabledIntent = NativeDisplayIntent::parse(
        QStringLiteral("LNDI:1;") + lock->resource + QLatin1Char(';') + twoBaseline + disabled);
    assert(disabledIntent && disabledIntent->nativeOptions(observed, scope, *lock));
    assert(disabledIntent->desired.commands(observed).back() ==
           "/keyword monitor HDMI-A-1,disable");
}
