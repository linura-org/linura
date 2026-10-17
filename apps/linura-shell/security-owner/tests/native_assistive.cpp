// Standard wire/metadata component checks, NOT native screen-reader evidence.
#include "native_assistive_model.h"
#include <QCoreApplication>
#include <cassert>
#include <cstring>

using namespace Linura::SecurityOwner;
namespace {
constexpr auto Accessible = "org.a11y.atspi.Accessible";
constexpr auto Application = "org.a11y.atspi.Application";
GVariant *owned(GVariant *value)
{
    assert(value);
    return g_variant_ref_sink(value);
}
void signature(GVariant *value, const char *expected)
{
    value = owned(value);
    assert(g_variant_is_of_type(value, G_VARIANT_TYPE(expected)));
    g_variant_unref(value);
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    NativeAssistiveProjection projection{
        QStringLiteral("Authenticate to unlock"),
        QStringLiteral("Protected keyboard response. Enter submits; Escape cancels."),
        QStringLiteral("Password (1) · UID 1000"),
        true,
        true,
        true};
    assert(projection.valid());
    for (int which = 0; which < 6; ++which) {
        auto invalid = projection;
        switch (which) {
        case 0:
            invalid.heading.clear();
            break;
        case 1:
            invalid.prompt += QChar::Null;
            break;
        case 2:
            invalid.description += QLatin1Char('\n');
            break;
        case 3:
            invalid.heading = QString(129, QLatin1Char('a'));
            break;
        case 4:
            invalid.visible = false;
            break;
        case 5:
            invalid.accepting = false;
            break;
        }
        assert(!invalid.valid());
    }
    assert(nativeAssistiveSocket(QStringLiteral("unix:path=/run/user/1000/at-spi/bus"), 1000) ==
           QStringLiteral("/run/user/1000/at-spi/bus"));
    assert(nativeAssistiveSocket(
               QStringLiteral(
                   "unix:path=/run/user/1000/at-spi/bus_0,guid=0123456789abcdef0123456789abcdef"),
               1000) == QStringLiteral("/run/user/1000/at-spi/bus_0"));
    for (const auto &address :
         {QStringLiteral("unix:abstract=/run/user/1000/at-spi/bus"),
          QStringLiteral("tcp:host=localhost,port=1234"),
          QStringLiteral("unix:path=/run/user/1001/at-spi/bus"),
          QStringLiteral("unix:path=/run/user/1000/at-spi/../bus"),
          QStringLiteral("unix:path=/run/user/1000/at-spi/%62us"),
          QStringLiteral("unix:path=/run/user/1000/at-spi/bus;unix:path=/tmp/other"),
          QStringLiteral("unix:path=/run/user/1000/at-spi/bus,guid=unknown"),
          QStringLiteral("unix:path=/run/user/1000/at-spi/bus_100")})
        assert(!nativeAssistiveSocket(address, 1000));
    assert(!nativeAssistiveSocket(QStringLiteral("unix:path=/run/user/0/at-spi/bus"), 0));

    NativeAssistiveModel model{projection, QByteArrayLiteral(":1.23"), QStringLiteral(":1.7"), 42};
    GError *error = nullptr;
    GDBusNodeInfo *schema = g_dbus_node_info_new_for_xml(nativeAssistiveIntrospection(), &error);
    assert(schema && !error && schema->interfaces[0] && schema->interfaces[1] &&
           !schema->interfaces[2]);
    for (int index = 0; index < 2; ++index) {
        auto *interface = schema->interfaces[index];
        for (int property = 0; interface->properties[property]; ++property) {
            auto *item = interface->properties[property];
            signature(model.property(0, interface->name, item->name), item->signature);
            if (item->flags & G_DBUS_PROPERTY_INFO_FLAGS_WRITABLE)
                assert(std::strcmp(interface->name, Application) == 0 &&
                       std::strcmp(item->name, "Id") == 0);
        }
        for (int method = 0; interface->methods[method]; ++method) {
            auto *item = interface->methods[method];
            GVariant *input =
                owned(std::strcmp(item->name, "GetChildAtIndex") == 0 ? g_variant_new("(i)", 0)
                      : std::strcmp(item->name, "GetLocale") == 0     ? g_variant_new("(u)", 0U)
                                                                      : g_variant_new("()"));
            GString *expected = g_string_new("(");
            for (int argument = 0; item->out_args && item->out_args[argument]; ++argument)
                g_string_append(expected, item->out_args[argument]->signature);
            g_string_append(expected, ")");
            signature(model.method(0, interface->name, item->name, input), expected->str);
            g_string_free(expected, TRUE);
            g_variant_unref(input);
        }
    }
    g_dbus_node_info_unref(schema);
    GVariant *empty = owned(g_variant_new("()"));
    for (int index : {-1, 3}) {
        assert(!model.property(index, Accessible, "Name"));
        assert(!model.method(index, Accessible, "GetRole", empty));
    }
    for (const char *interface :
         {"org.a11y.atspi.Text", "org.a11y.atspi.EditableText", "org.a11y.atspi.Value",
          "org.a11y.atspi.Action", "org.a11y.atspi.Component"}) {
        assert(!model.property(2, interface, "Value"));
        assert(!model.method(2, interface, "DoAction", empty));
    }
    assert(!model.property(2, Accessible, "Value"));
    assert(!model.method(2, Accessible, "SetTextContents", empty));
    assert(!model.method(1, Application, "GetApplicationBusAddress", empty));
    GVariant *wrong = owned(g_variant_new("(s)", "component malformed input"));
    assert(!model.method(0, Accessible, "GetChildAtIndex", wrong));
    assert(!model.method(0, Accessible, "GetRole", wrong));
    g_variant_unref(wrong);
    GVariant *interfaces = owned(model.method(2, Accessible, "GetInterfaces", empty));
    GVariant *names = g_variant_get_child_value(interfaces, 0);
    assert(g_variant_n_children(names) == 1);
    g_variant_unref(names);
    g_variant_unref(interfaces);
    for (bool active : {true, false}) {
        model.projection.accepting = model.projection.focused = active;
        GVariant *state = owned(model.method(2, Accessible, "GetState", empty));
        GVariant *words = g_variant_get_child_value(state, 0);
        gsize count = 0;
        const auto *flags =
            static_cast<const guint32 *>(g_variant_get_fixed_array(words, &count, sizeof(guint32)));
        assert(count == 2 && !(flags[0] & (1U << 7)) && flags[1] == 0);
        assert(bool(flags[0] & (1U << 12)) == active);
        assert(bool(flags[0] & (1U << 25)) == active);
        g_variant_unref(words);
        g_variant_unref(state);
    }
    model.projection.heading.clear();
    assert(!model.property(0, Accessible, "Name"));
    assert(!model.method(0, Accessible, "GetChildren", empty));
    g_variant_unref(empty);
    NativeAssistiveBridge invalidOwner(0);
    invalidOwner.publish(projection);
    assert(!invalidOwner.registered());
}
