#pragma once

// Private, pure AT-SPI wire model. No connection, input or authority handle.
#include "native_assistive.h"
#include <QByteArray>
#include <gio/gio.h>
#include <cstring>

namespace Linura::SecurityOwner {
class NativeAssistiveModel final
{
  public:
    NativeAssistiveProjection projection;
    QByteArray connectionName;
    QString parentName;
    int applicationId = 0;

    const char *name() const
    {
        return connectionName.constData();
    }
    GVariant *reference(const char *path) const
    {
        return g_variant_new("(so)", name(), path);
    }
    static int node(const char *path)
    {
        return equal(path, Root) ? 0 : equal(path, Frame) ? 1 : equal(path, Input) ? 2 : -1;
    }
    GVariant *property(int index, const char *interface, const char *key)
    {
        if (index < 0 || index > 2 || !interface || !key || !projection.valid())
            return nullptr;
        const auto &value = projection;
        if (equal(interface, Application)) {
            if (index != 0)
                return nullptr;
            if (equal(key, "Id"))
                return g_variant_new_int32(applicationId);
            if (equal(key, "InterfaceVersion"))
                return g_variant_new_uint32(1);
            if (equal(key, "AtspiVersion"))
                return g_variant_new_string("2.1");
            if (equal(key, "ToolkitName"))
                return g_variant_new_string("Linura protected presentation");
            if (equal(key, "Version") || equal(key, "ToolkitVersion"))
                return g_variant_new_string(QT_VERSION_STR);
            return nullptr;
        }
        if (!equal(interface, Accessible) || index < 0)
            return nullptr;
        if (equal(key, "version"))
            return g_variant_new_uint32(1);
        if (equal(key, "Name"))
            return g_variant_new_string(
                index == 0 ? "Linura protected session"
                           : (index == 1 ? value.heading : value.prompt).toUtf8().constData());
        if (equal(key, "Description") || equal(key, "HelpText"))
            return g_variant_new_string(value.description.toUtf8().constData());
        if (equal(key, "AccessibleId"))
            return g_variant_new_string(index == 0   ? "linura-security-owner"
                                        : index == 1 ? "protected-session"
                                                     : "protected-response");
        if (equal(key, "Locale"))
            return g_variant_new_string("C.UTF-8");
        if (equal(key, "ChildCount"))
            return g_variant_new_int32(index == 0 ? 1 : index == 1 && value.accepting ? 1 : 0);
        if (equal(key, "Parent"))
            return index == 0 ? g_variant_new("(so)", parentName.toUtf8().constData(),
                                              parentName.isEmpty() ? Null : Root)
                              : reference(index == 1 ? Root : Frame);
        return nullptr;
    }
    GVariant *method(int index, const char *interface, const char *member, GVariant *arguments)
    {
        if (index < 0 || index > 2 || !interface || !member || !arguments || !projection.valid() ||
            g_variant_get_size(arguments) > 128)
            return nullptr;
        const char *signature = equal(interface, Application) && equal(member, "GetLocale") ? "(u)"
                                : equal(interface, Accessible) && equal(member, "GetChildAtIndex")
                                    ? "(i)"
                                    : "()";
        if (!g_variant_is_of_type(arguments, G_VARIANT_TYPE(signature)))
            return nullptr;
        if (equal(interface, Application) && index == 0) {
            if (equal(member, "GetLocale"))
                return g_variant_new("(s)", "C.UTF-8");
            if (equal(member, "GetApplicationBusAddress"))
                return g_variant_new("(s)", ""); // No peer/direct route.
            return nullptr;
        }
        if (!equal(interface, Accessible))
            return nullptr;
        const auto &value = projection;
        const char *child = index == 0 ? Frame : index == 1 && value.accepting ? Input : nullptr;
        if (equal(member, "GetChildAtIndex")) {
            gint childIndex = -1;
            g_variant_get(arguments, "(i)", &childIndex);
            return child && childIndex == 0 ? g_variant_new("(@(so))", reference(child)) : nullptr;
        }
        if (equal(member, "GetChildren")) {
            GVariantBuilder children;
            g_variant_builder_init(&children, G_VARIANT_TYPE("a(so)"));
            if (child)
                g_variant_builder_add(&children, "(so)", name(), child);
            return g_variant_new("(a(so))", &children);
        }
        if (equal(member, "GetApplication"))
            return g_variant_new("(@(so))", reference(Root));
        if (equal(member, "GetIndexInParent"))
            return g_variant_new("(i)", index == 0 ? -1 : 0);
        if (equal(member, "GetRole"))
            return g_variant_new("(u)", index == 0 ? 75U : index == 1 ? 16U : 40U);
        if (equal(member, "GetRoleName") || equal(member, "GetLocalizedRoleName"))
            return g_variant_new("(s)", index == 0   ? "application"
                                        : index == 1 ? "dialog"
                                                     : "password text");
        if (equal(member, "GetRelationSet"))
            return g_variant_new("(@a(ua(so)))",
                                 g_variant_new_array(G_VARIANT_TYPE("(ua(so))"), nullptr, 0));
        if (equal(member, "GetAttributes"))
            return g_variant_new("(@a{ss})",
                                 g_variant_new_array(G_VARIANT_TYPE("{ss}"), nullptr, 0));
        if (equal(member, "GetInterfaces")) {
            const char *interfaces[] = {Accessible, index == 0 ? Application : nullptr, nullptr};
            return g_variant_new("(^as)", interfaces);
        }
        if (equal(member, "GetState")) {
            // Published AT-SPI bit positions. No editable/selection/value state.
            guint32 flags =
                value.visible && (index != 2 || value.accepting) ? (1U << 25) | (1U << 30) : 0;
            if (index != 2 || value.accepting)
                flags |= (1U << 8) | (1U << 24);
            if (index == 1 && value.visible)
                flags |= (1U << 1) | (1U << 16);
            if (index == 2) {
                flags |= (1U << 11) | (1U << 26);
                if (value.focused && value.accepting)
                    flags |= (1U << 12);
            }
            const guint32 states[] = {flags, 0};
            return g_variant_new("(@au)", g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32, states,
                                                                    2, sizeof(guint32)));
        }
        return nullptr;
    }

  private:
    static bool equal(const char *left, const char *right)
    {
        return std::strcmp(left, right) == 0;
    }
    static constexpr auto Root = "/org/a11y/atspi/accessible/root";
    static constexpr auto Frame = "/org/a11y/atspi/accessible/session";
    static constexpr auto Input = "/org/a11y/atspi/accessible/response";
    static constexpr auto Null = "/org/a11y/atspi/null";
    static constexpr auto Accessible = "org.a11y.atspi.Accessible";
    static constexpr auto Application = "org.a11y.atspi.Application";
};
[[nodiscard]] const char *nativeAssistiveIntrospection() noexcept;
} // namespace Linura::SecurityOwner
