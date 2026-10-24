#include "native_assistive.h"
#include "native_assistive_model.h"
#include "native_deadline.h"

#include <QRegularExpression>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <unistd.h>
#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <optional>
#include <thread>

namespace Linura::SecurityOwner {
namespace {
constexpr auto Root = "/org/a11y/atspi/accessible/root";
constexpr auto Frame = "/org/a11y/atspi/accessible/session";
constexpr auto Input = "/org/a11y/atspi/accessible/response";
constexpr auto Null = "/org/a11y/atspi/null";
constexpr auto Accessible = "org.a11y.atspi.Accessible";
constexpr auto Application = "org.a11y.atspi.Application";
constexpr auto Registry = "org.a11y.atspi.Registry";

// Implemented subset of the published AT-SPI protocol, not copied toolkit code
// or a private Qt ABI. Text/EditableText/Value/Action/Component are NOT exported.
// In particular, fake offscreen coordinates cannot become native geometry.
constexpr auto Schema = R"XML(<node>
<interface name="org.a11y.atspi.Accessible">
 <property name="version" type="u" access="read"/>
 <property name="Name" type="s" access="read"/>
 <property name="Description" type="s" access="read"/>
 <property name="Parent" type="(so)" access="read"/>
 <property name="ChildCount" type="i" access="read"/>
 <property name="Locale" type="s" access="read"/>
 <property name="AccessibleId" type="s" access="read"/>
 <property name="HelpText" type="s" access="read"/>
 <method name="GetChildAtIndex"><arg type="i" direction="in"/><arg type="(so)" direction="out"/></method>
 <method name="GetChildren"><arg type="a(so)" direction="out"/></method>
 <method name="GetIndexInParent"><arg type="i" direction="out"/></method>
 <method name="GetRelationSet"><arg type="a(ua(so))" direction="out"/></method>
 <method name="GetRole"><arg type="u" direction="out"/></method>
 <method name="GetRoleName"><arg type="s" direction="out"/></method>
 <method name="GetLocalizedRoleName"><arg type="s" direction="out"/></method>
 <method name="GetState"><arg type="au" direction="out"/></method>
 <method name="GetAttributes"><arg type="a{ss}" direction="out"/></method>
 <method name="GetApplication"><arg type="(so)" direction="out"/></method>
 <method name="GetInterfaces"><arg type="as" direction="out"/></method>
</interface>
<interface name="org.a11y.atspi.Application">
 <property name="ToolkitName" type="s" access="read"/>
 <property name="Version" type="s" access="read"/>
 <property name="ToolkitVersion" type="s" access="read"/>
 <property name="AtspiVersion" type="s" access="read"/>
 <property name="InterfaceVersion" type="u" access="read"/>
 <property name="Id" type="i" access="readwrite"/>
 <method name="GetLocale"><arg type="u" direction="in"/><arg type="s" direction="out"/></method>
 <method name="GetApplicationBusAddress"><arg type="s" direction="out"/></method>
</interface></node>)XML";

bool equal(const char *left, const char *right)
{
    return std::strcmp(left, right) == 0;
}
bool text(const QString &value, qsizetype limit)
{
    return !value.isEmpty() && value.size() <= limit &&
           std::none_of(value.cbegin(), value.cend(),
                        [](QChar c) { return c.isNull() || c.category() == QChar::Other_Control; });
}
void discard(GError *error)
{
    if (error)
        g_error_free(error);
}

// Cancellation, not authentication success or lock release. One original
// bounded connection attempt; stop also cancels its outstanding native I/O.
class Attempt final
{
  public:
    GCancellable *cancel = g_cancellable_new();
    explicit Attempt(GCancellable *stop) : stop_(stop)
    {
        handler_ = g_cancellable_connect(stop, G_CALLBACK(+[](GCancellable *, gpointer data) {
                                             g_cancellable_cancel(G_CANCELLABLE(data));
                                         }),
                                         cancel, nullptr);
        timer_ = std::thread([this] {
            std::unique_lock lock(mutex_);
            if (!condition_.wait_for(lock, std::chrono::seconds(2), [this] { return done_; }))
                g_cancellable_cancel(cancel);
        });
    }
    ~Attempt()
    {
        {
            std::lock_guard lock(mutex_);
            done_ = true;
        }
        condition_.notify_one();
        timer_.join();
        if (handler_)
            g_cancellable_disconnect(stop_, handler_);
        g_object_unref(cancel);
    }

  private:
    GCancellable *stop_;
    gulong handler_ = 0;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread timer_;
};

GDBusConnection *connectSocket(const QString &path, quint32 uid, GCancellable *cancel)
{
    GSocketClient *client = g_socket_client_new();
    g_socket_client_set_timeout(client, 2);
    const auto bytes = path.toUtf8();
    GSocketAddress *address = g_unix_socket_address_new(bytes.constData());
    GError *error = nullptr;
    GSocketConnection *stream =
        g_socket_client_connect(client, G_SOCKET_CONNECTABLE(address), cancel, &error);
    discard(error);
    g_object_unref(address);
    g_object_unref(client);
    if (!stream)
        return nullptr;
    error = nullptr;
    GCredentials *credentials =
        g_socket_get_credentials(g_socket_connection_get_socket(stream), &error);
    discard(error);
    error = nullptr;
    const bool ownPeer =
        credentials && g_credentials_get_unix_user(credentials, &error) == uid && !error;
    discard(error);
    if (credentials)
        g_object_unref(credentials);
    GDBusConnection *connection = nullptr;
    if (ownPeer) {
        error = nullptr;
        connection = g_dbus_connection_new_sync(
            G_IO_STREAM(stream), nullptr,
            static_cast<GDBusConnectionFlags>(G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                                              G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION),
            nullptr, cancel, &error);
        discard(error);
        if (connection)
            g_dbus_connection_set_exit_on_close(connection, FALSE);
    }
    g_object_unref(stream);
    return connection;
}
} // namespace

bool NativeAssistiveProjection::valid() const
{
    return text(heading, 128) && text(description, 512) && text(prompt, 128) &&
           (!accepting || visible) && (!focused || accepting);
}

const char *nativeAssistiveIntrospection() noexcept
{
    return Schema;
}

std::optional<QString> nativeAssistiveSocket(const QString &address, quint32 uid)
{
    if (!uid || address.size() > 256)
        return std::nullopt;
    const auto prefix = QStringLiteral("unix:path=/run/user/%1/at-spi/").arg(uid);
    if (!address.startsWith(prefix))
        return std::nullopt;
    static const QRegularExpression suffix(
        QStringLiteral("^(bus(?:_[0-9]{1,2})?)(?:,guid=[0-9a-f]{32})?$"));
    const auto match = suffix.match(address.mid(prefix.size()));
    if (!match.hasMatch())
        return std::nullopt;
    return prefix.mid(10) + match.captured(1); // Strip exactly "unix:path=".
}

class NativeAssistiveBridge::Impl final
{
  public:
    quint32 uid;
    std::mutex mutex;
    std::condition_variable condition;
    NativeAssistiveProjection projection{
        QStringLiteral("Protected session presentation"),
        QStringLiteral(
            "Presentation metadata is unavailable. No authentication or security is asserted."),
        QStringLiteral("Protected authentication response"),
        false,
        false,
        false};
    std::atomic_bool available = false;
    std::atomic_bool stopping = false;
    GCancellable *stop = g_cancellable_new();
    std::thread worker;
    GDBusConnection *bus = nullptr;
    QString parentName;
    int applicationId = 0; // Registry bookkeeping only; never read by authority.

    explicit Impl(quint32 owner) : uid(owner)
    {
        if (uid && uid == getuid())
            worker = std::thread([this] { run(); });
    }
    ~Impl()
    {
        stopping = true;
        g_cancellable_cancel(stop);
        condition.notify_all();
        if (worker.joinable())
            worker.join();
        g_object_unref(stop);
    }
    NativeAssistiveProjection snapshot()
    {
        std::lock_guard lock(mutex);
        return projection;
    }
    const char *name() const
    {
        return bus ? g_dbus_connection_get_unique_name(bus) : "";
    }
    GVariant *reference(const char *path) const
    {
        return g_variant_new("(so)", name(), path);
    }
    static int node(const char *path)
    {
        return NativeAssistiveModel::node(path);
    }
    NativeAssistiveModel model()
    {
        return {snapshot(), QByteArray(name()), parentName, applicationId};
    }
    GVariant *property(int index, const char *interface, const char *key)
    {
        return model().property(index, interface, key);
    }
    GVariant *method(int index, const char *interface, const char *member, GVariant *arguments)
    {
        return model().method(index, interface, member, arguments);
    }
    static void invoke(GDBusConnection *, const gchar *, const gchar *path, const gchar *interface,
                       const gchar *member, GVariant *arguments, GDBusMethodInvocation *invocation,
                       gpointer data)
    {
        auto &self = *static_cast<Impl *>(data);
        if (auto *result = self.method(node(path), interface, member, arguments))
            g_dbus_method_invocation_return_value(invocation, result);
        else
            g_dbus_method_invocation_return_dbus_error(
                invocation, "org.freedesktop.DBus.Error.NotSupported",
                "Protected presentation exposes bounded metadata only");
    }
    static GVariant *get(GDBusConnection *, const gchar *, const gchar *path,
                         const gchar *interface, const gchar *key, GError **error, gpointer data)
    {
        auto *value = static_cast<Impl *>(data)->property(node(path), interface, key);
        if (!value)
            g_set_error_literal(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                                "Unknown protected metadata property");
        return value;
    }
    static gboolean set(GDBusConnection *, const gchar *, const gchar *path, const gchar *interface,
                        const gchar *key, GVariant *value, GError **error, gpointer data)
    {
        // Standard registry handshake only. This integer has no interpretation
        // outside the AT-SPI adapter and cannot focus, edit, approve or dispatch.
        if (node(path) == 0 && equal(interface, Application) && equal(key, "Id") &&
            g_variant_is_of_type(value, G_VARIANT_TYPE_INT32) && g_variant_get_int32(value) >= 0) {
            static_cast<Impl *>(data)->applicationId = g_variant_get_int32(value);
            return TRUE;
        }
        g_set_error_literal(error, G_DBUS_ERROR, G_DBUS_ERROR_PROPERTY_READ_ONLY,
                            "Protected metadata is read only");
        return FALSE;
    }
    void event(const char *path, const char *member, const char *detail, int enabled,
               GVariant *payload, const char *interface = "org.a11y.atspi.Event.Object")
    {
        GVariantBuilder properties;
        g_variant_builder_init(&properties, G_VARIANT_TYPE("a{sv}"));
        GError *error = nullptr;
        g_dbus_connection_emit_signal(bus, nullptr, path, interface, member,
                                      g_variant_new("(siiv@a{sv})", detail, enabled, 0, payload,
                                                    g_variant_builder_end(&properties)),
                                      &error);
        discard(error);
    }
    void serve(GMainContext *context, Attempt &attempt)
    {
        GError *error = nullptr;
        GDBusNodeInfo *schema = g_dbus_node_info_new_for_xml(Schema, &error);
        discard(error);
        if (!schema)
            return;
        const GDBusInterfaceVTable table{invoke, get, set, {nullptr}};
        std::array<guint, 4> registrations{};
        const std::array paths{Root, Frame, Input, Root};
        for (std::size_t index = 0; index < paths.size(); ++index) {
            error = nullptr;
            registrations[index] = g_dbus_connection_register_object(
                bus, paths[index], schema->interfaces[index == 3 ? 1 : 0], &table, this, nullptr,
                &error);
            discard(error);
            if (!registrations[index])
                break;
        }
        struct Embedded
        {
            Impl *owner;
            bool done = false;
            bool success = false;
        } embedded{this};
        if (std::none_of(registrations.begin(), registrations.end(),
                         [](guint id) { return id == 0; })) {
            // If a native library fails to deliver its cancelled callback, do
            // not leave stack callback state live indefinitely or unwind it.
            NativeDeadline callbackDeadline(std::chrono::seconds(3),
                                            NativeDeadline::Stage::AssistiveCallback);
            g_dbus_connection_call(
                bus, Registry, Root, "org.a11y.atspi.Socket", "Embed",
                g_variant_new("(@(so))", reference(Root)), G_VARIANT_TYPE("((so))"),
                G_DBUS_CALL_FLAGS_NONE, 500, attempt.cancel,
                +[](GObject *source, GAsyncResult *result, gpointer data) {
                    auto &state = *static_cast<Embedded *>(data);
                    GError *failure = nullptr;
                    GVariant *reply =
                        g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &failure);
                    discard(failure);
                    if (reply) {
                        const char *parent = nullptr, *path = nullptr;
                        g_variant_get(reply, "((&s&o))", &parent, &path);
                        if (parent && strnlen(parent, 129) <= 128 && parent[0] == ':' &&
                            equal(path, Root)) {
                            state.owner->parentName = QString::fromLatin1(parent);
                            state.success = true;
                        }
                        g_variant_unref(reply);
                    }
                    state.done = true;
                },
                &embedded);
            // Process the registry's standard Id handshake while awaiting its
            // asynchronous Embed reply. Never deadlock a synchronous call here.
            while (!embedded.done) {
                if (stopping)
                    g_cancellable_cancel(attempt.cancel);
                for (unsigned budget = 0; budget < 8 && g_main_context_pending(context); ++budget)
                    g_main_context_iteration(context, FALSE);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
        available = embedded.success && !stopping && !g_cancellable_is_cancelled(attempt.cancel);
        const guint registryWatch = g_dbus_connection_signal_subscribe(
            bus, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
            "/org/freedesktop/DBus", Registry, G_DBUS_SIGNAL_FLAGS_NONE,
            +[](GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *,
                GVariant *arguments, gpointer data) {
                auto &self = *static_cast<Impl *>(data);
                if (!g_variant_is_of_type(arguments, G_VARIANT_TYPE("(sss)")) ||
                    g_variant_get_size(arguments) > 512) {
                    self.available = false;
                    return;
                }
                const char *name = nullptr, *oldOwner = nullptr, *newOwner = nullptr;
                g_variant_get(arguments, "(&s&s&s)", &name, &oldOwner, &newOwner);
                if (!equal(name, Registry) || self.parentName != QString::fromLatin1(newOwner))
                    self.available = false;
            },
            this, nullptr);
        // Close the Embed-to-watch race without making registry identity an
        // authority fact. Failure only retires this read-only metadata export.
        error = nullptr;
        GVariant *owner =
            available
                ? g_dbus_connection_call_sync(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                              "org.freedesktop.DBus", "GetNameOwner",
                                              g_variant_new("(s)", Registry), G_VARIANT_TYPE("(s)"),
                                              G_DBUS_CALL_FLAGS_NONE, 500, attempt.cancel, &error)
                : nullptr;
        discard(error);
        if (owner && g_variant_get_size(owner) <= 132) {
            const char *name = nullptr;
            g_variant_get(owner, "(&s)", &name);
            if (parentName != QString::fromLatin1(name))
                available = false;
        } else {
            available = false;
        }
        if (owner)
            g_variant_unref(owner);
        NativeAssistiveProjection previous;
        while (available && !stopping && !g_dbus_connection_is_closed(bus)) {
            for (unsigned budget = 0; budget < 8 && g_main_context_pending(context); ++budget)
                g_main_context_iteration(context, FALSE);
            const auto value = snapshot();
            if (value.valid() && value != previous) {
                if (value.heading != previous.heading)
                    event(Frame, "PropertyChange", "accessible-name", 0,
                          g_variant_new_string(value.heading.toUtf8().constData()));
                if (value.description != previous.description)
                    event(Frame, "PropertyChange", "accessible-description", 0,
                          g_variant_new_string(value.description.toUtf8().constData()));
                if (value.prompt != previous.prompt)
                    event(Input, "PropertyChange", "accessible-name", 0,
                          g_variant_new_string(value.prompt.toUtf8().constData()));
                if (value.accepting != previous.accepting)
                    event(Frame, "ChildrenChanged", value.accepting ? "add" : "remove", 0,
                          reference(Input));
                if (value.visible != previous.visible) {
                    event(Frame, "StateChanged", "showing", value.visible ? 1 : 0,
                          g_variant_new_string(""));
                    event(Frame, value.visible ? "Activate" : "Deactivate", "", 0,
                          g_variant_new_string(""), "org.a11y.atspi.Event.Window");
                }
                if (value.focused != previous.focused || value.accepting != previous.accepting)
                    event(Input, "StateChanged", "focused",
                          value.focused && value.accepting ? 1 : 0, g_variant_new_string(""));
                previous = value;
            }
            std::unique_lock lock(mutex);
            condition.wait_for(lock, std::chrono::milliseconds(20),
                               [this] { return stopping.load(); });
        }
        available = false;
        if (registryWatch)
            g_dbus_connection_signal_unsubscribe(bus, registryWatch);
        for (guint registration : registrations)
            if (registration)
                g_dbus_connection_unregister_object(bus, registration);
        g_dbus_node_info_unref(schema);
        parentName.clear();
        applicationId = 0;
    }
    void run()
    {
        GMainContext *context = g_main_context_new();
        g_main_context_push_thread_default(context);
        while (!stopping) {
            {
                Attempt attempt(stop);
                GDBusConnection *session =
                    connectSocket(QStringLiteral("/run/user/%1/bus").arg(uid), uid, attempt.cancel);
                if (session) {
                    GError *error = nullptr;
                    GVariant *reply = g_dbus_connection_call_sync(
                        session, "org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus", "GetAddress",
                        nullptr, G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 500, attempt.cancel,
                        &error);
                    discard(error);
                    if (reply && g_variant_get_size(reply) <= 260) {
                        const char *address = nullptr;
                        g_variant_get(reply, "(&s)", &address);
                        const auto path = nativeAssistiveSocket(QString::fromUtf8(address), uid);
                        if (path)
                            bus = connectSocket(*path, uid, attempt.cancel);
                    }
                    if (reply)
                        g_variant_unref(reply);
                    g_dbus_connection_close(session, nullptr, nullptr, nullptr);
                    g_object_unref(session);
                    if (bus) {
                        serve(context, attempt);
                        g_dbus_connection_close(bus, nullptr, nullptr, nullptr);
                        g_object_unref(bus);
                        bus = nullptr;
                    }
                }
            }
            std::unique_lock lock(mutex);
            condition.wait_for(lock, std::chrono::seconds(5), [this] { return stopping.load(); });
        }
        g_main_context_pop_thread_default(context);
        g_main_context_unref(context);
    }
};

NativeAssistiveBridge::NativeAssistiveBridge(quint32 ownerUid)
    : impl_(std::make_unique<Impl>(ownerUid))
{}
NativeAssistiveBridge::~NativeAssistiveBridge() = default;
void NativeAssistiveBridge::publish(const NativeAssistiveProjection &projection)
{
    if (!projection.valid())
        return;
    std::lock_guard lock(impl_->mutex);
    impl_->projection = projection;
}
bool NativeAssistiveBridge::registered() const noexcept
{
    return impl_->available.load();
}
} // namespace Linura::SecurityOwner
