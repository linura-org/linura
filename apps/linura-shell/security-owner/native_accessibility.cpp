#include "native_accessibility.h"
#include "secret_entry.h"

#include <QAccessibleObject>
#include <mutex>

namespace Linura::SecurityOwner {
namespace {
class ProtectedInputAccessibility final : public QAccessibleObject
{
  public:
    explicit ProtectedInputAccessibility(SecretEntry *entry) : QAccessibleObject(entry) {}
    QAccessibleInterface *parent() const override
    {
        const auto *entry = qobject_cast<SecretEntry *>(object());
        return entry && entry->parentItem()
                   ? QAccessible::queryAccessibleInterface(entry->parentItem())
                   : nullptr;
    }
    QAccessibleInterface *child(int) const override
    {
        return nullptr;
    }
    int childCount() const override
    {
        return 0;
    }
    int indexOfChild(const QAccessibleInterface *) const override
    {
        return -1;
    }
    QRect rect() const override
    {
        // This renderer is offscreen and shared by multiple native lock outputs.
        // Its Qt window coordinates are NOT global Wayland output geometry.
        return {};
    }
    QString text(QAccessible::Text kind) const override
    {
        const auto *entry = qobject_cast<SecretEntry *>(object());
        if (!entry)
            return {};
        if (kind == QAccessible::Name)
            return entry->nativeAccessibleName();
        if (kind == QAccessible::Description)
            return QStringLiteral("Protected keyboard response. Contents are never exposed.");
        return {}; // Value, selection, cursor and response length are never readable.
    }
    void setText(QAccessible::Text, const QString &) override {}
    void *interface_cast(QAccessible::InterfaceType) override
    {
        return nullptr;
    }
    QAccessible::Role role() const override
    {
        return QAccessible::EditableText;
    }
    QAccessible::State state() const override
    {
        QAccessible::State result;
        const auto *entry = qobject_cast<SecretEntry *>(object());
        result.invalid = !entry;
        result.passwordEdit = true;
        result.focusable = entry != nullptr;
        result.focused = entry && entry->nativeAccessibilityFocused();
        result.disabled = !entry || !entry->isEnabled() || !entry->acceptsInput();
        result.invisible = !entry || !entry->isVisible();
        result.readOnly = !entry || !entry->acceptsInput();
        return result;
    }
};
} // namespace

void installProtectedInputAccessibility()
{
    static std::once_flag installed;
    std::call_once(installed, [] {
        QAccessible::installFactory(
            +[](const QString &, QObject *object) -> QAccessibleInterface * {
                auto *entry = qobject_cast<SecretEntry *>(object);
                return entry ? new ProtectedInputAccessibility(entry) : nullptr;
            });
    });
}
void announceProtectedInputMetadata(SecretEntry &entry)
{
    QAccessibleEvent event(&entry, QAccessible::NameChanged);
    QAccessible::updateAccessibility(&event);
    QAccessible::State changed;
    changed.disabled = changed.readOnly = changed.focused = true;
    QAccessibleStateChangeEvent state(&entry, changed);
    QAccessible::updateAccessibility(&state);
}
void announceProtectedInputFocus(SecretEntry &entry)
{
    QAccessibleEvent event(&entry, QAccessible::Focus);
    QAccessible::updateAccessibility(&event);
}
} // namespace Linura::SecurityOwner
