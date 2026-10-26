#include "secret_entry.h"

#include <QFocusEvent>
#include <QAccessible>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMetaMethod>
#include <QMetaProperty>
#include <QQuickWindow>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

using Linura::SecurityOwner::NativePromptKind;
using Linura::SecurityOwner::SecretEntry;

namespace {
std::size_t checks = 0;
void check(bool condition)
{
    ++checks;
    if (!condition)
        throw std::runtime_error("protected input assertion failed (no secret data)");
}
void key(SecretEntry &entry, int value, Qt::KeyboardModifiers modifiers = Qt::NoModifier,
         const QString &text = {})
{
    QKeyEvent event(QEvent::KeyPress, value, modifiers, text);
    QCoreApplication::sendEvent(&entry, &event);
    check(event.isAccepted());
}
} // namespace

int main(int argc, char **argv)
{
    QGuiApplication application(argc, argv);
    try {
        // Visibility restoration requires an actual scene/window on Qt 6.10;
        // a detached item may stay effectively hidden after setVisible(true).
        // Exercise cancellation in the same scene ownership shape as the native
        // renderer, retaining every hide/disable/focus/borrowed-response check.
        QQuickWindow window;
        window.resize(1, 1);
        window.show();
        application.processEvents();
        SecretEntry entry(window.contentItem());
        using Linura::SecurityOwner::classifyNativePrompt;
        using Linura::SecurityOwner::nativePromptLabel;
        check(classifyNativePrompt(" Password: ") == NativePromptKind::Password);
        check(classifyNativePrompt("PIN:") == NativePromptKind::Pin);
        for (const char *question : {"Verification code:", "OTP:", "one-time password:"})
            check(classifyNativePrompt(question) == NativePromptKind::VerificationCode);
        check(classifyNativePrompt("Recovery code:") == NativePromptKind::RecoveryCode);
        check(!classifyNativePrompt(nullptr));
        const std::string oversized(513, 'x');
        check(!classifyNativePrompt(oversized.c_str()));
        for (const char *question :
             {"", "arbitrary native message", "Password: do not render this"})
            check(classifyNativePrompt(question) == NativePromptKind::Response);
        check(nativePromptLabel(NativePromptKind::Password, 1, 1000) ==
              QStringLiteral("Password (1) · UID 1000"));
        check(nativePromptLabel(NativePromptKind::VerificationCode, 2, 0) ==
              QStringLiteral("Code (2) · UID 0"));
        check(!nativePromptLabel(NativePromptKind::Response, 0, 1000));
        check(!nativePromptLabel(NativePromptKind::Response, 9, 1000));
        check(!nativePromptLabel(static_cast<NativePromptKind>(99), 1, 1000));
        check(!entry.beginNativePrompt(NativePromptKind::Response, 0));
        check(!entry.beginNativePrompt(NativePromptKind::Response, 9));
        check(!entry.beginNativePrompt(static_cast<NativePromptKind>(99)));
        check(entry.metaObject()->indexOfProperty("promptLabel") == -1);
        auto *accessible = QAccessible::queryAccessibleInterface(&entry);
        check(accessible && accessible->isValid());
        check(accessible->role() == QAccessible::EditableText && accessible->state().passwordEdit);
        check(!accessible->textInterface() && !accessible->editableTextInterface() &&
              !accessible->valueInterface() && !accessible->actionInterface());
        check(accessible->text(QAccessible::Value).isEmpty());
        check(accessible->rect().isEmpty()); // Offscreen Qt geometry is not native output geometry.
        check(entry.beginNativePrompt(NativePromptKind::VerificationCode, 2, 1000));
        const auto safeName = accessible->text(QAccessible::Name);
        check(safeName == QStringLiteral("Code (2) · UID 1000"));
        const QString generatedMetadataTest(1, QChar(char16_t(0x71)));
        key(entry, Qt::Key_unknown, Qt::NoModifier, generatedMetadataTest);
        check(entry.maskedLength() == 1 && accessible->text(QAccessible::Value).isEmpty());
        accessible->setText(QAccessible::Value, generatedMetadataTest);
        accessible->setText(QAccessible::Name, generatedMetadataTest);
        check(entry.maskedLength() == 1 && accessible->text(QAccessible::Name) == safeName);
        check(!accessible->textInterface() && !accessible->actionInterface());
        entry.cancelNativePrompt();
        check(accessible->text(QAccessible::Value).isEmpty());
        check(accessible->text(QAccessible::Name) ==
              QStringLiteral("Protected authentication response"));
        check(entry.storageAvailable());
        check(!entry.acceptsInput());
        check(entry.metaObject()->indexOfProperty("text") == -1);
        check(entry.metaObject()->indexOfProperty("password") == -1);
        check(entry.metaObject()->indexOfMethod("respondToNativePrompt()") == -1);
        check(entry.metaObject()->indexOfMethod("beginNativePrompt()") == -1);
        const int property = entry.metaObject()->indexOfProperty("acceptsInput");
        check(property >= 0 && !entry.metaObject()->property(property).isWritable());
        check(entry.beginNativePrompt());
        const QString generated(1, QChar(char16_t(0x61)));
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        check(entry.maskedLength() == 1);
        QKeyEvent released(QEvent::KeyRelease, Qt::Key_A, Qt::NoModifier, generated);
        QCoreApplication::sendEvent(&entry, &released);
        check(released.isAccepted());
        check(entry.maskedLength() == 1);
        key(entry, Qt::Key_V, Qt::ControlModifier, generated);
        check(entry.maskedLength() == 1);
        key(entry, Qt::Key_Backspace);
        check(entry.maskedLength() == 0);
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        bool submitted = false;
        QObject::connect(&entry, &SecretEntry::submissionRequested, &entry, [&] {
            check(entry.respondToNativePrompt([&](const char *response) {
                check(std::strlen(response) == 1);
                submitted = true;
            }));
        });
        key(entry, Qt::Key_Return);
        check(submitted && !entry.acceptsInput() && entry.maskedLength() == 0);
        check(!entry.respondToNativePrompt([](const char *) {}));
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        bool cancelled = false;
        QObject::connect(&entry, &SecretEntry::cancellationRequested, &entry,
                         [&] { cancelled = true; });
        key(entry, Qt::Key_Escape);
        check(cancelled && !entry.acceptsInput() && entry.maskedLength() == 0);
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        QFocusEvent focus(QEvent::FocusOut, Qt::OtherFocusReason);
        QCoreApplication::sendEvent(&entry, &focus);
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        entry.setVisible(false);
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        check(!entry.beginNativePrompt());
        entry.setVisible(true);
        check(entry.beginNativePrompt());
        entry.setEnabled(false);
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        check(!entry.beginNativePrompt());
        entry.setEnabled(true);
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        check(!entry.respondToNativePrompt({}));
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        check(entry.respondToNativePrompt([&](const char *response) {
            check(std::strlen(response) == 1);
            check(!entry.beginNativePrompt()); // Cannot erase the live response.
            check(!entry.respondToNativePrompt([](const char *) {}));
            check(std::strlen(response) == 1);
        }));
        check(!entry.acceptsInput() && entry.maskedLength() == 0);
        check(entry.beginNativePrompt());
        key(entry, Qt::Key_A, Qt::NoModifier, generated);
        try {
            (void)entry.respondToNativePrompt([](const char *) {
                throw std::runtime_error("synthetic native response-channel failure");
            });
            check(false);
        } catch (const std::runtime_error &) {
            check(!entry.acceptsInput() && entry.maskedLength() == 0);
        }
        check(entry.beginNativePrompt());
        entry.cancelNativePrompt();
        for (bool visibilityLoss : {false, true}) {
            check(entry.beginNativePrompt());
            key(entry, Qt::Key_A, Qt::NoModifier, generated);
            cancelled = false;
            check(entry.respondToNativePrompt([&](const char *response) {
                check(std::strlen(response) == 1);
                if (visibilityLoss)
                    entry.setVisible(false);
                else
                    entry.cancelNativePrompt();
                check(std::strlen(response) == 1); // Still borrowed until delivery returns.
                check(!cancelled); // No teardown/denial callback may escape before wiping.
            }));
            check(cancelled && !entry.acceptsInput() && entry.maskedLength() == 0);
            entry.setVisible(true);
        }
        std::cout << "protected native input: " << checks << " checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << " (check " << checks << ")\n";
        return 1;
    }
}
