#include "native_prompt.h"
#include "native_approval.h"

#include <cstring>
#include <string_view>

namespace Linura::SecurityOwner {
std::optional<NativePromptKind> classifyNativePrompt(const char *question)
{
    if (!question)
        return std::nullopt;
    const auto length = strnlen(question, 513);
    if (length > 512)
        return std::nullopt;
    std::string_view text(question, length);
    const auto space = [](char value) { return value == ' ' || value == '\t'; };
    while (!text.empty() && space(text.front()))
        text.remove_prefix(1);
    while (!text.empty() && space(text.back()))
        text.remove_suffix(1);
    if (!text.empty() && text.back() == ':')
        text.remove_suffix(1);
    const auto equals = [&](std::string_view known) {
        if (text.size() != known.size())
            return false;
        for (std::size_t index = 0; index < known.size(); ++index) {
            const char value = text[index];
            const char lower = value >= 'A' && value <= 'Z' ? char(value + ('a' - 'A')) : value;
            if (lower != known[index])
                return false;
        }
        return true;
    };
    if (equals("password"))
        return NativePromptKind::Password;
    if (equals("pin"))
        return NativePromptKind::Pin;
    if (equals("verification code") || equals("one-time password") || equals("otp"))
        return NativePromptKind::VerificationCode;
    if (equals("recovery code"))
        return NativePromptKind::RecoveryCode;
    // Unknown/localized/provider-specific questions remain generic. Never copy,
    // sanitize or render arbitrary native text, which may itself contain secrets.
    return NativePromptKind::Response;
}

std::optional<QString> nativePromptLabel(NativePromptKind kind, quint32 step,
                                         std::optional<quint32> uid)
{
    if (step == 0 || step > NativeApproval::MaximumConversationPrompts)
        return std::nullopt;
    QString name;
    switch (kind) {
    case NativePromptKind::Response:
        name = QStringLiteral("Response");
        break;
    case NativePromptKind::Password:
        name = QStringLiteral("Password");
        break;
    case NativePromptKind::Pin:
        name = QStringLiteral("PIN");
        break;
    case NativePromptKind::VerificationCode:
        name = QStringLiteral("Code");
        break;
    case NativePromptKind::RecoveryCode:
        name = QStringLiteral("Recovery code");
        break;
    default:
        return std::nullopt;
    }
    const auto label = QStringLiteral("%1 (%2)").arg(name).arg(step);
    return uid ? QStringLiteral("%1 · UID %2").arg(label).arg(*uid) : label;
}
} // namespace Linura::SecurityOwner
