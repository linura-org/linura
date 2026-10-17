#pragma once

#include <QString>
#include <optional>

namespace Linura::SecurityOwner {

// Presentation metadata only. No raw PAM question, echo flag, cookie or response
// may escape the native callback into Qt/QML strings or a model/log context.
enum class NativePromptKind { Response, Password, Pin, VerificationCode, RecoveryCode };
[[nodiscard]] std::optional<NativePromptKind> classifyNativePrompt(const char *question);
[[nodiscard]] std::optional<QString> nativePromptLabel(NativePromptKind kind, quint32 step,
                                                       std::optional<quint32> uid);
} // namespace Linura::SecurityOwner
