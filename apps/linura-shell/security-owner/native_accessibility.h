#pragma once

namespace Linura::SecurityOwner {
class SecretEntry;
// Native metadata adapter only. No text/value/action interface or input grant.
void installProtectedInputAccessibility();
void announceProtectedInputMetadata(SecretEntry &entry);
void announceProtectedInputFocus(SecretEntry &entry);
} // namespace Linura::SecurityOwner
