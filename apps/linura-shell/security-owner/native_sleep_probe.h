#pragma once

#include "native_sleep_fence.h"
#include <QDBusMessage>
#include <QVariantMap>

namespace Linura::SecurityOwner {
// Decode only the result of the caller's bounded GetUnit call to the attested
// unique supervisor on the trusted system bus. Newer Qt hides service() for
// replies/errors; it is not a portable received-sender API. The bus correlates
// replies to that request. If Qt exposes a sender it must still match. Only the
// exact native NoSuchUnit error can describe absence.
[[nodiscard]] bool nativeSleepUnitLookupReply(const QDBusMessage &reply, const QString &supervisor,
                                              bool failureDiagnostics = false);
// Private adapter codec, not native evidence by itself. The caller must acquire
// two matching samples from the authenticated unique native supervisor.
[[nodiscard]] std::optional<NativeSleepUnitFacts>
decodeNativeSleepUnitFacts(const QString &supervisor, const QVariantMap &unit,
                           const QVariantMap &service, bool failureDiagnostics = false);
} // namespace Linura::SecurityOwner
