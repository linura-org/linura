#pragma once

#include "native_sleep_fence.h"
#include <QVariantMap>

namespace Linura::SecurityOwner {
// Private adapter codec, not native evidence by itself. The caller must acquire
// two matching samples from the authenticated unique native supervisor.
[[nodiscard]] std::optional<NativeSleepUnitFacts>
decodeNativeSleepUnitFacts(const QString &supervisor, const QVariantMap &unit,
                           const QVariantMap &service);
} // namespace Linura::SecurityOwner
