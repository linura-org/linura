#include "native_compose.h"

#include <QCryptographicHash>
#include <QFile>
#include <QResource>

#include <xkbcommon/xkbcommon-compose.h>

#include <algorithm>
#include <mutex>

// Q_INIT_RESOURCE must resolve its generated symbol in the global namespace.
static void initializeComposeResources()
{
    Q_INIT_RESOURCE(linura_security_owner_compose);
}

namespace Linura::SecurityOwner {
namespace {
constexpr qsizetype MaximumComposeBytes = 1024 * 1024;
constexpr auto ComposePath = ":/linura/security-owner/compose/en_US.UTF-8";
constexpr auto ComposeSha256 = "272667553c5abc2e7940507502963092defbdaa52740a59efc1acfdfe1f4cef2";
} // namespace

bool boundedComposeSource(std::string_view source) noexcept
{
    if (source.empty() || source.size() > static_cast<std::size_t>(MaximumComposeBytes) ||
        std::find(source.begin(), source.end(), '\0') != source.end())
        return false;
    while (!source.empty()) {
        const auto newline = source.find('\n');
        auto line = source.substr(0, newline);
        const auto start = line.find_first_not_of(" \t\r");
        if (start != std::string_view::npos && line.substr(start).starts_with("include"))
            return false;
        if (newline == std::string_view::npos)
            break;
        source.remove_prefix(newline + 1);
    }
    return true;
}

xkb_compose_table *trustedComposeTable(xkb_context *context) noexcept
{
    if (!context)
        return nullptr;
    static std::once_flag initialized;
    std::call_once(initialized, initializeComposeResources);
    QFile resource(QString::fromLatin1(ComposePath));
    if (!resource.open(QIODevice::ReadOnly) || resource.size() <= 0 ||
        resource.size() > MaximumComposeBytes)
        return nullptr;
    const QByteArray source = resource.read(MaximumComposeBytes + 1);
    if (source.size() != resource.size() ||
        !boundedComposeSource(
            std::string_view(source.constData(), static_cast<std::size_t>(source.size()))) ||
        QCryptographicHash::hash(source, QCryptographicHash::Sha256).toHex() != ComposeSha256)
        return nullptr;
    return xkb_compose_table_new_from_buffer(
        context, source.constData(), static_cast<std::size_t>(source.size()), "C.UTF-8",
        XKB_COMPOSE_FORMAT_TEXT_V1, XKB_COMPOSE_COMPILE_NO_FLAGS);
}
} // namespace Linura::SecurityOwner
