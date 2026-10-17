#include "secret_buffer.h"

#include <sys/mman.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <limits>

namespace Linura::SecurityOwner {
namespace {

void wipe(void *pointer, std::size_t bytes) noexcept
{
    // Linux's explicit_bzero is guaranteed not to be optimized away.
    explicit_bzero(pointer, bytes);
}

} // namespace

SecretBuffer::SecretBuffer()
{
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || static_cast<unsigned long>(page) < MaximumBytes + 1)
        return;
    mappingBytes_ = static_cast<std::size_t>(page);
    void *memory =
        mmap(nullptr, mappingBytes_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        mappingBytes_ = 0;
        return;
    }
    if (mlock(memory, mappingBytes_) != 0 || madvise(memory, mappingBytes_, MADV_DONTDUMP) != 0 ||
        madvise(memory, mappingBytes_, MADV_DONTFORK) != 0) {
        wipe(memory, mappingBytes_);
        munlock(memory, mappingBytes_);
        munmap(memory, mappingBytes_);
        mappingBytes_ = 0;
        return;
    }
    mapping_ = static_cast<char *>(memory);
}

SecretBuffer::~SecretBuffer()
{
    if (mapping_) {
        clear();
        munlock(mapping_, mappingBytes_);
        munmap(mapping_, mappingBytes_);
    }
}

bool SecretBuffer::available() const noexcept
{
    return mapping_ != nullptr;
}
std::size_t SecretBuffer::length() const noexcept
{
    return scalars_;
}

bool SecretBuffer::append(QStringView text) noexcept
{
    if (!available() || text.isEmpty() || text.size() > qsizetype(MaximumScalars * 2))
        return false;

    // Encode into a bounded stack buffer first: malformed/oversized input cannot
    // leave a partial edit. No intermediate owning QString/QByteArray is created.
    std::array<char, MaximumBytes> encoded{};
    std::size_t count = 0;
    std::size_t characters = 0;
    bool valid = true;
    for (qsizetype index = 0; index < text.size(); ++index) {
        char32_t scalar = text[index].unicode();
        if (QChar::isHighSurrogate(scalar)) {
            if (++index >= text.size() || !text[index].isLowSurrogate()) {
                valid = false;
                break;
            }
            scalar = QChar::surrogateToUcs4(text[index - 1], text[index]);
        } else if (QChar::isLowSurrogate(scalar)) {
            valid = false;
            break;
        }
        // NUL/control values cannot be valid protected-channel responses. Text
        // navigation and paste are handled by the native input widget instead.
        if (scalar < 0x20 || (scalar >= 0x7f && scalar <= 0x9f)) {
            valid = false;
            break;
        }
        const std::size_t required = scalar < 0x80      ? 1
                                     : scalar < 0x800   ? 2
                                     : scalar < 0x10000 ? 3
                                                        : 4;
        if (count + required > encoded.size() || ++characters + scalars_ > MaximumScalars) {
            valid = false;
            break;
        }
        if (required == 1) {
            encoded[count++] = static_cast<char>(scalar);
        } else {
            const unsigned char prefix = required == 2 ? 0xc0 : required == 3 ? 0xe0 : 0xf0;
            encoded[count++] = static_cast<char>(prefix | (scalar >> (6 * (required - 1))));
            for (std::size_t remaining = required - 1; remaining > 0; --remaining)
                encoded[count++] =
                    static_cast<char>(0x80 | ((scalar >> (6 * (remaining - 1))) & 0x3f));
        }
    }
    if (valid && bytes_ + count <= MaximumBytes) {
        std::memcpy(mapping_ + bytes_, encoded.data(), count);
        bytes_ += count;
        scalars_ += characters;
        mapping_[bytes_] = '\0';
    } else {
        valid = false;
    }
    wipe(encoded.data(), encoded.size());
    return valid;
}

bool SecretBuffer::appendUtf8(std::string_view text) noexcept
{
    if (!available() || text.empty() || text.size() > MaximumBytes - bytes_)
        return false;
    std::size_t count = 0;
    for (std::size_t index = 0; index < text.size();) {
        const auto first = static_cast<unsigned char>(text[index++]);
        char32_t scalar = first;
        std::size_t continuation = 0;
        char32_t minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            scalar = first & 0x1f;
            continuation = 1;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            scalar = first & 0x0f;
            continuation = 2;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            scalar = first & 0x07;
            continuation = 3;
            minimum = 0x10000;
        } else if (first >= 0x80)
            return false;
        if (continuation > text.size() - index)
            return false;
        while (continuation > 0) {
            --continuation;
            const auto next = static_cast<unsigned char>(text[index++]);
            if ((next & 0xc0) != 0x80)
                return false;
            scalar = (scalar << 6) | (next & 0x3f);
        }
        if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff) ||
            scalar < 0x20 || (scalar >= 0x7f && scalar <= 0x9f) ||
            ++count > MaximumScalars - scalars_)
            return false;
    }
    // Validate the entire edit before touching the protected mapping. Embedded
    // NUL, overlong forms, surrogates, truncation and scalar/capacity overflow
    // cannot leave a partial response or be repaired to replacement characters.
    std::memcpy(mapping_ + bytes_, text.data(), text.size());
    bytes_ += text.size();
    scalars_ += count;
    mapping_[bytes_] = '\0';
    return true;
}

void SecretBuffer::eraseLast() noexcept
{
    if (bytes_ == 0)
        return;
    std::size_t start = bytes_ - 1;
    while (start > 0 && (static_cast<unsigned char>(mapping_[start]) & 0xc0) == 0x80)
        --start;
    wipe(mapping_ + start, bytes_ - start);
    bytes_ = start;
    --scalars_;
}

void SecretBuffer::clear() noexcept
{
    if (mapping_)
        wipe(mapping_, mappingBytes_);
    bytes_ = 0;
    scalars_ = 0;
}

bool SecretBuffer::respond(const std::function<void(const char *)> &response)
{
    if (!available() || !response) {
        clear(); // A broken native channel must not retain the entered response.
        return false;
    }
    struct ClearOnExit
    {
        SecretBuffer &buffer;
        ~ClearOnExit()
        {
            buffer.clear();
        }
    } cleanup{*this};
    response(mapping_);
    return true;
}

} // namespace Linura::SecurityOwner
