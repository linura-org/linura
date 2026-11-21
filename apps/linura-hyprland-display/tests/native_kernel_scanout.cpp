#include "native_kernel_scanout.h"

#include <cassert>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>

using namespace Linura::HyprlandDisplay;

int main()
{
    // Comparison/refusal component fixture only, not real KMS qualification.
    drmModeModeInfo original{};
    original.clock = 148500;
    original.hdisplay = 1920;
    original.hsync_start = 2008;
    original.hsync_end = 2052;
    original.htotal = 2200;
    original.vdisplay = 1080;
    original.vsync_start = 1084;
    original.vsync_end = 1089;
    original.vtotal = 1125;
    assert(sameKernelMode(original, original));
    for (unsigned field = 0; field < 12; ++field) {
        auto changed = original;
        switch (field) {
        case 0:
            ++changed.clock;
            break;
        case 1:
            ++changed.hdisplay;
            break;
        case 2:
            ++changed.hsync_start;
            break;
        case 3:
            ++changed.hsync_end;
            break;
        case 4:
            ++changed.htotal;
            break;
        case 5:
            ++changed.hskew;
            break;
        case 6:
            ++changed.vdisplay;
            break;
        case 7:
            ++changed.vsync_start;
            break;
        case 8:
            ++changed.vsync_end;
            break;
        case 9:
            ++changed.vtotal;
            break;
        case 10:
            ++changed.vscan;
            break;
        case 11:
            ++changed.flags;
            break;
        }
        assert(!sameKernelMode(original, changed));
    }
    auto labels = original;
    labels.name[0] = 'x';
    labels.type = 123;
    labels.vrefresh = 60;
    assert(sameKernelMode(original, labels)); // Labels/derived hints are not timing.

    unsigned calls = 0;
    auto budget = [&] {
        ++calls;
        return true;
    };
    assert(!readNativeKernelScanout(-1, 1, budget) && calls == 0);
    assert(!readNativeKernelScanout(0, 0, budget) && calls == 0);
    assert(!readNativeKernelScanout(0, 1, {}));
    assert(!readNativeKernelScanout(0, 1, [] { return false; }));
    const int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(descriptor >= 0);
    assert(!readNativeKernelScanout(descriptor, 1, budget));
    assert(calls <= 3 && fcntl(descriptor, F_GETFD) == FD_CLOEXEC);
    close(descriptor);
}
