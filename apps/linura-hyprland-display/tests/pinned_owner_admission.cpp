// The live sd-bus adapter is compiled and tested inside the pinned SDK. Host
// component tests need no second, unpinned host libsystemd development package.
#include "native_owner_admission.h"

#include <chrono>
#include <unistd.h>
#include <gtest/gtest.h>

using namespace Linura::HyprlandDisplay;

TEST(LinuraDisplayOwnerAdmission, SameUidOrdinaryExecutableIsNotSupervisedOwner)
{
    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(attestDisplayOwner(getpid(), getuid()));
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(1));
    EXPECT_FALSE(attestDisplayOwner(0, getuid()));
    EXPECT_FALSE(attestDisplayOwner(getpid(), 0));
}
