cmake_minimum_required(VERSION 3.24)
project(linura-s17-native-probes LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core DBus)
# Disposable-guest qualification client only. No install target, credentials,
# native input, Control/effect handles, or production runtime linkage.
add_executable(linura-s17-assistive-probe native-assistive-probe.cpp)
target_link_libraries(linura-s17-assistive-probe PRIVATE Qt6::Core Qt6::DBus)
target_compile_options(linura-s17-assistive-probe PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

# The guest explicitly enables this against its pinned native systemd package.
# Host AT-SPI component checks do not install or borrow a second development SDK.
option(LINURA_DISPLAY_OWNER_ADMISSION_PROBE "Build guest-only native display admission probe" OFF)
if(LINURA_DISPLAY_OWNER_ADMISSION_PROBE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DISPLAY_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
    get_filename_component(DISPLAY_NATIVE_SOURCE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../apps/linura-hyprland-display" ABSOLUTE)
    add_executable(linura-s21-owner-admission-probe native-display-admission-probe.cpp
        "${DISPLAY_NATIVE_SOURCE}/native_owner_admission.cpp"
        "${DISPLAY_NATIVE_SOURCE}/owner_identity.cpp")
    target_include_directories(linura-s21-owner-admission-probe PRIVATE "${DISPLAY_NATIVE_SOURCE}")
    target_link_libraries(linura-s21-owner-admission-probe PRIVATE PkgConfig::DISPLAY_SYSTEMD)
    target_compile_options(linura-s21-owner-admission-probe PRIVATE
        -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
endif()
include(CTest)
if(BUILD_TESTING)
    add_executable(linura-s17-assistive-denial-test native-assistive-denial-test.cpp)
    target_link_libraries(linura-s17-assistive-denial-test PRIVATE Qt6::Core)
    target_compile_options(linura-s17-assistive-denial-test PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME native-assistive-denial-classification
        COMMAND linura-s17-assistive-denial-test)
    set_tests_properties(native-assistive-denial-classification PROPERTIES TIMEOUT 10)
    add_executable(linura-s17-assistive-discovery-test native-assistive-discovery-test.cpp)
    target_link_libraries(linura-s17-assistive-discovery-test PRIVATE Qt6::Core Qt6::DBus)
    target_compile_options(linura-s17-assistive-discovery-test PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME native-assistive-registry-discovery
        COMMAND linura-s17-assistive-discovery-test)
    set_tests_properties(native-assistive-registry-discovery PROPERTIES TIMEOUT 10)
endif()
