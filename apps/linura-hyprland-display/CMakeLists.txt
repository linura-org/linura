cmake_minimum_required(VERSION 3.24)
project(linura-hyprland-display VERSION 0.10 LANGUAGES C CXX)

# The pinned parent sets -frtti for its C++ sources at directory scope. Keep
# that behavior for C++, while the scanner's generated C stays valid under our
# unchanged -Werror gate. No diagnostic or warning class is suppressed.
get_directory_property(inherited_compile_options COMPILE_OPTIONS)
if("-frtti" IN_LIST inherited_compile_options)
    list(REMOVE_ITEM inherited_compile_options "-frtti")
    list(APPEND inherited_compile_options "$<$<COMPILE_LANGUAGE:CXX>:-frtti>")
endif()
# Upstream appends non-PIE flags for debug helpers after creating Hyprland's
# main targets. They must not override -fPIC on our later-added libraries or
# weaken our own executables. Keep the parent targets' options unchanged.
list(REMOVE_ITEM inherited_compile_options "-fno-pie")
set_directory_properties(PROPERTIES COMPILE_OPTIONS "${inherited_compile_options}")
get_directory_property(inherited_link_options LINK_OPTIONS)
list(REMOVE_ITEM inherited_link_options "-no-pie")
set_directory_properties(PROPERTIES LINK_OPTIONS "${inherited_link_options}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# These static libraries are linked into the pinned compositor's PIE binary.
# Preserve that hardening when this component is built as a subdirectory.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include("${CMAKE_CURRENT_SOURCE_DIR}/integration_identity.cmake")
linura_display_integration_identity("${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")

add_library(linura-hyprland-display-mechanism STATIC display_transaction.cpp protected_interaction.cpp protected_input_retirement.cpp)
target_include_directories(linura-hyprland-display-mechanism PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(linura-hyprland-display-mechanism PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
pkg_check_modules(WAYLAND_SERVER REQUIRED IMPORTED_TARGET wayland-server>=1.22)
add_library(linura-hyprland-display-supervisor STATIC compositor_display_service.cpp)
target_link_libraries(linura-hyprland-display-supervisor PUBLIC
    linura-hyprland-display-mechanism PkgConfig::WAYLAND_SERVER)
target_compile_options(linura-hyprland-display-supervisor PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

find_program(WAYLAND_SCANNER wayland-scanner REQUIRED)
set(DISPLAY_XML "${CMAKE_CURRENT_SOURCE_DIR}/protocols/linura-display-management-v1.xml")
set(DISPLAY_SERVER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/linura-display-management-v1-server-protocol.h")
set(DISPLAY_CLIENT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/linura-display-management-v1-client-protocol.h")
set(DISPLAY_CODE "${CMAKE_CURRENT_BINARY_DIR}/linura-display-management-v1-protocol.c")
add_custom_command(OUTPUT "${DISPLAY_SERVER_HEADER}" "${DISPLAY_CLIENT_HEADER}" "${DISPLAY_CODE}"
    COMMAND "${WAYLAND_SCANNER}" server-header "${DISPLAY_XML}" "${DISPLAY_SERVER_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" client-header "${DISPLAY_XML}" "${DISPLAY_CLIENT_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" private-code "${DISPLAY_XML}" "${DISPLAY_CODE}"
    DEPENDS "${DISPLAY_XML}" VERBATIM)
add_library(linura-hyprland-display-wire STATIC
    wire_endpoint.cpp "${DISPLAY_SERVER_HEADER}" "${DISPLAY_CODE}")
target_include_directories(linura-hyprland-display-wire PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(linura-hyprland-display-wire PUBLIC linura-hyprland-display-supervisor)
target_compile_options(linura-hyprland-display-wire PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

set(PROTECTED_XML "${CMAKE_CURRENT_SOURCE_DIR}/protocols/linura-protected-display-v1.xml")
set(PROTECTED_SERVER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/linura-protected-display-v1-server-protocol.h")
set(PROTECTED_CLIENT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/linura-protected-display-v1-client-protocol.h")
set(PROTECTED_CODE "${CMAKE_CURRENT_BINARY_DIR}/linura-protected-display-v1-protocol.c")
add_custom_command(OUTPUT "${PROTECTED_SERVER_HEADER}" "${PROTECTED_CLIENT_HEADER}" "${PROTECTED_CODE}"
    COMMAND "${WAYLAND_SCANNER}" server-header "${PROTECTED_XML}" "${PROTECTED_SERVER_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" client-header "${PROTECTED_XML}" "${PROTECTED_CLIENT_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" private-code "${PROTECTED_XML}" "${PROTECTED_CODE}"
    DEPENDS "${PROTECTED_XML}" VERBATIM)
add_library(linura-hyprland-protected-wire STATIC
    protected_wire.cpp "${PROTECTED_SERVER_HEADER}" "${PROTECTED_CODE}")
target_include_directories(linura-hyprland-protected-wire PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(linura-hyprland-protected-wire PUBLIC linura-hyprland-display-supervisor)
target_compile_options(linura-hyprland-protected-wire PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
target_link_libraries(linura-hyprland-display-wire PUBLIC linura-hyprland-protected-wire)

add_library(linura-hyprland-display-owner STATIC owner_identity.cpp)
target_link_libraries(linura-hyprland-display-owner PUBLIC linura-hyprland-display-wire)
target_compile_options(linura-hyprland-display-owner PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

include(CTest)
if(BUILD_TESTING)
    set(LINURA_DISPLAY_RECOVERY_FIXTURE
        "${CMAKE_CURRENT_SOURCE_DIR}/../../crates/linura-core/src/display_recovery/fixtures/original-baseline.txt"
        CACHE FILEPATH "Canonical cross-language original display baseline fixture")
    if(NOT EXISTS "${LINURA_DISPLAY_RECOVERY_FIXTURE}" OR IS_SYMLINK "${LINURA_DISPLAY_RECOVERY_FIXTURE}")
        message(FATAL_ERROR "Missing or substituted canonical original display fixture")
    endif()
    add_executable(linura-hyprland-original-restoration-grant-tests tests/original_restoration_grant.cpp)
    target_link_libraries(linura-hyprland-original-restoration-grant-tests PRIVATE OpenSSL::Crypto)
    target_include_directories(linura-hyprland-original-restoration-grant-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(linura-hyprland-original-restoration-grant-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-original-restoration-grant COMMAND linura-hyprland-original-restoration-grant-tests
        "${LINURA_DISPLAY_RECOVERY_FIXTURE}")
    set_tests_properties(hyprland-original-restoration-grant PROPERTIES TIMEOUT 10)
    # A real DSO constructor and an executable C++ constructor must both
    # observe the filtered vector, before main or any native group reset.
    add_library(linura-native-environment-constructor SHARED tests/native_environment_constructor.cpp)
    add_executable(linura-native-environment-tests tests/native_environment.cpp)
    target_include_directories(linura-native-environment-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(linura-native-environment-tests PRIVATE linura-native-environment-constructor)
    foreach(target IN ITEMS linura-native-environment-constructor linura-native-environment-tests)
        target_compile_options(${target} PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    endforeach()
    add_test(NAME hyprland-native-environment-before-constructors COMMAND linura-native-environment-tests)
    # This known test-only DSO must also resolve when the product build disables
    # RPATH. The preinit hook removes LD_LIBRARY_PATH before either constructor.
    set_tests_properties(hyprland-native-environment-before-constructors PROPERTIES TIMEOUT 5
        ENVIRONMENT "LANG=C;__EGL_VENDOR_LIBRARY_FILENAMES=/untrusted/vendor.json;__EGL_VENDOR_LIBRARY_DIRS=/untrusted;GBM_BACKENDS_PATH=/untrusted;LINURA_NATIVE_ENV_TEST=discard;LD_LIBRARY_PATH=$<TARGET_FILE_DIR:linura-native-environment-constructor>")
    add_executable(linura-hyprland-process-privilege-tests tests/native_process_privilege.cpp)
    target_include_directories(linura-hyprland-process-privilege-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(linura-hyprland-process-privilege-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-native-process-privilege COMMAND linura-hyprland-process-privilege-tests)
    set_tests_properties(hyprland-native-process-privilege PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-startup-fence-tests tests/startup_fence.cpp)
    target_include_directories(linura-hyprland-startup-fence-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(linura-hyprland-startup-fence-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-startup-admission-lifetime COMMAND linura-hyprland-startup-fence-tests)
    set_tests_properties(hyprland-startup-admission-lifetime PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-recovery-rule-tests tests/recovery_rule.cpp)
    target_include_directories(linura-hyprland-recovery-rule-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(linura-hyprland-recovery-rule-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-recovery-rule-preimage COMMAND linura-hyprland-recovery-rule-tests)
    set_tests_properties(hyprland-recovery-rule-preimage PROPERTIES TIMEOUT 5)
    # Mandatory in the real pinned compositor build. Portable mechanism suites
    # alone do not exercise GLES or qualify actual rendered scanout storage.
    if(TARGET hyprland_lib)
        pkg_check_modules(NATIVE_DRM REQUIRED IMPORTED_TARGET libdrm)
        add_executable(linura-native-kernel-scanout-tests tests/native_kernel_scanout.cpp)
        target_include_directories(linura-native-kernel-scanout-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(linura-native-kernel-scanout-tests PRIVATE PkgConfig::NATIVE_DRM)
        target_compile_options(linura-native-kernel-scanout-tests PRIVATE
            -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
        add_test(NAME hyprland-native-kernel-scanout COMMAND linura-native-kernel-scanout-tests)
        set_tests_properties(hyprland-native-kernel-scanout PROPERTIES TIMEOUT 5)
        pkg_check_modules(PROTECTED_EGL REQUIRED IMPORTED_TARGET egl>=1.5 glesv2>=3.2)
        add_executable(linura-hyprland-protected-opaque-buffer-tests tests/protected_opaque_buffer.cpp)
        target_include_directories(linura-hyprland-protected-opaque-buffer-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(linura-hyprland-protected-opaque-buffer-tests PRIVATE PkgConfig::PROTECTED_EGL)
        target_compile_options(linura-hyprland-protected-opaque-buffer-tests PRIVATE
            -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
        add_test(NAME hyprland-protected-opaque-buffer COMMAND linura-hyprland-protected-opaque-buffer-tests)
        set_tests_properties(hyprland-protected-opaque-buffer PROPERTIES TIMEOUT 15
            ENVIRONMENT "EGL_PLATFORM=surfaceless;LIBGL_ALWAYS_SOFTWARE=1")
    endif()
    add_executable(linura-hyprland-protected-scope-history-tests tests/protected_scope_history.cpp)
    target_link_libraries(linura-hyprland-protected-scope-history-tests PRIVATE linura-hyprland-display-mechanism)
    target_compile_options(linura-hyprland-protected-scope-history-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-protected-scope-history COMMAND linura-hyprland-protected-scope-history-tests)
    set_tests_properties(hyprland-protected-scope-history PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-protected-frame-tests tests/protected_frame.cpp)
    target_link_libraries(linura-hyprland-protected-frame-tests PRIVATE linura-hyprland-display-mechanism)
    target_compile_options(linura-hyprland-protected-frame-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-protected-frame-boundary COMMAND linura-hyprland-protected-frame-tests)
    set_tests_properties(hyprland-protected-frame-boundary PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-protected-retirement-tests tests/protected_input_retirement.cpp)
    target_link_libraries(linura-hyprland-protected-retirement-tests PRIVATE linura-hyprland-display-mechanism)
    target_compile_options(linura-hyprland-protected-retirement-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-protected-input-retirement COMMAND linura-hyprland-protected-retirement-tests)
    set_tests_properties(hyprland-protected-input-retirement PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-protected-interaction-tests tests/protected_interaction.cpp)
    target_link_libraries(linura-hyprland-protected-interaction-tests PRIVATE linura-hyprland-display-mechanism)
    target_compile_options(linura-hyprland-protected-interaction-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-protected-interaction-boundary COMMAND linura-hyprland-protected-interaction-tests)
    set_tests_properties(hyprland-protected-interaction-boundary PROPERTIES TIMEOUT 5)
    add_test(NAME hyprland-display-integration-identity
        COMMAND "${CMAKE_COMMAND}"
            "-DNATIVE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DTEST_OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_identity.cmake")
    set_tests_properties(hyprland-display-integration-identity PROPERTIES TIMEOUT 10)
    add_executable(linura-hyprland-display-inhibitor-tests tests/native_inhibitor_fd.cpp)
    target_include_directories(linura-hyprland-display-inhibitor-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(linura-hyprland-display-inhibitor-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-display-inhibitor-lifetime COMMAND linura-hyprland-display-inhibitor-tests)
    set_tests_properties(hyprland-display-inhibitor-lifetime PROPERTIES TIMEOUT 5)
    find_package(Threads REQUIRED)
    pkg_check_modules(WAYLAND_CLIENT REQUIRED IMPORTED_TARGET wayland-client>=1.22)
    add_executable(linura-hyprland-display-owner-tests tests/native_owner_admission.cpp)
    target_link_libraries(linura-hyprland-display-owner-tests PRIVATE linura-hyprland-display-owner)
    target_compile_options(linura-hyprland-display-owner-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-display-owner-admission COMMAND linura-hyprland-display-owner-tests)
    set_tests_properties(hyprland-display-owner-admission PROPERTIES TIMEOUT 5)
    add_executable(linura-hyprland-protected-wire-tests tests/protected_wire.cpp "${PROTECTED_CLIENT_HEADER}")
    target_link_libraries(linura-hyprland-protected-wire-tests PRIVATE
        linura-hyprland-protected-wire PkgConfig::WAYLAND_CLIENT Threads::Threads)
    target_compile_options(linura-hyprland-protected-wire-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-protected-display-wire-boundary COMMAND linura-hyprland-protected-wire-tests)
    set_tests_properties(hyprland-protected-display-wire-boundary PROPERTIES TIMEOUT 15)
    add_executable(linura-hyprland-display-wire-tests tests/wire_endpoint.cpp "${DISPLAY_CLIENT_HEADER}")
    target_link_libraries(linura-hyprland-display-wire-tests PRIVATE
        linura-hyprland-display-wire PkgConfig::WAYLAND_CLIENT Threads::Threads)
    target_compile_options(linura-hyprland-display-wire-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-display-wire-boundary COMMAND linura-hyprland-display-wire-tests)
    set_tests_properties(hyprland-display-wire-boundary PROPERTIES TIMEOUT 15)

    add_executable(linura-hyprland-display-mechanism-tests tests/display_transaction.cpp)
    target_link_libraries(linura-hyprland-display-mechanism-tests PRIVATE linura-hyprland-display-mechanism)
    target_compile_options(linura-hyprland-display-mechanism-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-display-mechanism-boundary COMMAND linura-hyprland-display-mechanism-tests)
    set_tests_properties(hyprland-display-mechanism-boundary PROPERTIES TIMEOUT 10)

    add_executable(linura-hyprland-display-supervisor-tests tests/compositor_display_service.cpp)
    target_link_libraries(linura-hyprland-display-supervisor-tests PRIVATE linura-hyprland-display-supervisor)
    target_compile_options(linura-hyprland-display-supervisor-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_test(NAME hyprland-display-supervisor-boundary COMMAND linura-hyprland-display-supervisor-tests)
    set_tests_properties(hyprland-display-supervisor-boundary PROPERTIES TIMEOUT 10)
endif()
