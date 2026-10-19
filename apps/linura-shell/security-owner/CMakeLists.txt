cmake_minimum_required(VERSION 3.24)
project(linura-security-owner VERSION 0.10 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core DBus Gui Qml Quick QuickControls2)
set(CMAKE_AUTOMOC ON)

# Private native security owner, not the ordinary shell bridge. Installation is
# not qualification; the native runtime still requires exact protected startup.
add_library(linura-security-owner-mechanisms STATIC
    native_scope.cpp
    native_transition_fence.cpp native_transition_fence.h
    native_sleep_fence.cpp native_sleep_fence.h native_sleep_probe.cpp
    native_launch.cpp
    native_prompt.cpp native_prompt.h
    native_deadline.cpp
    native_approval.cpp
    lock_mechanism.cpp
    native_lock_protocol.cpp native_lock_protocol.h
    native_managed_lock_backend.cpp native_managed_lock_backend.h
    secret_buffer.cpp
    process_guard.cpp
    peer_guard.cpp
    session_bootstrap.cpp
    compositor_probe.cpp
)
target_link_libraries(linura-security-owner-mechanisms PUBLIC Qt6::Core Qt6::DBus)
target_include_directories(linura-security-owner-mechanisms PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(linura-security-owner-mechanisms PUBLIC QT_NO_KEYWORDS)
target_compile_options(linura-security-owner-mechanisms PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion
)

add_library(linura-security-owner-input STATIC secret_entry.cpp secret_entry.h
    native_accessibility.cpp native_accessibility.h)
target_link_libraries(linura-security-owner-input PUBLIC
    linura-security-owner-mechanisms Qt6::Gui Qt6::Quick
)
target_compile_options(linura-security-owner-input PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion
)

# Embed the same first-party semantic UI source into the extension-free private
# renderer. Runtime QML imports never search a source tree or user module path.
set(LINURA_SECURITY_OWNER_UI_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ui" CACHE PATH
    "Canonical first-party Linura UI source directory")
set(presentation_ui_sources)
foreach(component IN ITEMS LinuraTheme LinuraSurface LinuraText LinuraButton)
    set(source "${LINURA_SECURITY_OWNER_UI_SOURCE_DIR}/${component}.qml")
    set_source_files_properties("${source}" PROPERTIES QT_RESOURCE_ALIAS "ui/${component}.qml")
    list(APPEND presentation_ui_sources "${source}")
endforeach()
add_library(linura-security-owner-presentation STATIC native_presentation.cpp native_presentation.h)
target_link_libraries(linura-security-owner-presentation PUBLIC
    linura-security-owner-input Qt6::Qml Qt6::Quick Qt6::QuickControls2)
qt_add_resources(linura-security-owner-presentation linura_security_owner_presentation
    PREFIX "/linura/security-owner" FILES LockPresentation.qml ${presentation_ui_sources})
target_compile_options(linura-security-owner-presentation PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

# Bindings are generated from the official distribution XML, never vendored.
find_package(PkgConfig REQUIRED)
pkg_check_modules(WAYLAND_CLIENT REQUIRED IMPORTED_TARGET wayland-client)
pkg_check_modules(WAYLAND_PROTOCOLS REQUIRED wayland-protocols>=1.34)
pkg_check_modules(XKBCOMMON REQUIRED IMPORTED_TARGET xkbcommon>=1.6)
pkg_get_variable(WAYLAND_PROTOCOL_DIR wayland-protocols pkgdatadir)
find_program(WAYLAND_SCANNER wayland-scanner REQUIRED)
set(LOCK_XML "${WAYLAND_PROTOCOL_DIR}/staging/ext-session-lock/ext-session-lock-v1.xml")
set(LOCK_HEADER "${CMAKE_CURRENT_BINARY_DIR}/ext-session-lock-v1-client-protocol.h")
set(LOCK_CODE "${CMAKE_CURRENT_BINARY_DIR}/ext-session-lock-v1-protocol.c")
add_custom_command(OUTPUT "${LOCK_HEADER}" "${LOCK_CODE}"
    COMMAND "${WAYLAND_SCANNER}" client-header "${LOCK_XML}" "${LOCK_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" private-code "${LOCK_XML}" "${LOCK_CODE}"
    DEPENDS "${LOCK_XML}" VERBATIM)
set(XDG_XML "${WAYLAND_PROTOCOL_DIR}/stable/xdg-shell/xdg-shell.xml")
set(XDG_HEADER "${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-client-protocol.h")
set(XDG_CODE "${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-protocol.c")
add_custom_command(OUTPUT "${XDG_HEADER}" "${XDG_CODE}"
    COMMAND "${WAYLAND_SCANNER}" client-header "${XDG_XML}" "${XDG_HEADER}"
    COMMAND "${WAYLAND_SCANNER}" private-code "${XDG_XML}" "${XDG_CODE}"
    DEPENDS "${XDG_XML}" VERBATIM)
add_library(linura-security-owner-wayland STATIC native_wayland_lock.cpp native_wayland_lock.h
    native_wayland_readiness.cpp native_wayland_readiness.h
    native_keyboard.cpp native_keyboard.h
    "${LOCK_HEADER}" "${LOCK_CODE}" "${XDG_HEADER}" "${XDG_CODE}")
target_include_directories(linura-security-owner-wayland PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(linura-security-owner-wayland PUBLIC
    linura-security-owner-mechanisms linura-security-owner-input Qt6::Gui
    PkgConfig::WAYLAND_CLIENT PkgConfig::XKBCOMMON)
target_compile_options(linura-security-owner-wayland PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)

# The authentication target uses actual native headers. The development-only
# mechanisms/input mode has no authentication substitute and installs no runtime.
option(LINURA_SECURITY_OWNER_NATIVE_AUTH "Build the official native Polkit/PAM adapter" ON)
if(LINURA_SECURITY_OWNER_NATIVE_AUTH)
    set(LINURA_SECURITY_OWNER_CONTRACT
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../interfaces/dbus/org.linura.SecurityOwner1.xml"
        CACHE FILEPATH "Canonical private native-owner D-Bus contract")
    if(NOT EXISTS "${LINURA_SECURITY_OWNER_CONTRACT}")
        message(FATAL_ERROR "Canonical org.linura.SecurityOwner1 contract is required")
    endif()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(POLKIT_AGENT REQUIRED IMPORTED_TARGET polkit-agent-1)
    add_library(linura-security-owner-auth STATIC
        native_assistive.cpp native_assistive.h native_assistive_model.h
        polkit_conversation.cpp polkit_conversation.h
        authentication_agent.cpp authentication_agent.h
    )
    target_link_libraries(linura-security-owner-auth PUBLIC
        linura-security-owner-input PkgConfig::POLKIT_AGENT
    )
    target_compile_options(linura-security-owner-auth PRIVATE
        -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion
    )
    add_library(linura-security-owner-runtime STATIC
        native_startup.cpp native_startup.h native_runtime.cpp native_runtime.h
        native_unlock_status.cpp native_unlock_status.h
        native_endpoint.cpp native_endpoint.h)
    target_link_libraries(linura-security-owner-runtime PUBLIC
        linura-security-owner-auth linura-security-owner-wayland linura-security-owner-presentation)
    target_compile_options(linura-security-owner-runtime PRIVATE
        -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    add_executable(linura-security-owner main.cpp)
    target_link_libraries(linura-security-owner PRIVATE linura-security-owner-runtime)
    target_compile_options(linura-security-owner PRIVATE
        -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
    set(LINURA_SECURITY_OWNER_PACKAGING_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../packaging"
        CACHE PATH "Canonical repository-owned native-owner deployment assets")
    install(TARGETS linura-security-owner RUNTIME DESTINATION lib/linura)
    install(FILES "${LINURA_SECURITY_OWNER_PACKAGING_DIR}/security-owner/fonts.conf"
        DESTINATION share/linura/security-owner)
    install(FILES
        "${LINURA_SECURITY_OWNER_PACKAGING_DIR}/systemd/system/linura-security-owner@.service"
        "${LINURA_SECURITY_OWNER_PACKAGING_DIR}/systemd/system/linura-security-owner@.path"
        DESTINATION lib/systemd/system)
    install(FILES "${LINURA_SECURITY_OWNER_PACKAGING_DIR}/systemd/system/user@.service.d/50-linura-security-owner.conf"
        DESTINATION lib/systemd/system/user@.service.d)
    install(FILES "${LINURA_SECURITY_OWNER_CONTRACT}" DESTINATION share/dbus-1/interfaces)
    # Never set capabilities on a developer installation or through CMake.
    # The target image's fixed package hook does this after final root ownership.
endif()

include(CTest)
if(BUILD_TESTING)
    pkg_check_modules(WAYLAND_SERVER REQUIRED IMPORTED_TARGET wayland-server)
    add_executable(linura-security-owner-readiness-tests tests/native_wayland_readiness.cpp)
    target_link_libraries(linura-security-owner-readiness-tests PRIVATE
        linura-security-owner-wayland PkgConfig::WAYLAND_SERVER)
    target_compile_options(linura-security-owner-readiness-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-compositor-readiness COMMAND linura-security-owner-readiness-tests)
    set_tests_properties(security-owner-compositor-readiness PROPERTIES TIMEOUT 10)
    add_executable(linura-security-owner-sleep-tests tests/native_sleep_fence.cpp)
    target_link_libraries(linura-security-owner-sleep-tests PRIVATE linura-security-owner-mechanisms)
    target_compile_options(linura-security-owner-sleep-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-native-sleep-coverage-fence COMMAND linura-security-owner-sleep-tests)
    set_tests_properties(security-owner-native-sleep-coverage-fence PROPERTIES TIMEOUT 20)
    add_executable(linura-security-owner-transition-tests tests/native_transition_fence.cpp)
    target_link_libraries(linura-security-owner-transition-tests PRIVATE linura-security-owner-mechanisms)
    target_compile_options(linura-security-owner-transition-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-transition-coverage-fence COMMAND linura-security-owner-transition-tests)
    set_tests_properties(security-owner-transition-coverage-fence PROPERTIES TIMEOUT 20)
    add_executable(linura-security-owner-launch-tests tests/native_launch.cpp)
    target_link_libraries(linura-security-owner-launch-tests PRIVATE linura-security-owner-mechanisms)
    target_compile_options(linura-security-owner-launch-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-launch-wire-boundary COMMAND linura-security-owner-launch-tests)
    set_tests_properties(security-owner-launch-wire-boundary PROPERTIES TIMEOUT 20)
    add_executable(linura-security-owner-presentation-tests tests/native_presentation.cpp)
    target_link_libraries(linura-security-owner-presentation-tests PRIVATE linura-security-owner-presentation)
    target_compile_options(linura-security-owner-presentation-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-native-presentation COMMAND linura-security-owner-presentation-tests)
    set_tests_properties(security-owner-native-presentation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 20)
    set(LOCK_SERVER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/ext-session-lock-v1-server-protocol.h")
    add_custom_command(OUTPUT "${LOCK_SERVER_HEADER}"
        COMMAND "${WAYLAND_SCANNER}" server-header "${LOCK_XML}" "${LOCK_SERVER_HEADER}"
        DEPENDS "${LOCK_XML}" VERBATIM)
    set(XDG_SERVER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-server-protocol.h")
    add_custom_command(OUTPUT "${XDG_SERVER_HEADER}"
        COMMAND "${WAYLAND_SCANNER}" server-header "${XDG_XML}" "${XDG_SERVER_HEADER}"
        DEPENDS "${XDG_XML}" VERBATIM)
    add_executable(linura-security-owner-wayland-tests tests/native_wayland_lock.cpp
        "${LOCK_SERVER_HEADER}" "${XDG_SERVER_HEADER}")
    target_include_directories(linura-security-owner-wayland-tests PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(linura-security-owner-wayland-tests PRIVATE
        linura-security-owner-wayland linura-security-owner-presentation PkgConfig::WAYLAND_SERVER)
    target_compile_options(linura-security-owner-wayland-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-wayland-wire-boundary COMMAND linura-security-owner-wayland-tests)
    set_tests_properties(security-owner-wayland-wire-boundary PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
    add_executable(linura-security-owner-mechanism-tests tests/mechanisms.cpp)
    target_link_libraries(linura-security-owner-mechanism-tests PRIVATE linura-security-owner-mechanisms)
    target_compile_options(linura-security-owner-mechanism-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-mechanisms COMMAND linura-security-owner-mechanism-tests)
    add_executable(linura-security-owner-lock-protocol-tests tests/native_lock_protocol.cpp)
    target_link_libraries(linura-security-owner-lock-protocol-tests PRIVATE linura-security-owner-mechanisms)
    target_compile_options(linura-security-owner-lock-protocol-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-lock-protocol-boundary COMMAND linura-security-owner-lock-protocol-tests)
    set_tests_properties(security-owner-mechanisms security-owner-lock-protocol-boundary
        PROPERTIES TIMEOUT 20)
    add_executable(linura-security-owner-input-tests tests/protected_input.cpp)
    target_link_libraries(linura-security-owner-input-tests PRIVATE linura-security-owner-input)
    target_compile_options(linura-security-owner-input-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME security-owner-protected-input COMMAND linura-security-owner-input-tests)
    set_tests_properties(security-owner-protected-input PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 20
    )
    if(LINURA_SECURITY_OWNER_NATIVE_AUTH)
        add_executable(linura-security-owner-assistive-tests tests/native_assistive.cpp)
        target_link_libraries(linura-security-owner-assistive-tests PRIVATE linura-security-owner-auth)
        target_compile_options(linura-security-owner-assistive-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME security-owner-assistive-metadata-boundary COMMAND linura-security-owner-assistive-tests)
        set_tests_properties(security-owner-assistive-metadata-boundary PROPERTIES TIMEOUT 20)
        add_executable(linura-security-owner-runtime-tests tests/native_runtime.cpp)
        target_link_libraries(linura-security-owner-runtime-tests PRIVATE linura-security-owner-runtime)
        target_compile_options(linura-security-owner-runtime-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME security-owner-runtime-boundary COMMAND linura-security-owner-runtime-tests
            "${LINURA_SECURITY_OWNER_CONTRACT}" "$<TARGET_FILE:linura-security-owner>")
        set_tests_properties(security-owner-runtime-boundary PROPERTIES TIMEOUT 20)
        add_executable(linura-security-owner-auth-tests tests/authentication_boundary.cpp)
        target_link_libraries(linura-security-owner-auth-tests PRIVATE linura-security-owner-auth)
        target_compile_options(linura-security-owner-auth-tests PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME security-owner-authentication-boundary COMMAND linura-security-owner-auth-tests)
        set_tests_properties(security-owner-authentication-boundary PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 20
        )
    endif()
endif()
