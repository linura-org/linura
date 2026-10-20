cmake_minimum_required(VERSION 3.24)
project(linura-security-owner VERSION 0.10 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core DBus Gui Quick)
find_package(PkgConfig REQUIRED)
pkg_check_modules(WAYLAND_CLIENT REQUIRED IMPORTED_TARGET wayland-client)

# Foundation only: exact native session/compositor identity, bounded startup and
# the lock state machine. Authentication, protected input and power transitions
# are deliberately composed by later stacked changes.
add_library(linura-security-owner-foundation STATIC
    native_scope.cpp
    native_launch.cpp
    native_deadline.cpp
    lock_mechanism.cpp
    process_guard.cpp
    native_startup.cpp
    session_bootstrap.cpp
    compositor_probe.cpp
    native_wayland_readiness.cpp
)
target_include_directories(linura-security-owner-foundation PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(linura-security-owner-foundation PUBLIC
    Qt6::Core Qt6::DBus Qt6::Gui Qt6::Quick PkgConfig::WAYLAND_CLIENT
)
target_compile_definitions(linura-security-owner-foundation PUBLIC QT_NO_KEYWORDS)
target_compile_options(linura-security-owner-foundation PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion
)

include(CTest)
if(BUILD_TESTING)
    pkg_check_modules(WAYLAND_SERVER REQUIRED IMPORTED_TARGET wayland-server)
    add_executable(linura-security-owner-readiness-tests tests/native_wayland_readiness.cpp)
    target_link_libraries(linura-security-owner-readiness-tests PRIVATE
        linura-security-owner-foundation PkgConfig::WAYLAND_SERVER
    )
    target_compile_options(linura-security-owner-readiness-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror
    )
    add_test(NAME security-owner-compositor-readiness
        COMMAND linura-security-owner-readiness-tests
    )
    set_tests_properties(security-owner-compositor-readiness PROPERTIES TIMEOUT 10)
endif()
