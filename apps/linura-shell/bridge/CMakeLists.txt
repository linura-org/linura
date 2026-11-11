cmake_minimum_required(VERSION 3.24)
project(linura-shell-bridge VERSION 0.10 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core DBus Qml)
qt_standard_project_setup()

qt_add_library(linura-shell-bridge SHARED)

qt_add_qml_module(linura-shell-bridge
    URI org.linura.ShellBridge
    VERSION 1.0
    PLUGIN_TARGET linura-shell-bridgeplugin
    OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/qml/org/linura/ShellBridge"
    SOURCES
        audio_session_controller.h
        audio_session_controller.cpp
        session_controller.h
        session_controller.cpp
        session_receipt.h
        session_receipt.cpp
        network_observation_contract.h
        network_observation_contract.cpp
        network_overview_controller.h
        network_overview_controller.cpp
)

target_link_libraries(linura-shell-bridge PRIVATE
    Qt6::Core
    Qt6::DBus
    Qt6::Qml
)

target_include_directories(linura-shell-bridge PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

include(CTest)
if(BUILD_TESTING)
    add_executable(linura-session-client-tests tests/session_receipt.cpp session_receipt.cpp)
    target_include_directories(linura-session-client-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(linura-session-client-tests PRIVATE Qt6::Core)
    target_compile_options(linura-session-client-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME session-client-receipt COMMAND linura-session-client-tests)
    set_tests_properties(session-client-receipt PROPERTIES TIMEOUT 20)
    add_executable(linura-session-tracking-tests tests/session_tracking.cpp
        session_controller.h session_controller.cpp session_receipt.cpp)
    target_include_directories(linura-session-tracking-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(linura-session-tracking-tests PRIVATE Qt6::Core Qt6::DBus Qt6::Qml)
    target_compile_definitions(linura-session-tracking-tests PRIVATE LINURA_SESSION_TRACKING_TESTS)
    target_compile_options(linura-session-tracking-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME session-client-tracking COMMAND linura-session-tracking-tests)
    set_tests_properties(session-client-tracking PROPERTIES TIMEOUT 20)
    add_executable(linura-network-observation-tests
        tests/network_observation_contract.cpp network_observation_contract.cpp)
    target_include_directories(linura-network-observation-tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(linura-network-observation-tests PRIVATE Qt6::Core)
    target_compile_options(linura-network-observation-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME network-observation-classification
        COMMAND linura-network-observation-tests)
    set_tests_properties(network-observation-classification PROPERTIES TIMEOUT 20)

    find_package(Qt6 6.4 REQUIRED COMPONENTS Gui Quick)
    add_executable(linura-network-surface-tests tests/network_surface.cpp)
    target_link_libraries(linura-network-surface-tests PRIVATE
        Qt6::Gui Qt6::Qml Qt6::Quick)
    target_compile_options(linura-network-surface-tests PRIVATE
        -UNDEBUG -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME network-client-surface COMMAND linura-network-surface-tests
        "${CMAKE_CURRENT_SOURCE_DIR}/../plugins/network/NetworkStatusCard.qml")
    set_tests_properties(network-client-surface PROPERTIES TIMEOUT 30
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software")

    add_executable(linura-session-surface-tests tests/session_surface.cpp)
    target_link_libraries(linura-session-surface-tests PRIVATE Qt6::Gui Qt6::Qml Qt6::Quick)
    target_compile_options(linura-session-surface-tests PRIVATE -Wall -Wextra -Werror)
    # Install/build both modules before running. This CPU component fixture is
    # not native Wayland pointer, accessibility-runner or visual evidence.
    add_test(NAME session-client-surface COMMAND linura-session-surface-tests
        "${CMAKE_CURRENT_SOURCE_DIR}/../plugins/session/SessionControls.qml")
    set_tests_properties(session-client-surface PROPERTIES TIMEOUT 30
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software")
endif()

set(LINURA_SHELL_BRIDGE_QML_INSTALL_DIR "lib/qt6/qml/org/linura/ShellBridge")

# The generated QML plugin links the backing linura-shell-bridge shared library.
# Keep the installed module self-contained instead of depending on linker-cache
# state that is unrelated to the QML import path.
set_target_properties(linura-shell-bridgeplugin PROPERTIES
    INSTALL_RPATH "$ORIGIN"
)

install(
    DIRECTORY "${CMAKE_BINARY_DIR}/qml/org/linura/ShellBridge/"
    DESTINATION "${LINURA_SHELL_BRIDGE_QML_INSTALL_DIR}"
    USE_SOURCE_PERMISSIONS
)

install(
    TARGETS linura-shell-bridge linura-shell-bridgeplugin
    LIBRARY DESTINATION "${LINURA_SHELL_BRIDGE_QML_INSTALL_DIR}"
    RUNTIME DESTINATION "${LINURA_SHELL_BRIDGE_QML_INSTALL_DIR}"
    ARCHIVE DESTINATION "${LINURA_SHELL_BRIDGE_QML_INSTALL_DIR}"
)
