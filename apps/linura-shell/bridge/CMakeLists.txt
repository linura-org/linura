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
)

target_link_libraries(linura-shell-bridge PRIVATE
    Qt6::Core
    Qt6::DBus
    Qt6::Qml
)

target_include_directories(linura-shell-bridge PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

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
