cmake_minimum_required(VERSION 3.24)
project(linura-ui VERSION 0.10 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Qml Quick QuickControls2)
qt_standard_project_setup()

qt_add_library(linura-ui SHARED)

qt_add_qml_module(linura-ui
    URI org.linura.UI
    VERSION 1.0
    PLUGIN_TARGET linura-uiplugin
    OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/qml/org/linura/UI"
    QML_FILES
        LinuraTheme.qml
        LinuraSurface.qml
        LinuraText.qml
        LinuraButton.qml
        LinuraSlider.qml
        LinuraIconButton.qml
        LinuraSwitch.qml
        LinuraTextField.qml
        LinuraActionRow.qml
        LinuraCard.qml
        LinuraStatus.qml
        LinuraDivider.qml
        LinuraPopover.qml
        LinuraDialog.qml
)

target_link_libraries(linura-ui PRIVATE
    Qt6::Core
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
)

set(LINURA_UI_QML_INSTALL_DIR "lib/qt6/qml/org/linura/UI")

# The generated QML plugin links the backing linura-ui shared library. Keep the
# module self-contained so QML loading never depends on a global linker cache.
set_target_properties(linura-uiplugin PROPERTIES
    INSTALL_RPATH "$ORIGIN"
)

install(
    DIRECTORY "${CMAKE_BINARY_DIR}/qml/org/linura/UI/"
    DESTINATION "${LINURA_UI_QML_INSTALL_DIR}"
    USE_SOURCE_PERMISSIONS
)

install(
    TARGETS linura-ui linura-uiplugin
    LIBRARY DESTINATION "${LINURA_UI_QML_INSTALL_DIR}"
    RUNTIME DESTINATION "${LINURA_UI_QML_INSTALL_DIR}"
    ARCHIVE DESTINATION "${LINURA_UI_QML_INSTALL_DIR}"
)
