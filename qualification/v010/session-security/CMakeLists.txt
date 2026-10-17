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
include(CTest)
if(BUILD_TESTING)
    add_executable(linura-s17-assistive-denial-test native-assistive-denial-test.cpp)
    target_link_libraries(linura-s17-assistive-denial-test PRIVATE Qt6::Core)
    target_compile_options(linura-s17-assistive-denial-test PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME native-assistive-denial-classification
        COMMAND linura-s17-assistive-denial-test)
    set_tests_properties(native-assistive-denial-classification PROPERTIES TIMEOUT 10)
endif()
