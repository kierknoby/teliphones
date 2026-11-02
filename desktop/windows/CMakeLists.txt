cmake_minimum_required(VERSION 3.16)
project(TeliphonesDesktopCore CXX)

# Portable core and its tests only. The Windows application itself is built with TELIPHONES.sln (Visual Studio + MFC).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(teliphones_core STATIC
    src/core/CommandLine.cpp
    src/core/ConnectionHealth.cpp
    src/core/Encoding.cpp
    src/core/Json.cpp
    src/core/Launchers.cpp
    src/core/Monitor.cpp
    src/core/Pairing.cpp
    src/core/Profiles.cpp
    src/core/SessionDiagnostics.cpp
    src/core/TunnelConfig.cpp
    src/core/Validation.cpp
    src/core/WireGuardSetup.cpp)
if(MSVC)
    target_compile_options(teliphones_core PUBLIC /W4 /WX /utf-8)
else()
    target_compile_options(teliphones_core PUBLIC -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(core_tests tests/core_tests.cpp)
target_link_libraries(core_tests PRIVATE teliphones_core)
find_package(Threads REQUIRED)
add_executable(session_diagnostics_tests tests/session_diagnostics_tests.cpp)
target_link_libraries(session_diagnostics_tests PRIVATE teliphones_core Threads::Threads)
add_executable(contract_tool tests/contract_tool.cpp)
target_link_libraries(contract_tool PRIVATE teliphones_core)

enable_testing()
add_test(NAME core_tests COMMAND core_tests)
add_test(NAME session_diagnostics COMMAND session_diagnostics_tests)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME build_layout COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_layout_test.py)
    add_test(NAME contract_check COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/contract_check.py $<TARGET_FILE:contract_tool>)
endif()
