cmake_minimum_required(VERSION 3.16)
project(TeliphonesDesktopCore C CXX)

# Portable core and its tests only. The Windows application itself is built with TELIPHONES.sln (Visual Studio + MFC).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TELIPHONES_CORE_SOURCES
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
    src/core/TunnelLifecycle.cpp
    src/core/Validation.cpp
    src/core/WireGuardSetup.cpp
    src/core/WorkstationHeartbeat.cpp)
add_library(teliphones_core STATIC ${TELIPHONES_CORE_SOURCES})
if(MSVC)
    set(TELIPHONES_WARNING_OPTIONS /W4 /WX /utf-8)
else()
    set(TELIPHONES_WARNING_OPTIONS -Wall -Wextra -Wpedantic -Werror)
endif()
target_compile_options(teliphones_core PUBLIC ${TELIPHONES_WARNING_OPTIONS})

set(LIBVTERM_SOURCES
    third_party/libvterm/src/encoding.c
    third_party/libvterm/src/keyboard.c
    third_party/libvterm/src/mouse.c
    third_party/libvterm/src/parser.c
    third_party/libvterm/src/pen.c
    third_party/libvterm/src/screen.c
    third_party/libvterm/src/state.c
    third_party/libvterm/src/unicode.c
    third_party/libvterm/src/vterm.c)
add_library(teliphones_vterm STATIC ${LIBVTERM_SOURCES})
target_include_directories(teliphones_vterm PUBLIC third_party/libvterm/include PRIVATE third_party/libvterm/src)
set_target_properties(teliphones_vterm PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
add_library(teliphones_terminal STATIC src/core/TerminalEmulator.cpp)
target_include_directories(teliphones_terminal PUBLIC src/core third_party/libvterm/include)
target_link_libraries(teliphones_terminal PUBLIC teliphones_vterm)
target_compile_options(teliphones_terminal PRIVATE ${TELIPHONES_WARNING_OPTIONS})
add_executable(terminal_emulator_tests tests/terminal_emulator_tests.cpp)
target_link_libraries(terminal_emulator_tests PRIVATE teliphones_terminal)
target_compile_options(terminal_emulator_tests PRIVATE ${TELIPHONES_WARNING_OPTIONS})

add_executable(core_tests tests/core_tests.cpp)
target_link_libraries(core_tests PRIVATE teliphones_core)
find_package(Threads REQUIRED)
add_executable(session_diagnostics_tests tests/session_diagnostics_tests.cpp)
target_link_libraries(session_diagnostics_tests PRIVATE teliphones_core Threads::Threads)
add_executable(contract_tool tests/contract_tool.cpp)
target_link_libraries(contract_tool PRIVATE teliphones_core)
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
add_library(teliphones_connect_protection STATIC src/core/ConnectProtection.cpp)
target_link_libraries(teliphones_connect_protection PUBLIC teliphones_core OpenSSL::Crypto)
target_compile_options(teliphones_connect_protection PRIVATE ${TELIPHONES_WARNING_OPTIONS})
add_executable(connect_protection_tests tests/connect_protection_tests.cpp)
target_link_libraries(connect_protection_tests PRIVATE teliphones_connect_protection)
add_library(teliphones_ssh_crypto STATIC src/core/SshCrypto.cpp)
target_include_directories(teliphones_ssh_crypto PUBLIC src/core)
target_link_libraries(teliphones_ssh_crypto PUBLIC teliphones_core OpenSSL::Crypto)
add_executable(ssh_crypto_tool tests/ssh_crypto_tool.cpp)
target_link_libraries(ssh_crypto_tool PRIVATE teliphones_ssh_crypto)
if(WIN32)
    set(WIREGUARD_NT "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/wireguard-nt")
    add_custom_target(verify_wireguard_nt
        COMMAND powershell.exe -NoProfile -NonInteractive
            -File "${CMAKE_CURRENT_SOURCE_DIR}/restore-wireguard-nt.ps1" -CheckOnly)
    add_executable(wireguard_nt_native_tests tests/wireguard_nt_native_tests.cpp
        src/platform/WireGuardNt.cpp src/platform/WireGuard.cpp src/platform/Win.cpp)
    add_dependencies(wireguard_nt_native_tests verify_wireguard_nt)
    target_include_directories(wireguard_nt_native_tests PRIVATE "${WIREGUARD_NT}/include")
    target_compile_definitions(wireguard_nt_native_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
    target_compile_options(wireguard_nt_native_tests PRIVATE ${TELIPHONES_WARNING_OPTIONS})
    target_link_libraries(wireguard_nt_native_tests PRIVATE teliphones_core
        advapi32 bcrypt crypt32 iphlpapi shell32 ole32 wintrust uuid)
    add_custom_command(TARGET wireguard_nt_native_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${WIREGUARD_NT}/bin/amd64/wireguard.dll"
                "$<TARGET_FILE_DIR:wireguard_nt_native_tests>/wireguard.dll")
    add_executable(tunnel_startup_native_tests tests/tunnel_startup_native_tests.cpp)
    target_compile_definitions(tunnel_startup_native_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
    target_compile_options(tunnel_startup_native_tests PRIVATE ${TELIPHONES_WARNING_OPTIONS})
    target_link_libraries(tunnel_startup_native_tests PRIVATE advapi32)
    # Only the loopback integration fixture accepts its reserved local source.
    # Production core/tests retain the deployed non-loopback route policy.
    add_library(teliphones_fixture_core STATIC ${TELIPHONES_CORE_SOURCES})
    target_compile_definitions(teliphones_fixture_core PRIVATE TELIPHONES_SSH_LOOPBACK_FIXTURE)
    target_compile_options(teliphones_fixture_core PUBLIC ${TELIPHONES_WARNING_OPTIONS})
    add_library(teliphones_fixture_crypto STATIC src/core/SshCrypto.cpp src/core/ConnectProtection.cpp)
    target_include_directories(teliphones_fixture_crypto PUBLIC src/core)
    target_link_libraries(teliphones_fixture_crypto PUBLIC teliphones_fixture_core OpenSSL::Crypto)
    add_executable(ssh_native_host tests/ssh_native_host.cpp tests/fixture_security.cpp src/platform/SshAgent.cpp src/platform/SshSession.cpp
        src/platform/Ssh.cpp src/platform/Applications.cpp src/platform/Services.cpp src/platform/Win.cpp)
    target_compile_definitions(ssh_native_host PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 TELIPHONES_SSH_TESTING)
    target_link_libraries(ssh_native_host PRIVATE teliphones_fixture_crypto advapi32 bcrypt crypt32 ws2_32 iphlpapi shell32 ole32 oleaut32 taskschd uuid winhttp)
endif()

enable_testing()
if(WIN32)
    add_test(NAME tunnel_startup_native COMMAND tunnel_startup_native_tests)
    set_tests_properties(tunnel_startup_native PROPERTIES TIMEOUT 60)
    add_test(NAME wireguard_nt_unit COMMAND wireguard_nt_native_tests --unit)
    # Real driver/service test is an explicit CI gate, not a portable mock or silent skip.
    # Do not run this privileged fixture on a development workstation.
endif()
add_test(NAME connect_protection COMMAND connect_protection_tests)
add_test(NAME terminal_emulator COMMAND terminal_emulator_tests)
add_test(NAME core_tests COMMAND core_tests)
add_test(NAME session_diagnostics COMMAND session_diagnostics_tests)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME build_layout COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_layout_test.py)
    add_test(NAME contract_check COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/contract_check.py $<TARGET_FILE:contract_tool>)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME broker_contract_check COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/broker_contract_check.py $<TARGET_FILE:contract_tool>)
    endif()
    add_test(NAME managed_ssh_check COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/managed_ssh_check.py $<TARGET_FILE:contract_tool>)
    add_test(NAME ssh_crypto_check COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/ssh_crypto_check.py $<TARGET_FILE:ssh_crypto_tool>)
endif()
