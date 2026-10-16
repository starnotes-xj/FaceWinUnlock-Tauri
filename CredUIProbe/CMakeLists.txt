cmake_minimum_required(VERSION 3.21)
project(CredUIProbe LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "CredUIProbe requires the native Windows x64 MSVC toolchain.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(/W4 /WX /utf-8 /permissive- /sdl)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(CredUIProbeHost src/host.cpp)
add_library(CredUIProbeFixture SHARED tests/fixture_dll.cpp)
add_executable(CredUIProbeFixtureHost tests/fixture_host.cpp)

enable_testing()
add_test(NAME probe_fixture COMMAND CredUIProbeHost --self-test)
add_test(NAME probe_restore_detach COMMAND CredUIProbeHost --self-test-detach)
add_test(NAME probe_module_unload COMMAND CredUIProbeHost --self-test-unload)
add_test(NAME probe_crash COMMAND CredUIProbeHost --self-test-crash)
add_test(NAME probe_rejects_external_target COMMAND CredUIProbeHost --dedicated-test-instance -- notepad.exe)
set_tests_properties(probe_fixture probe_restore_detach probe_module_unload probe_crash
    PROPERTIES TIMEOUT 15)
set_tests_properties(probe_rejects_external_target PROPERTIES WILL_FAIL TRUE TIMEOUT 2)
