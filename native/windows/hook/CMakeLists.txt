# Proxynator hook DLL for the Windows "injection" capture mode.
#
# Build one configuration per target bitness (the output name follows it):
#   cmake -S native/windows/hook -B .cache/native/x64 -A x64   && cmake --build .cache/native/x64 --config Release && cmake --install .cache/native/x64 --config Release --prefix artifacts/native/win-x64
#   cmake -S native/windows/hook -B .cache/native/x86 -A Win32 && cmake --build .cache/native/x86 --config Release && cmake --install .cache/native/x86 --config Release --prefix artifacts/native/win-x86
# build/build-native.ps1 does both. Microsoft Detours (MIT) is fetched at a pinned commit and linked statically.

cmake_minimum_required(VERSION 3.21)
project(proxynator_hook LANGUAGES CXX)

if(NOT MSVC)
  message(FATAL_ERROR "The hook DLL is built with MSVC (Visual Studio or Build Tools with the C++ workload).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static C runtime: the DLL is loaded into arbitrary processes, which may not ship the VC++ runtime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(FetchContent)
set(DETOURS_COMMIT 1dbd4ea281d73d478aa8d09a8b83fbd265f715f7)
# SOURCE_SUBDIR points at a directory without a CMakeLists.txt: only download, the library is defined below.
FetchContent_Declare(detours
  GIT_REPOSITORY https://github.com/microsoft/Detours.git
  GIT_TAG ${DETOURS_COMMIT}
  SOURCE_SUBDIR src)
FetchContent_MakeAvailable(detours)

add_library(detours STATIC
  ${detours_SOURCE_DIR}/src/detours.cpp
  ${detours_SOURCE_DIR}/src/modules.cpp
  ${detours_SOURCE_DIR}/src/disasm.cpp
  ${detours_SOURCE_DIR}/src/image.cpp
  ${detours_SOURCE_DIR}/src/creatwth.cpp
  ${detours_SOURCE_DIR}/src/disolx86.cpp
  ${detours_SOURCE_DIR}/src/disolx64.cpp
  ${detours_SOURCE_DIR}/src/disolia64.cpp
  ${detours_SOURCE_DIR}/src/disolarm.cpp
  ${detours_SOURCE_DIR}/src/disolarm64.cpp)
target_include_directories(detours PUBLIC ${detours_SOURCE_DIR}/src)
target_compile_definitions(detours PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
target_compile_options(detours PRIVATE /W3 /Gy)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(HOOK_NAME proxynator-hook64)
else()
  set(HOOK_NAME proxynator-hook32)
endif()

add_library(proxynator_hook SHARED
  src/dllmain.cpp
  src/hook_state.cpp
  src/log.cpp
  src/protocol.cpp
  src/service_client.cpp
  src/hostname_cache.cpp
  src/socket_hooks.cpp
  src/resolver_hooks.cpp
  src/process_hooks.cpp
  src/inject.cpp
  src/proxynator-hook.def
  src/version.rc)
set_target_properties(proxynator_hook PROPERTIES OUTPUT_NAME ${HOOK_NAME})
target_compile_definitions(proxynator_hook PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00 _WINSOCK_DEPRECATED_NO_WARNINGS)
target_compile_options(proxynator_hook PRIVATE /W4 /WX /permissive- /utf-8 /guard:cf)
target_link_options(proxynator_hook PRIVATE /GUARD:CF /DYNAMICBASE /NXCOMPAT)
target_link_libraries(proxynator_hook PRIVATE detours ws2_32)

install(TARGETS proxynator_hook RUNTIME DESTINATION .)
install(FILES $<TARGET_PDB_FILE:proxynator_hook> DESTINATION . OPTIONAL)
