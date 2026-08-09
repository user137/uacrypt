cmake_minimum_required(VERSION 3.16)
project(dstu_core_cpp CXX)

# Header-only wrapper (T-53, docs/bindings-strategy.md) over crates/dstu-core-capi's C ABI
# (T-158). Consumes a prebuilt dstu-core-capi build - run `cargo xtask capi` first (D-158 point 3:
# no CMake FetchContent for the Rust side, no equivalent tooling exists for this project to depend
# on).

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED DSTU_CORE_CAPI_DIR)
  set(DSTU_CORE_CAPI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../crates/dstu-core-capi")
endif()
if(NOT DEFINED DSTU_CORE_TARGET_DIR)
  set(DSTU_CORE_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release")
endif()

add_library(dstu_core_cpp INTERFACE)
target_include_directories(dstu_core_cpp INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${DSTU_CORE_CAPI_DIR}/include"
)
target_compile_features(dstu_core_cpp INTERFACE cxx_std_17)

# dstu-core-capi's cdylib - matches c-tests/test_capi.c's own choice (linked via xtask, D-158),
# not the staticlib bindings/go links: this crate's own C consumer already proves the cdylib is
# the simpler, sufficient artifact to build against.
add_library(dstu_core_capi_shared SHARED IMPORTED)
if(WIN32)
  if(MSVC)
    set_target_properties(dstu_core_capi_shared PROPERTIES
      IMPORTED_LOCATION "${DSTU_CORE_TARGET_DIR}/dstu_core_capi.dll"
      IMPORTED_IMPLIB "${DSTU_CORE_TARGET_DIR}/dstu_core_capi.dll.lib"
    )
  else()
    set_target_properties(dstu_core_capi_shared PROPERTIES
      IMPORTED_LOCATION "${DSTU_CORE_TARGET_DIR}/dstu_core_capi.dll"
      IMPORTED_IMPLIB "${DSTU_CORE_TARGET_DIR}/libdstu_core_capi.dll.a"
    )
  endif()
elseif(APPLE)
  set_target_properties(dstu_core_capi_shared PROPERTIES
    IMPORTED_LOCATION "${DSTU_CORE_TARGET_DIR}/libdstu_core_capi.dylib"
  )
else()
  set_target_properties(dstu_core_capi_shared PROPERTIES
    IMPORTED_LOCATION "${DSTU_CORE_TARGET_DIR}/libdstu_core_capi.so"
  )
endif()

option(DSTU_CORE_CPP_BUILD_TESTS "Build the dstu-core C++ binding's own test suite" ON)
option(DSTU_CORE_CPP_BUILD_EXAMPLES "Build the dstu-core C++ binding's own examples" ON)

# Copies the shared library next to a target's own output directory so the OS loader finds it
# without a PATH/LD_LIBRARY_PATH change - same convention xtask's own capi_run_c_program uses for
# the C test harness.
function(dstu_core_cpp_copy_shared_lib target)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "$<TARGET_FILE:dstu_core_capi_shared>"
      "$<TARGET_FILE_DIR:${target}>"
  )
endfunction()

if(WIN32)
  set(DSTU_UACRYPT_EXE "${DSTU_CORE_TARGET_DIR}/uacrypt.exe")
else()
  set(DSTU_UACRYPT_EXE "${DSTU_CORE_TARGET_DIR}/uacrypt")
endif()

# PRIVATE, on the test/example executables only - never on the dstu_core_cpp INTERFACE library
# itself, which must not impose its own warning flags on a downstream consumer's build. Matches
# xtask's own capi_compile_unixlike (-Wall)/capi_compile_msvc (/W3) posture for the plain-C harness.
function(dstu_core_cpp_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W3)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra)
  endif()
endfunction()

if(DSTU_CORE_CPP_BUILD_TESTS)
  enable_testing()
  add_executable(dstu_core_cpp_tests tests/test_dstu.cpp)
  target_link_libraries(dstu_core_cpp_tests PRIVATE dstu_core_cpp dstu_core_capi_shared)
  target_compile_definitions(dstu_core_cpp_tests PRIVATE DSTU_UACRYPT_EXE="${DSTU_UACRYPT_EXE}")
  dstu_core_cpp_warnings(dstu_core_cpp_tests)
  dstu_core_cpp_copy_shared_lib(dstu_core_cpp_tests)
  add_test(NAME dstu_core_cpp_tests COMMAND dstu_core_cpp_tests)
endif()

if(DSTU_CORE_CPP_BUILD_EXAMPLES)
  foreach(example_name secretbox box box512 secretstream_file sign sign257 password_hashing misc)
    add_executable(dstu_core_cpp_example_${example_name} examples/${example_name}.cpp)
    target_link_libraries(dstu_core_cpp_example_${example_name} PRIVATE dstu_core_cpp dstu_core_capi_shared)
    dstu_core_cpp_warnings(dstu_core_cpp_example_${example_name})
    dstu_core_cpp_copy_shared_lib(dstu_core_cpp_example_${example_name})
  endforeach()
endif()
