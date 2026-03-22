cmake_minimum_required(VERSION 3.20)
project(hans VERSION 1.1 LANGUAGES C CXX)

# Remove all debug information from Release binaries
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "")
string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "/Zi" "" CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}")
string(REPLACE "/ZI" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "/ZI" "" CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/INCREMENTAL:NO /DEBUG:NONE /EMITPOGOPHASEINFO:NO")

# ---------------------------------------------------------------------------
# Language standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# MSVC-specific flags  (supports x64 and ARM64)
# ---------------------------------------------------------------------------
if(MSVC)
    add_compile_options(
        /W3
        /wd4996   # deprecated CRT functions (_CRT_SECURE_NO_WARNINGS)
        /wd4267   # size_t → int conversion (64-bit)
        /wd4244   # intptr_t → int conversion (fd casts)
        /wd4200   # nonstandard zero-size array (not used but silences noise)
    )
    add_compile_definitions(
        WIN32                           # legacy guard used in original code
        _WIN32                          # standard MSVC pre-define (explicit)
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX                        # prevent windows.h min/max macros
    )
endif()

# ---------------------------------------------------------------------------
# Source files common to all platforms
# ---------------------------------------------------------------------------
set(COMMON_SOURCES
    src/main.cpp
    src/client.cpp
    src/server.cpp
    src/worker.cpp
    src/tun.cpp
    src/echo.cpp
    src/auth.cpp
    src/sha1.cpp
    src/hans_time.cpp
    src/exception.cpp
    src/utility.cpp
)

# ---------------------------------------------------------------------------
# Platform-specific TUN/TAP driver
# ---------------------------------------------------------------------------
if(WIN32)
    # Native MSVC build — uses TAP-Windows (OpenVPN TAP driver)
    list(APPEND COMMON_SOURCES
        src/win32_compat.cpp
        src/tun_dev_win32.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND COMMON_SOURCES src/tun_dev_linux.c)
    add_compile_definitions(HAVE_LINUX_IF_TUN_H LINUX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND COMMON_SOURCES src/tun_dev_freebsd.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    list(APPEND COMMON_SOURCES src/tun_dev_openbsd.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND COMMON_SOURCES src/tun_dev_utun.c)
else()
    list(APPEND COMMON_SOURCES src/tun_dev_generic.c)
endif()

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(hans ${COMMON_SOURCES})

target_include_directories(hans PRIVATE src)

set_target_properties(hans PROPERTIES
    LINK_FLAGS_RELEASE "/INCREMENTAL:NO /DEBUG:NONE"
)

# ---------------------------------------------------------------------------
# Linker dependencies
# ---------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(hans PRIVATE
        ws2_32          # Winsock2
        iphlpapi        # IP helper API (used indirectly by Winsock)
    )
elseif(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(hans PRIVATE Threads::Threads)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        # tunemu mode would also need -lpcap, but utun mode does not
    endif()
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS hans RUNTIME DESTINATION bin)
