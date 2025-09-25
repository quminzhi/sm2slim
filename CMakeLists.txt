cmake_minimum_required(VERSION 3.16)

project(sm2verify C)

# Generate compile_commands.json in the build directory
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C standard and warnings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Collect sources from src/
file(GLOB SRC_FILES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build the executable
add_executable(sm2verify
    sm2verify.c
    ${SRC_FILES}
)

# Include path for headers: include/gmssl/...
target_include_directories(sm2verify PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# Helpful warnings (tweak as you like)
if (MSVC)
    target_compile_options(sm2verify PRIVATE /W4)
else()
    target_compile_options(sm2verify PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Optional: installation
# install(TARGETS sm2verify RUNTIME DESTINATION bin)
