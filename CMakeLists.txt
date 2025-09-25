cmake_minimum_required(VERSION 3.16)

set(APP sm2verify)
project(${APP} C)

# Generate compile_commands.json in the build directory
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C standard and warnings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Collect sources from src/
file(GLOB SRC_FILES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build the executable
add_executable(${APP}
    main.c
    ${SRC_FILES}
)

include(cmake/coverage.cmake)
cover_target(${APP})

# Include path for headers: include/gmssl/...
target_include_directories(${APP} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# Optional: installation
# install(TARGETS sm2verify RUNTIME DESTINATION bin)
