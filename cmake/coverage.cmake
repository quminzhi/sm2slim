option(ENABLE_COVERAGE "Enable coverage flags for a specific target" OFF)

function(cover_target tgt)
  if(NOT ENABLE_COVERAGE)
    message(STATUS "[coverage] OFF for target ${tgt}")
    return()
  endif()
  if(NOT TARGET ${tgt})
    message(FATAL_ERROR "[coverage] target '${tgt}' not found")
  endif()

  # 关闭 IPO/LTO，避免覆盖率统计异常
  set_property(TARGET ${tgt} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # macOS: clang/llvm-cov
    target_compile_options(${tgt} PRIVATE
      -O0 -g -fno-inline -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(${tgt} PRIVATE
      -fprofile-instr-generate)
  else()
    # Linux: gcc/gcov/lcov
    target_compile_options(${tgt} PRIVATE
      -O0 -g -fno-inline -fprofile-arcs -ftest-coverage)
    target_link_options(${tgt} PRIVATE
      --coverage)
  endif()
endfunction()
