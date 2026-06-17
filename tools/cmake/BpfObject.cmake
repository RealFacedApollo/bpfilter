# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

# Compile a standalone BPF object for unit tests.
#
# Params:
#   - OUTPUT_VAR: cmake variable name to store the output .o path.
#   - SOURCE: path to the .bpf.c source file.
function(bf_compile_bpf_object OUTPUT_VAR SOURCE)
    find_program(CLANG_BIN clang REQUIRED)

    get_filename_component(_src_name "${SOURCE}" NAME_WE)
    set(_obj "${CMAKE_CURRENT_BINARY_DIR}/${_src_name}.bpf.o")

    file(GLOB _bf_bpf_headers
         "${CMAKE_SOURCE_DIR}/src/libbpfilter/ct/bpf/*.h"
         "${CMAKE_SOURCE_DIR}/src/libbpfilter/include/bpfilter/ct.h")

    add_custom_command(
        OUTPUT "${_obj}"
        COMMAND
            ${CLANG_BIN}
                -O2
                -g
                -target bpf
                -mllvm -bpf-stack-size=2048
                -I ${CMAKE_SOURCE_DIR}/src/libbpfilter/include
                -I ${CMAKE_SOURCE_DIR}/src/libbpfilter
                -I ${CMAKE_SOURCE_DIR}/src/external/include
                -c "${SOURCE}"
                -o "${_obj}"
        DEPENDS "${SOURCE}" ${_bf_bpf_headers}
        COMMENT "Compile BPF object ${_src_name}"
        VERBATIM
    )

    add_custom_target("${_src_name}_bpf_obj" DEPENDS "${_obj}")
    set("${OUTPUT_VAR}" "${_obj}" PARENT_SCOPE)
endfunction()
