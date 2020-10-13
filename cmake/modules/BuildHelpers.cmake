# ############################################################### #
# Args:
#   Option:
#       IF_DIFFERENT        copy files if different (optional)
#   One arg:
#       TARGET              files will be copied before build this target
#       DESTINATION         folder destination
#   Multi args:
#       FILES_PATTERNS      files for copy, regex suppoted
# ############################################################### #
function(copy_files_before_build)
    set(options IF_DIFFERENT)
    set(oneValueArgs TARGET DESTINATION)
    set(multiValueArgs FILES_PATTERNS)
    cmake_parse_arguments(BH "${options}" "${oneValueArgs}" "${multiValueArgs}" "${ARGN}")

    file(GLOB FILES ${BH_FILES_PATTERNS})

    set(_COMMAND copy)
    if (${BH_IF_DIFFERENT})
        set(_COMMAND copy_if_different)
    endif()

    set(COPY_TARGETS "")

    foreach(FILE ${BH_FILES_PATTERNS})
        get_filename_component(CURRENT_TARGET ${FILE} NAME_WE)
        add_custom_target(${CURRENT_TARGET}
            COMMAND ${CMAKE_COMMAND} -E ${_COMMAND} "${FILE}" "${BH_DESTINATION}")

        set(COPY_TARGETS ${COPY_TARGETS} ${CURRENT_TARGET})
    endforeach()

    add_dependencies(${BH_TARGET} ${COPY_TARGETS})
endfunction()

####################################################################################################
# This function converts any file into C/C++ source code.
# Example:
# - input file: data.dat
# - output file: data.h
# - variable name declared in output file: DATA
# - data length: sizeof(DATA)
# embed_resource("data.dat" "data.h" "DATA" UNSIGNED)
####################################################################################################
function(embed_resource resource_file_name source_file_name variable_name type)
    if ("${type}" STREQUAL "SIGNED")
        set(array_element_type "char")
    else()
        set(array_element_type "unsigned char")
    endif()

    file(READ ${resource_file_name} hex_content HEX)

    string(REPEAT "[0-9a-f]" 32 column_pattern)
    string(REGEX REPLACE "(${column_pattern})" "\\1\n" content "${hex_content}")

    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " content "${content}")

    string(REGEX REPLACE ", $" "" content "${content}")

    set(array_definition "static const ${array_element_type} ${variable_name}[] =\n{\n${content}\n};")

    set(source "// Auto generated file.\n${array_definition}\n")

    file(WRITE "${source_file_name}" "${source}")

endfunction()
