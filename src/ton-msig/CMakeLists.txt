set(SUBPROJ_NAME ton-msig)

set(${SUBPROJ_NAME}_CXX_STANDARD 17)
set(${SUBPROJ_NAME}_CXX_EXTENSIONS OFF)
set(${SUBPROJ_NAME}_CXX_STANDARD_REQUIRED YES)

set(${SUBPROJ_NAME}_HEADERS
        "MsigActions.hpp"
        "AddressGenerator.hpp")

set(${SUBPROJ_NAME}_SOURCES
        "main.cpp"
        "MsigActions.cpp"
        "AddressGenerator.cpp")

include(BuildHelpers)

# ############################################################### #
# Options ####################################################### #
# ############################################################### #

include(OptionHelpers)
generate_basic_options_executable(${SUBPROJ_NAME})

# ############################################################### #
# Set all target sources ######################################## #
# ############################################################### #

set(
        ${SUBPROJ_NAME}_ALL_SRCS
        ${${SUBPROJ_NAME}_HEADERS}
        ${${SUBPROJ_NAME}_SOURCES})

# ############################################################### #
# Create target for build ####################################### #
# ############################################################### #

add_executable(
        ${SUBPROJ_NAME}
        ${${SUBPROJ_NAME}_ALL_SRCS})

# Enable C++17 on this project
set_target_properties(
        ${SUBPROJ_NAME} PROPERTIES
        CXX_STANDARD ${${SUBPROJ_NAME}_CXX_STANDARD}
        CXX_EXTENSIONS ${${SUBPROJ_NAME}_CXX_EXTENSIONS}
        CXX_STANDARD_REQUIRED ${${SUBPROJ_NAME}_CXX_STANDARD_REQUIRED})

# Set specific properties
set_target_properties(
        ${SUBPROJ_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
        ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
        OUTPUT_NAME "${SUBPROJ_NAME}$<$<CONFIG:Debug>:d>")

# Set include directories for this project and if it will use as installing
target_link_libraries(${SUBPROJ_NAME} PUBLIC utils)

# Size optimizations
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${SUBPROJ_NAME} PRIVATE -ffunction-sections -fdata-sections)
    target_link_libraries(${SUBPROJ_NAME} PRIVATE -Wl,--gc-sections)
endif()

# Enable IPO
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

include(CheckIPOSupported)
check_ipo_supported(RESULT result)
if (result)
    message("INTERPROCEDURAL_OPTIMIZATION enabled")
    set_target_properties(${SUBPROJ_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
else ()
    message("INTERPROCEDURAL_OPTIMIZATION disabled")
endif ()

# ############################################################### #
# Installing #################################################### #
# ############################################################### #

# Create export targets
install(
        TARGETS ${SUBPROJ_NAME}
        EXPORT ${SUBPROJ_NAME}-targets)

# Set out paths
install(
        TARGETS ${SUBPROJ_NAME}
        DESTINATION /usr/bin
        RUNTIME DESTINATION /usr/bin)

if (BUILD_DEB_PACKAGE)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_PACKAGE_VERSION_MAJOR "${_PROJECT_MAJOR_VERSION}")
    set(CPACK_PACKAGE_VERSION_MINOR "${_PROJECT_MINOR_VERSION}")
    set(CPACK_PACKAGE_VERSION_PATCH "${_PROJECT_PATCH_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION "Tool for TON multisignature wallets")
    set(CPACK_PACKAGE_CONTACT "Ivan Kalinin reide740@dexpa.io")

    include(CPack)
endif()
