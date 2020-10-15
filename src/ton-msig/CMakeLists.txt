set(SUBPROJ_NAME ton-msig)

set(${SUBPROJ_NAME}_CXX_STANDARD 17)
set(${SUBPROJ_NAME}_CXX_EXTENSIONS OFF)
set(${SUBPROJ_NAME}_CXX_STANDARD_REQUIRED YES)

set(${SUBPROJ_NAME}_HEADERS
        "Action.hpp"
        "Api.hpp"
        "App.hpp"
        "Cli.hpp"
        "Contract.hpp"
        "Stuff.hpp"
        "Wallet.hpp")

set(${SUBPROJ_NAME}_SOURCES
        "main.cpp"
        "Action.cpp"
        "Api.cpp"
        "App.cpp"
        "Cli.cpp"
        "Contract.cpp"
        "Wallet.cpp")

include(BuildHelpers)
set(${SUBPROJ_NAME}_RES_DIR ${CMAKE_CURRENT_BINARY_DIR}/res)

configure_file(${RESOURCE_DIR}/config.h.in "${${SUBPROJ_NAME}_RES_DIR}/config.h")
embed_resource("${RESOURCE_DIR}/mainnet.config.json" "${${SUBPROJ_NAME}_RES_DIR}/mainnet_config_json.h" MAINNET_CONFIG_JSON SIGNED)
embed_resource("${RESOURCE_DIR}/SafeMultisigWallet.tvc" "${${SUBPROJ_NAME}_RES_DIR}/safe_multisig_wallet_tvc.h" SAFE_MULTISIG_WALLET_TVC UNSIGNED)

set(${SUBPROJ_NAME}_RES
        "${${SUBPROJ_NAME}_RES_DIR}/config.h"
        "${${SUBPROJ_NAME}_RES_DIR}/mainnet_config_json.h"
        "${${SUBPROJ_NAME}_RES_DIR}/safe_multisig_wallet_tvc.h")

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
        ${${SUBPROJ_NAME}_SOURCES}
        ${${SUBPROJ_NAME}_RES})

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
target_include_directories(
        ${SUBPROJ_NAME}
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${PROJECT_ROOT_DIR}/extlibs/cppcodec>
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

target_link_libraries(${SUBPROJ_NAME} PRIVATE
        tonlib tdactor adnllite tl_lite_api tl-lite-utils ton_crypto ton_block lite-client-common smc-envelope ftabi CLI11)

if (MSIG_WITH_API)
    target_compile_definitions(${SUBPROJ_NAME} PUBLIC "MSIG_WITH_API")
endif ()

# Size optimizations
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${SUBPROJ_NAME} PRIVATE -ffunction-sections -fdata-sections)
    target_link_libraries(${SUBPROJ_NAME} PRIVATE -Wl,--gc-sections)
endif ()

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
        DESTINATION ${${SUBPROJ_NAME}_INSTALL_BIN_PREFIX}
        RUNTIME DESTINATION ${${SUBPROJ_NAME}_INSTALL_BIN_PREFIX}
        ARCHIVE DESTINATION ${${SUBPROJ_NAME}_INSTALL_LIB_PREFIX}
        LIBRARY DESTINATION ${${SUBPROJ_NAME}_INSTALL_LIB_PREFIX})
