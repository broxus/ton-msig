cmake_minimum_required(VERSION 3.10)

set(_PROJECT_NAME ton-msig)
set(_PROJECT_LANGUAGE CXX)

set(_PROJECT_MAJOR_VERSION 1)
set(_PROJECT_MINOR_VERSION 0)
set(_PROJECT_PATCH_VERSION 0)

set(SUBPROJECT_LIST
        "src/ton-msig"
        )

# Cmake module path
set(PROJECT_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(RESOURCE_DIR ${PROJECT_ROOT_DIR}/res)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_ROOT_DIR}/cmake/modules")

set(_PROJECT_VERSION
        ${_PROJECT_MAJOR_VERSION}.${_PROJECT_MINOR_VERSION}.${_PROJECT_PATCH_VERSION})

project(${_PROJECT_NAME} LANGUAGES ${_PROJECT_LANGUAGE} VERSION ${_PROJECT_VERSION})

option(MSIG_WITH_API "Use \"ON\" to build with integrated server." OFF)
option(BUILD_DEB_PACKAGE "Use \"ON\" to build with cpack." OFF)

# Extlibs
set(WITH_GFLAGS OFF)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")

add_subdirectory(${PROJECT_ROOT_DIR}/extlibs/ton EXCLUDE_FROM_ALL)
add_subdirectory(${PROJECT_ROOT_DIR}/extlibs/CLI11 EXCLUDE_FROM_ALL)
add_subdirectory(${PROJECT_ROOT_DIR}/extlibs/cppcodec EXCLUDE_FROM_ALL)
add_subdirectory(${PROJECT_ROOT_DIR}/extlibs/json EXCLUDE_FROM_ALL)

# Targets
foreach (SUBPROJ ${SUBPROJECT_LIST})
    add_subdirectory(${SUBPROJ})
endforeach ()
