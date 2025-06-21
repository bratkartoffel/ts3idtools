cmake_minimum_required(VERSION 3.10)
project(ts3idtools)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
if (NOT APPLE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msha -msse4")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wl,-s")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()
set(VERSION "1.0.4-SNAPSHOT")

# enable cmake modules
include(CheckCCompilerFlag)
include(FindPackageHandleStandardArgs)
include(FindSelfPackers)

# build libressl
set(BUILD_SHARED_LIBS false)
set(BUILD_STATIC_LIBS true)
add_subdirectory("libressl" EXCLUDE_FROM_ALL)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libressl;${CMAKE_MODULE_PATH}")

# ----- id cruncher for increasing security level -----
project(ts3idcrunch C)
add_executable(${PROJECT_NAME}
        src/globals.c
        src/base64.c
        src/identity.c
        src/ts3idcrunch.c
        src/sha1.c
)
include(common.cmake)

# ----- id dumper to print out information about exported identities -----
project(ts3iddump C)
add_executable(${PROJECT_NAME}
        src/globals.c
        src/base64.c
        src/identity.c
        src/ts3iddump.c
)
include(common.cmake)

# ----- id generator for new identities -----
project(ts3idgen C)
add_executable(${PROJECT_NAME}
        src/globals.c
        src/base64.c
        src/ts3idgen.c
        src/identity.c
        src/sha1.c
)
include(common.cmake)

# ----- testapp for crunching -----
project(ts3idtests C)
add_executable(${PROJECT_NAME}
        src/globals.c
        src/base64.c
        src/identity.c
        src/ts3idtests.c
        src/sha1.c
)
include(common.cmake)
