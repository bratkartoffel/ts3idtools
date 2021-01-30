target_include_directories(${PROJECT_NAME} PUBLIC include)
target_compile_options(${PROJECT_NAME} PUBLIC
        -fpic
        -Wall
        -Wextra
        -pedantic
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
        -Bsymbolic-functions
        )
target_compile_definitions(${PROJECT_NAME} PUBLIC -DVERSION="${VERSION}")

check_symbol_exists(setpriority "sys/resource.h" HAVE_SYS_RESOURCE_H)
if (HAVE_SYS_RESOURCE_H)
    target_compile_definitions(${PROJECT_NAME} PUBLIC -DHAVE_SYS_RESOURCE_H)
endif ()

check_symbol_exists(pthread_setaffinity_np "pthread.h" HAVE_SETAFFINITY)
if (HAVE_SETAFFINITY)
    target_compile_definitions(${PROJECT_NAME} PUBLIC -DHAVE_SETAFFINITY)
endif ()

if (NOT WIN32)
    target_compile_options(${PROJECT_NAME} PUBLIC -fstack-protector-strong -Wstack-protector --param ssp-buffer-size=4)
    target_compile_definitions(${PROJECT_NAME} PUBLIC -D_FORTIFY_SOURCE=2)
endif ()

target_link_libraries(${PROJECT_NAME} -Wl,-Bstatic crypto)
target_include_directories(${PROJECT_NAME} PUBLIC libressl/include)

if (CMAKE_BUILD_TYPE STREQUAL Release AND SELF_PACKER_FOR_EXECUTABLE)
    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${SELF_PACKER_FOR_EXECUTABLE} -v $<TARGET_FILE:${PROJECT_NAME}>
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/precompiled
            COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${PROJECT_NAME}> ${CMAKE_CURRENT_SOURCE_DIR}/precompiled
            )
endif ()
