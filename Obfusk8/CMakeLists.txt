cmake_minimum_required(VERSION 3.20)

project(Obfusk8 LANGUAGES CXX)

set(SRC "${CMAKE_SOURCE_DIR}/_MAIN/main.cpp")
set(OUT "${CMAKE_BINARY_DIR}/Obfusk8.exe")

if(EXISTS "${SRC}")
    if(MSVC)
        message(STATUS "Using MSVC (cl.exe)")

        add_custom_target(Obfusk8 ALL
            COMMAND cl /nologo /std:c++17 /EHsc "${SRC}" /Fe"${OUT}"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
            COMMENT "Compiling with cl.exe"
        )

    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(STATUS "Using clang-cl")

        add_custom_target(Obfusk8 ALL
            COMMAND clang-cl /nologo /std:c++17 /EHsc "${SRC}" /Fe"${OUT}"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
            COMMENT "Compiling with clang-cl"
        )

    else()
        message(FATAL_ERROR "Unsupported compiler (need cl or clang-cl)")
    endif()
else()
    message(FATAL_ERROR "source not found: ${SRC}")
endif()