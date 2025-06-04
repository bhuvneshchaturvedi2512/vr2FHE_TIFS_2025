# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

# Import Microsoft SEAL
find_package(SEAL 4.1.2 EXACT REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(results_BGV)

target_sources(results_BGV
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/results_BGV.cpp
)

if(TARGET SEAL::seal)
    target_link_libraries(results_BGV PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(results_BGV PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()
