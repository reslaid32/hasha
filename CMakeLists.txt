cmake_minimum_required(VERSION 3.10)

project(hasha VERSION 1.0 LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

include_directories(include)

set(SOURCES
    src/sha2.c
    src/sha3.c
    src/sha3_keccak.c
)

add_library(hashlib SHARED ${SOURCES})

set(INSTALL_LIB_DIR lib)
set(INSTALL_INCLUDE_DIR include)

install(TARGETS hashlib DESTINATION ${INSTALL_LIB_DIR})

install(DIRECTORY include/ DESTINATION ${INSTALL_INCLUDE_DIR})

enable_testing()

set(TEST_SOURCES
    tests/unit.c
    tests/main.c
)

add_executable(run_tests ${TEST_SOURCES})

target_link_libraries(run_tests hashlib)

add_test(NAME AllTests COMMAND run_tests)