cmake_minimum_required(VERSION 3.10)
project(libhasha)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

set(CMAKE_C_FLAGS "-Wall -Wextra -I./include -fPIC -funroll-loops -ftree-vectorize -O2")
set(CMAKE_CXX_FLAGS "-Wall -Wextra -I./include -fPIC")

set(LDFLAGS_SHARED "-shared")

set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)
set(UTILS_DIR ${CMAKE_SOURCE_DIR}/utils)

file(GLOB SRCS ${SRC_DIR}/*.c)
file(GLOB TEST_SRCS ${TEST_DIR}/*.c)
file(GLOB UTILS_SRCS ${UTILS_DIR}/*.c)

set(OBJS)
foreach(SRC ${SRCS})
  get_filename_component(SRC_NAME ${SRC} NAME_WE)
  set(OBJS ${OBJS} ${CMAKE_BINARY_DIR}/obj/${SRC_NAME}.o)
endforeach()

add_library(libhasha SHARED ${SRCS})

set_target_properties(libhasha PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_PATH}
  PREFIX ""
)

target_include_directories(libhasha PUBLIC ${INCLUDE_DIR})

target_link_libraries(libhasha PRIVATE)

install(TARGETS libhasha DESTINATION lib)
install(DIRECTORY ${INCLUDE_DIR}/hasha DESTINATION include)

foreach(UTIL_SRC ${UTILS_SRCS})
  get_filename_component(UTIL_NAME ${UTIL_SRC} NAME_WE)
  add_executable(${UTIL_NAME} ${UTIL_SRC})
  target_include_directories(${UTIL_NAME} PUBLIC ${INCLUDE_DIR})
  target_link_libraries(${UTIL_NAME} libhasha)
  # set_target_properties(${UTIL_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH}/utils)
  install(TARGETS ${UTIL_NAME} DESTINATION bin)
endforeach()

install(DIRECTORY ${EXECUTABLE_OUTPUT_PATH}/ DESTINATION bin)

if(EXISTS "${CMAKE_BINARY_DIR}/install_manifest.txt")
  file(READ "${CMAKE_BINARY_DIR}/install_manifest.txt" INSTALL_FILES)
  foreach(FILE ${INSTALL_FILES})
    file(REMOVE ${FILE})
  endforeach()
endif()

add_custom_target(clean-all
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/clean.cmake
)

add_custom_target(bench
  COMMAND hashabench
  DEPENDS hashabench
)
