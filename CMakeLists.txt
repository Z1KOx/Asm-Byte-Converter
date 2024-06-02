cmake_minimum_required(VERSION 3.8)
project(OpcodeToBytes)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add sources
set(SOURCES
	src/main.cpp
	src/assembler.cpp
)

# Add source to this project's executable.
add_executable(OpcodeToBytes ${SOURCES})

# Add include directories
target_include_directories(OpcodeToBytes PRIVATE "${CMAKE_SOURCE_DIR}/dependencies/keystone/include")

# Set the library directory
set(KESTONE_LIB_DIR "${CMAKE_SOURCE_DIR}/dependencies/keystone/lib")

# Ensure that the library file exists
if(NOT EXISTS "${KESTONE_LIB_DIR}/keystone.lib")
  message(FATAL_ERROR "keystone.lib not found in ${KESTONE_LIB_DIR}")
endif()

# Add the library directory
target_link_directories(OpcodeToBytes PRIVATE "${KESTONE_LIB_DIR}")

# Link the keystone library
target_link_libraries(OpcodeToBytes PRIVATE keystone)