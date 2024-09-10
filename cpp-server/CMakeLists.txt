cmake_minimum_required(VERSION 3.10)
project(DebuggerProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
include(FindPkgConfig)

# Fetch ELFIO library
FetchContent_Declare(
  elfio
  GIT_REPOSITORY https://github.com/serge1/ELFIO.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(elfio)
message(STATUS "ELFIO source directory: ${elfio_SOURCE_DIR}")
include_directories(${elfio_SOURCE_DIR}/include)

# Find Capstone library
pkg_check_modules(CAPSTONE REQUIRED capstone)
message(STATUS "Capstone include directory: ${CAPSTONE_INCLUDE_DIRS}")
include_directories(${CAPSTONE_INCLUDE_DIRS})

find_package(Boost REQUIRED COMPONENTS system)

# Define sources and executable
set(SOURCE_FILES
    main.cpp
    debugger.cpp
    server_debugger.cpp
    utils.cpp
)
add_executable(debugger ${SOURCE_FILES})

target_link_libraries(debugger PRIVATE elfio ${CAPSTONE_LIBRARIES} Boost::system pthread)