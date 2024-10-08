cmake_minimum_required(VERSION 2.8)
set (CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR} CACHE PATH "")

if (NOT DEFINED WIN32)
  set (CMAKE_CXX_FLAGS "-Wno-multichar")
endif()

set(PROJNAME net_call)

Project(${PROJNAME})
Message(STATUS "-------------------------------")
Message(STATUS "Processing Project ${PROJNAME}:")

#####################################################################################
# LIBMIN Bootstrap
#
get_filename_component ( LIBMIN_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../" REALPATH )
list( APPEND CMAKE_MODULE_PATH "${LIBMIN_ROOT}/cmake" )
list( APPEND CMAKE_PREFIX_PATH "${LIBMIN_ROOT}/cmake" )

#####################################################################################
# Include LIBMIN
#
find_package(Libmin QUIET)

if (NOT LIBMIN_FOUND)

  Message ( FATAL_ERROR "
  This project requires libmin. 
  Set LIBMIN_ROOT to the libmin repository path for /libmin/cmake.
  " )

else()
  add_definitions(-DUSE_LIBMIN)  
  include_directories(${LIBMIN_INC_DIR})
  include_directories(${LIBRARIES_INC_DIR})  

  if (DEFINED ${BUILD_LIBMIN_STATIC})
    add_definitions(-DLIBMIN_STATIC) 
    file(GLOB LIBMIN_SRC "${LIBMIN_SRC_DIR}/*.cpp" )
    file(GLOB LIBMIN_INC "${LIBMIN_INC_DIR}/*.h" )
    LIST( APPEND LIBMIN_SOURCE_FILES ${LIBMIN_SRC} ${LIBMIN_INC} )
    message ( STATUS "  ---> Using LIBMIN (static)")
  else()    
    LIST( APPEND LIBRARIES_OPTIMIZED "${LIBMIN_LIB_DIR}/${LIBMIN_REL}")
    LIST( APPEND LIBRARIES_DEBUG "${LIBMIN_LIB_DIR}/${LIBMIN_DEBUG}")	     
    _EXPANDLIST( OUTPUT PACKAGE_DLLS SOURCE ${LIBMIN_LIB_DIR} FILES ${LIBMIN_DLLS} )
    message ( STATUS "  ---> Using LIBMIN")
  endif() 
endif()

#####################################################################################
# Options

_REQUIRE_LIBEXT()

_REQUIRE_OPENSSL (true)

# _REQUIRE_BCRYPT (true)

#--- symbols in release mode
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF" CACHE STRING "" FORCE)

#####################################################################################
# Asset Path
#
if ( NOT DEFINED ASSET_PATH ) 
   get_filename_component ( _assets "${CMAKE_CURRENT_SOURCE_DIR}/assets" REALPATH )
   set ( ASSET_PATH ${_assets} CACHE PATH "Full path to /assets" )   
endif()
add_definitions(-DASSET_PATH="${ASSET_PATH}/")

#####################################################################################
# Executable
#
file(GLOB MAIN_FILES *.cpp *.c *.h )

unset ( ALL_SOURCE_FILES )

list( APPEND ALL_SOURCE_FILES ${MAIN_FILES} )
list( APPEND ALL_SOURCE_FILES ${COMMON_SOURCE_FILES} )
list( APPEND ALL_SOURCE_FILES ${PACKAGE_SOURCE_FILES} )
list( APPEND ALL_SOURCE_FILES ${UTIL_SOURCE_FILES} )

if ( NOT DEFINED WIN32 )
  set( libdeps )
  LIST(APPEND LIBRARIES_OPTIMIZED ${libdeps})
  LIST(APPEND LIBRARIES_DEBUG ${libdeps})
ENDIF()
include_directories ("${CMAKE_CURRENT_SOURCE_DIR}")    

add_executable (${PROJNAME} ${ALL_SOURCE_FILES} ${CUDA_FILES} ${GLSL_FILES} )

set_property ( TARGET ${PROJNAME} APPEND PROPERTY DEPENDS )

#--- debug and release exe
set ( CMAKE_DEBUG_POSTFIX "d" CACHE STRING "" )
set_target_properties( ${PROJNAME} PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})

#####################################################################################
# Additional Libraries
#
_LINK ( PROJECT ${PROJNAME} OPT ${LIBRARIES_OPTIMIZED} DEBUG ${LIBRARIES_DEBUG} PLATFORM ${PLATFORM_LIBRARIES} )

#####################################################################################
# Windows specific
#
_MSVC_PROPERTIES()
source_group("Source Files" FILES ${MAIN_FILES} ${COMMON_SOURCE_FILES} ${PACKAGE_SOURCE_FILES})
source_group( CUDA FILES ${CUDA_FILES})

#####################################################################################
# Install Binaries
#
#
_DEFAULT_INSTALL_PATH()

# assets folder
file (COPY "${CMAKE_CURRENT_SOURCE_DIR}/assets" DESTINATION ${CMAKE_INSTALL_PREFIX} )

if (WIN32) 
  _INSTALL ( FILES ${PACKAGE_DLLS} DESTINATION ${CMAKE_INSTALL_PREFIX} )		# DLLs
  install ( FILES $<TARGET_PDB_FILE:${PROJNAME}> DESTINATION ${CMAKE_INSTALL_PREFIX} OPTIONAL )   # PDB
endif()

install ( FILES ${INSTALL_LIST} DESTINATION ${CMAKE_INSTALL_PREFIX} )		# exe

###########################
# Done
message ( STATUS "CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}" )
message ( STATUS "CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}" )
message ( STATUS "------------------------------------")
message ( STATUS "${PROJNAME} Install Location:  ${CMAKE_INSTALL_PREFIX}" )
message ( STATUS "------------------------------------")



