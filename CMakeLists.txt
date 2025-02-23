cmake_minimum_required(VERSION 3.18)

project(chatroot)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

option(BUILD_MEDIAVIEWER "Build mediaviewer" ON)

include_directories(~/dev/libevent/include )
link_directories(~/dev/libevent/build/lib)

add_subdirectory(lnx_chatsrv)
add_subdirectory(lnx_chatcli)
if(${BUILD_MEDIAVIEWER})
	add_subdirectory(mediaviewer)
endif()
add_subdirectory(subprocess/test)

add_custom_target(ipcbuild ALL 
#	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ipc/clean.sh
	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ipc/build.sh
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ipc
)

