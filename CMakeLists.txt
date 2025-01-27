cmake_minimum_required(VERSION 3.22)

project(chatroot)
set(CMAKE_CXX_STANDARD 20)

include_directories(~/dev/libevent/include )
link_directories(~/dev/libevent/build/lib)

add_subdirectory(lnx_chatsrv)
add_subdirectory(lnx_chatcli)
add_subdirectory(mediaviewer)
add_subdirectory(subprocess/test)

add_custom_target(ipcbuild ALL 
#	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ipc/clean.sh
	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ipc/build.sh
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ipc
)

