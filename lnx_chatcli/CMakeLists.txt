cmake_minimum_required(VERSION 3.18)
project(lnx_chatcli)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

#add_compile_options(-g )
#add_compile_options(-fsanitize=address )
#set(ENV{ASAN_OPTIONS} "allocator_may_return_null=1")

include(FindCURL)
find_package(CURL REQUIRED)

if (NOT CURL_FOUND)
    message (FATAL_ERROR "Curl is not supported")
endif (NOT CURL_FOUND)

include_directories(CURL_INCLUDE_DIRS)

set(CMAKE_REQUIRED_LIBRARIES "${CURL_LIBRARIES}")
list(APPEND LIBS "${CURL_LIBRARIES}")

# Many distros path
LINK_DIRECTORIES(
	/usr/lib64 
	/usr/lib/x86_64-linux-gnu   
	"${CMAKE_CURRENT_SOURCE_DIR}/../../notcurses/build"       
)

include_directories(
../../wide-decimal
../../wide-integer
 /usr/include)

add_executable(lnx_chatcli
        ../src/Base64.cpp
        ../src/chat_client_main.cpp
        ../src/crc32a.cpp
        ../src/crypto_file.cpp
        ../src/crypto_keymgr.cpp
        ../src/crypto_client.cpp
        ../src/encdec_algo.cpp
        ../src/encrypt.cpp
        ../src/includes.cpp
        ../src/machineid.cpp
        ../src/netw_msg.cpp
        ../src/SHA256.cpp
        ../src/socket_node.cpp
        ../src/twofish.c
        ../src/twofish_cfb.c
        ../src/vigenere.cpp
        ../include/DES.cpp
        ../include/SymAlg.cpp
        ../include/AESa.cpp
        ../include/exclusive-lock-file.cpp
	../include/qa/SystemProperties.cpp
	../src/client_term.cpp
	../src/nc_terminal.cpp
        ../include/qa/Bin2PNG/lodepng.cpp
        ../include/qa/RSA-GMP/RSAGMP.cpp
        ../include/qa/RSA-GMP/RSAGMPPrime.cpp
        ../include/qa/RSA-GMP/RSAGMPTest.cpp
        ../include/qa/RSA-GMP/RSAGMPUtils.cpp
        ../include/qa/RSA_generate/bigint/BigInteger.cc
        ../include/qa/RSA_generate/bigint/BigIntegerAlgorithms.cc
        ../include/qa/RSA_generate/bigint/BigIntegerUtils.cc
        ../include/qa/RSA_generate/bigint/BigUnsigned.cc
        ../include/qa/RSA_generate/bigint/BigUnsignedInABase.cc
        ../include/qa/RSA_generate/bigint/BigUnsignedInABase.hh
        ../include/qa/RSA_generate/bigint/NumberlikeArray.hh
        ../include/qa/RSA_generate/bigint/run-testsuite
        ../include/qa/ecc_point/ecc_curve.cpp
        ../include/qa/ecc_point/ecc_elgamal.cpp
        ../include/qa/rsa_gen.cpp
)

link_libraries(gmp curl openssl nghttp2 gssapi2 pthread notcurses notcurses-core unistring deflate tinfo  ${LIBS})

if(EXISTS /usr/lib/x86_64-linux-gnu/libgmp.a)
  set(GMPLIB libgmp.a)
else()
  set(GMPLIB gmp)
endif()
if(EXISTS /usr/lib64/libgmp.a)
  set(GMPLIB libgmp.a)
endif()

if(EXISTS /usr/lib/x86_64-linux-gnu/libdeflate.a)
  set(DEFLATELIB libdeflate.a)
else()
  set(DEFLATELIB deflate)
endif()
if(EXISTS /usr/lib64/libdeflate.a)
  set(DEFLATELIB libdeflate.a)
endif()

if(EXISTS /usr/lib/x86_64-linux-gnu/libtinfo.a)
  set(TINFOLIB libtinfo.a)
else()
  set(TINFOLIB tinfo)
endif()
if(EXISTS /usr/lib64/libtinfo.a)
  set(TINFOLIB libtinfo.a)
endif()

target_link_libraries(lnx_chatcli
		${GMPLIB}
		libnotcurses.a
		libnotcurses-core.a
		pthread
		unistring
		${DEFLATELIB}
		${TINFOLIB}
#		-static-libstdc++
		${LIBS}
)
