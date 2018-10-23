project(ethash)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")
set(ETHHASH_LIBS ethash)

if (WIN32 AND WANT_CRYPTOPP)
    add_subdirectory(ethash/cryptopp)
endif()

add_subdirectory(ethash/src/libethash)

add_subdirectory(ethash/src/benchmark EXCLUDE_FROM_ALL)


file(GLOB ETHER_HEADERS "include/eth-crypto/core/*.h" "include/eth-crypto/crypto/*.h")
file(GLOB ETHER_SOURCES "src/core/*.cpp" "src/crypto/*.cpp")

FIND_PACKAGE(Boost 1.65 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

include_directories(${Boost_INCLUDE_DIR}
        "ethash/src/libethash"
        "${CMAKE_SOURCE_DIR}/libraries/secp256k1/include"
        )

IF(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
    set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR} )
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    message(STATUS "Setting up OpenSSL root and include vars to ${OPENSSL_ROOT_DIR}, ${OPENSSL_INCLUDE_DIR}")
ENDIF()

find_package(OpenSSL REQUIRED)

add_library( eth-crypto ${ETHER_SOURCES} ${ETHER_HEADERS} )

target_link_libraries( eth-crypto secp256k1 ${OPENSSL_LIBRARIES}  ${CMAKE_USE_PTHREADS_INIT} dl ethash )

target_include_directories( eth-crypto
        PUBLIC "${CMAKE_SOURCE_DIR}/libraries/eth-crypto/include"
        PUBLIC "${CMAKE_SOURCE_DIR}/libraries/secp256k1/include"
        PUBLIC "ethash/src/libethash"
)