add_subdirectory(ethash/src/libethash)

file(GLOB ETHER_HEADERS "include/eth-crypto/core/*.h" "include/eth-crypto/crypto/*.h")
file(GLOB ETHER_SOURCES "src/core/*.cpp" "src/crypto/*.cpp")

FIND_PACKAGE(Boost 1.65 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

IF(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
    set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR} )
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    message(STATUS "Setting up OpenSSL root and include vars to ${OPENSSL_ROOT_DIR}, ${OPENSSL_INCLUDE_DIR}")
ENDIF()

find_package(OpenSSL REQUIRED)

add_library( eth-crypto ${ETHER_SOURCES} ${ETHER_HEADERS} )

target_link_libraries( eth-crypto secp256k1 ${OPENSSL_LIBRARIES}  ${CMAKE_USE_PTHREADS_INIT} dl ethash )

target_include_directories( eth-crypto
        PUBLIC "${Boost_INCLUDE_DIR}"
        PUBLIC "${CMAKE_SOURCE_DIR}/libraries/eth-crypto/include"
        PUBLIC "${CMAKE_SOURCE_DIR}/libraries/secp256k1/include"
        PUBLIC "${OPENSSL_INCLUDE_DIR}"
        PRIVATE "ethash/src/libethash"
)
