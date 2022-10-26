cmake_minimum_required(VERSION 3.16)
project(wssl_pub)

set(CMAKE_CXX_STANDARD 20)

set(HEADERS src/CryptoIdentity.h)
add_library(CryptoLib STATIC src/CryptoIdentity.cpp src/CryptoIdentity.h)
add_library(wssl STATIC src/safety_entity_send.cpp src/safety_entity_rcv.cpp src/lib_wssl.h)

add_executable(CertificationAuthority ${HEADERS} CertificationAuthority.cpp)
add_executable(wssl_pub publisher.cpp publisher.cpp ${HEADERS})
add_executable(wssl_sub subscriber.cpp subscriber.cpp ${HEADERS})

target_include_directories(wssl_pub PUBLIC src)
target_include_directories(wssl_sub PUBLIC src)
target_include_directories(CertificationAuthority PUBLIC src)

target_link_libraries(CertificationAuthority CryptoLib sodium)
target_link_libraries(wssl_pub wssl CryptoLib sodium mosquitto)
target_link_libraries(wssl_sub wssl CryptoLib sodium mosquitto)



