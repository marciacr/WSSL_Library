cmake_minimum_required(VERSION 3.10)
project(wssl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -lstdc++fs")

set(HEADERS src/CryptoIdentity.h src/libwssl_class.h)
add_library(Crypto STATIC src/CryptoIdentity.cpp src/CryptoIdentity.h)
add_library(Wssl STATIC src/safety_entity_snd.cpp src/safety_entity_rcv.cpp src/libwssl_class.h)

add_executable(CertificationAuthority src/CryptoIdentity.h CertificationAuthority.cpp)
add_executable(wssl_pub ${HEADERS} publisher.cpp)
add_executable(wssl_sub ${HEADERS} subscriber.cpp)

target_include_directories(wssl_pub PUBLIC src)
target_include_directories(wssl_sub PUBLIC src)
target_include_directories(CertificationAuthority PUBLIC src)

target_link_libraries(CertificationAuthority Crypto sodium)
target_link_libraries(wssl_pub Wssl Crypto sodium mosquitto)
target_link_libraries(wssl_sub Wssl Crypto sodium mosquitto)

# target_link_libraries(CertificationAuthority Crypto sodium stdc++fs)
# target_link_libraries(wssl_pub Wssl Crypto sodium mosquitto stdc++fs)
# target_link_libraries(wssl_sub Wssl Crypto sodium mosquitto stdc++fs)



