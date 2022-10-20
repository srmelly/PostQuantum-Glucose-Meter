# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)
set(PICO_SDK_PATH "/home/nasa/Downloads/pico-sdk")
set(PICO_BOARD pico_w)

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(tcp_server C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(tcp_server picow_tcp_server.c)

pico_set_program_name(tcp_server "tcp_server")
pico_set_program_version(tcp_server "0.1")

pico_enable_stdio_uart(tcp_server 1)
pico_enable_stdio_usb(tcp_server 0)

# Add the standard library to the build
target_link_libraries(tcp_server pico_stdlib)


target_compile_definitions(tcp_server PRIVATE
        WIFI_SSID=\"${TP-Link_A15C}\"
        WIFI_PASSWORD=\"${43193455}\"
        )
target_include_directories(tcp_server PRIVATE
${CMAKE_CURRENT_LIST_DIR}
${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
sha PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/sha/rfc6234"
)

# set(BOARD pico-w)
target_link_libraries(tcp_server
        pico_cyw43_arch_lwip_threadsafe_background
        pico_stdlib hardware_adc hardware_pio
        )
add_subdirectory(../X3DH/sha sha)
add_subdirectory(../X3DH/ed25519 ed25519)
target_include_directories(ed25519 PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/ed25519/src")
target_link_libraries(tcp_server ed25519 sha)
pico_add_extra_outputs(tcp_server)
