add_executable(picow_tcpip_server_background
        picow_tcp_server.c
        )
target_compile_definitions(picow_tcpip_server_background PRIVATE
        WIFI_SSID=\"${TP-Link_A15C}\"
        WIFI_PASSWORD=\"${43193455}\"
        )
target_include_directories(picow_tcpip_server_background PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        sha PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/sha/rfc6234"
        )
target_link_libraries(picow_tcpip_server_background
        pico_cyw43_arch_lwip_threadsafe_background
        pico_stdlib hardware_adc  
        )
        
add_subdirectory(../X3DH/sha sha)
add_subdirectory(../X3DH/ed25519 ed25519)
target_include_directories(ed25519 PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/ed25519/src")
target_link_libraries(picow_tcpip_server_background ed25519 sha)

# enable usb output, disable uart output
    pico_enable_stdio_usb(picow_tcpip_server_background 1)
    pico_enable_stdio_uart(picow_tcpip_server_background 0)
pico_add_extra_outputs(picow_tcpip_server_background)

add_executable(picow_tcpip_server_poll
        picow_tcp_server.c
        )
target_compile_definitions(picow_tcpip_server_poll PRIVATE
        WIFI_SSID=\"${TP-Link_A15C}\"
        WIFI_PASSWORD=\"${43193455}\"
        )
target_include_directories(picow_tcpip_server_poll PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        sha PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/sha/rfc6234"
        )
target_link_libraries(picow_tcpip_server_poll
        pico_cyw43_arch_lwip_poll
        pico_stdlib hardware_adc
        )
        
#add_subdirectory(../X3DH/sha)
#add_subdirectory(../X3DH/ed25519 ed25519)
target_include_directories(ed25519 PUBLIC "${CMAKE_CURRENT_LIST_DIR}../X3DH/ed25519/src")
target_link_libraries(picow_tcpip_server_poll ed25519 sha)
# enable usb output, disable uart output
    pico_enable_stdio_usb(picow_tcpip_server_poll 1)
    pico_enable_stdio_uart(picow_tcpip_server_poll 0)
pico_add_extra_outputs(picow_tcpip_server_poll)


    
