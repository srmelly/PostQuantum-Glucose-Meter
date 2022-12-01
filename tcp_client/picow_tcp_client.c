/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <time.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include <stdio.h>
#include "../X3DH/ed25519/src/ed25519.h"
#include "../X3DH/sha/rfc6234/sha.h"
#include "include/tinyJambu/crypto_aead.h"

#if !defined(TEST_TCP_SERVER_IP)
#error TEST_TCP_SERVER_IP not defined
#endif

#define TCP_PORT 4242
#define DEBUG_printf printf
#define BUF_SIZE 64

#define TEST_ITERATIONS 4
#define POLL_TIME_S 10

#if 0
static void dump_bytes(const uint8_t *bptr, uint32_t len) {
    unsigned int i = 0;

    printf("dump_bytes %d", len);
    for (i = 0; i < len;) {
        if ((i & 0x0f) == 0) {
            printf("\n");
        } else if ((i & 0x07) == 0) {
            printf(" ");
        }
        printf("%02x ", bptr[i++]);
    }
    printf("\n");
}
#define DUMP_BYTES dump_bytes
#else
#define DUMP_BYTES(A,B)
#endif

typedef struct TCP_CLIENT_T_ {
    struct tcp_pcb *tcp_pcb;
    ip_addr_t remote_addr;
    uint8_t buffer[BUF_SIZE];
    int buffer_len;
    int sent_len;
    bool complete;
    int run_count;
    bool connected;
    unsigned char alice_id_public_key[32]; //Bob's Identity Public Key
    unsigned char alice_id_private_key[64]; //Bob's Identity Private Key
    unsigned char alice_seed[32]; //Seed to generate new keys
    unsigned char alice_ephemeral_public_key[32]; //Alice public identity key
    unsigned char alice_ephemeral_private_key[64]; //Alice ephemeral/generated key
    unsigned char bob_spk_public_key[32];
    unsigned char bob_id_public_key[32]; //Bob's Signed prekey public
    unsigned char dh1_alice[32];
    unsigned char dh2_alice[32];
    unsigned char dh3_alice[32];
    unsigned char dh_final_alice[96];
    unsigned char hex_hkdf_output_alice[128];
    unsigned char cipher[32];
    
} TCP_CLIENT_T;

static err_t tcp_client_close(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    err_t err = ERR_OK;
    if (state->tcp_pcb != NULL) {
        tcp_arg(state->tcp_pcb, NULL);
        tcp_poll(state->tcp_pcb, NULL, 0);
        tcp_sent(state->tcp_pcb, NULL);
        tcp_recv(state->tcp_pcb, NULL);
        tcp_err(state->tcp_pcb, NULL);
        err = tcp_close(state->tcp_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(state->tcp_pcb);
            err = ERR_ABRT;
        }
        state->tcp_pcb = NULL;
    }
    return err;
}

void decrypt(const unsigned char* c, unsigned long long clen, const unsigned char* k);
void encrypt(const unsigned char* m, unsigned long long mlen, const unsigned char* k);

// Called with results of operation
static err_t tcp_result(void *arg, int status) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (status == 0) {
        DEBUG_printf("test success\n");
    } else {
        DEBUG_printf("test failed %d\n", status);
    }
    state->complete = true;
    return tcp_client_close(arg);
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("tcp_client_sent %u\n", len);
    state->sent_len += len;

    if (state->sent_len <= BUF_SIZE || state->sent_len > BUF_SIZE) {//->buffer

        state->run_count++;
        if (state->run_count >= TEST_ITERATIONS) {
            tcp_result(arg, 0);
            return ERR_OK;
        }

        // We should receive a new buffer from the server
        state->buffer_len = 0;
        state->sent_len = 0;
        DEBUG_printf("Waiting for buffer from server\n");
    }

    return ERR_OK;
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (err != ERR_OK) {
        printf("connect failed %d\n", err);
        return tcp_result(arg, err);
    }
    state->connected = true;
    DEBUG_printf("Waiting for buffer from server\n");
    return ERR_OK;
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_client_poll\n");
    return tcp_result(arg, -1); // no response is an error?
}

static void tcp_client_err(void *arg, err_t err) {
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err %d\n", err);
        tcp_result(arg, err);
    }
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
 //Defining parameters for Alice
   
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    if (!p) {
        return tcp_result(arg, -1);
    }
    // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
    // can use this method to cause an assertion in debug mode, if this method is called when
    // cyw43_arch_lwip_begin IS needed
    cyw43_arch_lwip_check();
    if (p->tot_len > 0) {
        DEBUG_printf("recv %d err %d\n", p->tot_len, err);
        for (struct pbuf *q = p; q != NULL; q = q->next) {
            DUMP_BYTES(q->payload, q->len);
        }
        // Receive the buffer
        const uint16_t buffer_left = BUF_SIZE - state->buffer_len;
        state->buffer_len += pbuf_copy_partial(p, state->buffer + state->buffer_len,
                                               p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
        tcp_recved(tpcb, p->tot_len);
    }
    
   
   
    pbuf_free(p);



if(state->run_count < 1)
{
	for (int i = 0; i < 32; i++)
    {
        state->bob_spk_public_key[i] = state->buffer[i];
    }
    
     //Verifying on Alice's side
    ed25519_create_seed(state->alice_seed);
    ed25519_create_keypair(state->alice_id_public_key, state-> alice_id_private_key, state-> alice_seed);

    //Generate Ephemeral keys
    ed25519_create_seed(state->alice_seed);
    ed25519_create_keypair(state->alice_ephemeral_public_key,state-> alice_ephemeral_private_key, state->alice_seed);

    
}
    // If we have received the whole buffer, send it back to the server
    if (state->buffer_len){// == BUF_SIZE) {
       // DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        //err_t err = tcp_write(tpcb, state->buffer, state->buffer_len, TCP_WRITE_FLAG_COPY);
        
       if (state->run_count == 0) 
       {
           
           DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t err = tcp_write(tpcb, state->alice_id_public_key, state->buffer_len,TCP_WRITE_FLAG_COPY);
        
         ed25519_key_exchange(state->dh1_alice, state->bob_spk_public_key, state->alice_id_private_key);
    printf("Exchanging DH1\n");
   
        }
        
        
        
         if (state->run_count == 1) 
       {
           DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t err = tcp_write(tpcb, state -> alice_ephemeral_public_key, state->buffer_len,TCP_WRITE_FLAG_COPY);
        
        for (int i = 0; i < 32; i++)
    {
        state->bob_id_public_key[i] = state->buffer[i];
    }
        
        ed25519_key_exchange(state->dh2_alice, state->bob_id_public_key, state->alice_ephemeral_private_key);
    printf("Exchanging DH2\n");
    
    
        }
        
         if (state->run_count == 2) 
       {
         
         DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t err = tcp_write(tpcb, state -> alice_ephemeral_public_key, state->buffer_len,TCP_WRITE_FLAG_COPY);
         ed25519_key_exchange(state-> dh3_alice, state-> bob_spk_public_key, state->alice_ephemeral_private_key);
         
         printf("Exchanging DH3\n");
    
            for(int j=0; j<96;j++)
    {
        if(j<32) state->dh_final_alice[j] = state->dh1_alice[j]; 
        if(j>=32 && j< 64)  state->dh_final_alice[j] = state->dh2_alice[j%32]; 
        if(j>=64)  state->dh_final_alice[j] = state->dh3_alice[j%32]; 
    }
        
     get_shared_key(state -> dh_final_alice, SHA512, NULL, NULL, state -> hex_hkdf_output_alice, 128);
        
        
        
         for(int i=0; i<16;i++)
    {
        // if (i%16 == 0) printf("\t");
        printf("%02X\n",state -> hex_hkdf_output_alice[i]);
        
    }
    
        }
        
         if (state->run_count == 3) 
       {
       		
   DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
        err_t err = tcp_write(tpcb,state ->  alice_ephemeral_public_key, state->buffer_len,TCP_WRITE_FLAG_COPY);
   
    unsigned long long c_length = 16;
    unsigned char result[c_length];  
    
    
    for (int i = 0; i < c_length; i++)
    {
        result[i] = state->buffer[i];
    }
    
    
    for(int i=0; i< c_length;i++)
    {
      printf("%02X|", result[i]);
    }
    
    printf("\n");
    
    unsigned long long clen = sizeof(result); 
    unsigned char k[16];
    
    for (int i = 0; i < sizeof(k); i++)
    {
        k[i] = state->hex_hkdf_output_alice[i];
    }
    
    
    
     //encrypt(sampleResult, M_SIZE, state -> hex_hkdf_output_alice, c, &c_length);
     decrypt(result, clen , k);
      }
    
            
    return ERR_OK;
}

return ERR_OK;
}

 



static bool tcp_client_open(void *arg) {
    TCP_CLIENT_T *state = (TCP_CLIENT_T*)arg;
    DEBUG_printf("Connecting to %s port %u\n", ip4addr_ntoa(&state->remote_addr), TCP_PORT);
    state->tcp_pcb = tcp_new_ip_type(IP_GET_TYPE(&state->remote_addr));
    if (!state->tcp_pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    tcp_arg(state->tcp_pcb, state);
    tcp_poll(state->tcp_pcb, tcp_client_poll, POLL_TIME_S * 2);
    tcp_sent(state->tcp_pcb, tcp_client_sent);
    tcp_recv(state->tcp_pcb, tcp_client_recv);
    tcp_err(state->tcp_pcb, tcp_client_err);

    state->buffer_len = 0;

    // cyw43_arch_lwip_begin/end should be used around calls into lwIP to ensure correct locking.
    // You can omit them if you are in a callback from lwIP. Note that when using pico_cyw_arch_poll
    // these calls are a no-op and can be omitted, but it is a good practice to use them in
    // case you switch the cyw43_arch type later.
    cyw43_arch_lwip_begin();
    err_t err = tcp_connect(state->tcp_pcb, &state->remote_addr, TCP_PORT, tcp_client_connected);
    cyw43_arch_lwip_end();

    return err == ERR_OK;
}


// Perform initialisation
static TCP_CLIENT_T* tcp_client_init(void) {
    TCP_CLIENT_T *state = calloc(1, sizeof(TCP_CLIENT_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    ip4addr_aton("192.168.0.119", &state->remote_addr);
    return state;
}

void run_tcp_client_test(void) {
    TCP_CLIENT_T *state = tcp_client_init();
    if (!state) {
        return;
    }
    if (!tcp_client_open(state)) {
        tcp_result(state, -1);
        return;
    }
    while(!state->complete) {
        // the following #ifdef is only here so this same example can be used in multiple modes;
        // you do not need it in your code
#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer) to check for WiFi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        sleep_ms(1);
#else
        // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(1000);
#endif
    }
    free(state);
}


int main() {
    stdio_init_all();
     for(int i = 5; i > 0; i--) {
   sleep_ms(1000);
    printf("%d",i);
    if(i > 1) printf(", \n");
    else printf("\n");
    
  }
	
	
   
    
    if (cyw43_arch_init()) {
        DEBUG_printf("failed to initialise\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();

    printf("Connecting to WiFi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms("TP-Link_A15C", "43193455", CYW43_AUTH_WPA2_AES_PSK, 50000)) {
        printf("failed to connect.\n");
        return 1;
    } else {
        printf("Connected.\n");
    }
    run_tcp_client_test();
    cyw43_arch_deinit();
    
    
    return 0;
}

void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
     unsigned char* output_key, int okm_len){
    int salt_len; //The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    int info_len; // The length of optional context and application (ignored if info==NULL)
    int ikm_len; //The length of the input keying material
    uint8_t okm_integer[okm_len]; //output keying material - okm
    ikm_len = 96;
    // printf("%d\n", ikm_len);
    if(salt == NULL) salt_len = 0;
    if(info == NULL) info_len = 0;



    if(hkdf(whichSha,salt,salt_len,dh_final,ikm_len,info,info_len,okm_integer,okm_len) == 0)
    {
        printf("HKDF Shared secret):\n");
    } else {
        fprintf(stderr, "\nHKDF is invalid\n");
    }

    for(int i=0; i<okm_len;i++)
    {
        output_key[i] = okm_integer[i];
        // printf("%d\n", output_key[i]);
    }

}

void decrypt(const unsigned char* c, unsigned long long clen, const unsigned char* k){
    unsigned long long m_length = 8;                               // plaintext length
    unsigned char m[m_length];                                      // plaintext
    unsigned long long *mlen = &m_length;                           // plaintext length pointer
    const unsigned char ad[] = {0x00};                              // associated data
    unsigned long long adlen = sizeof(ad);                          // associated data length
    unsigned char *nsec;                                            // secret message number
    const unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};  // public message number

    crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);

    // print
    printf("Plaintext = ");
    for (int i = 0; i < m_length; i++){
        printf("%c", m[i]);
        //printf("%02X", m[i]);
    }
    printf("\n");
}

void encrypt(const unsigned char* m, unsigned long long mlen, const unsigned char* k){
    unsigned long long c_length = 80;                               // ciphertext length
    unsigned char c[c_length];                                      // ciphertext
    unsigned long long *clen = &c_length;                           // ciphertext length pointer
    const unsigned char ad[] = {0x00};                              // associated data
    unsigned long long adlen = sizeof(ad);                          // associated data length
    const unsigned char *nsec;                                      // secret message number
    const unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};  // public message number

    crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

    printf("\n");
    printf("Ciphertext = ");
    for (int i = 0; i < c_length; i++){
        printf("%02X", c[i]);
    }
    printf("\n");
}



