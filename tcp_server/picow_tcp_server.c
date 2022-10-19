/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <time.h>


#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "math.h"
#include "hardware/pio.h"
#include "bob/crypto_aead.h"
#include "../X3DH/ed25519/src/ed25519.h"
#include "../X3DH/sha/rfc6234/sha.h"


#define TCP_PORT 4242
#define DEBUG_printf printf
#define BUF_SIZE 64
#define TEST_ITERATIONS 3
#define POLL_TIME_S 10

typedef struct TCP_SERVER_T_ {
    struct tcp_pcb *server_pcb;
    struct tcp_pcb *client_pcb;
    bool complete;
    unsigned char buffer_sent[BUF_SIZE];
    unsigned char conn[BUF_SIZE]; 
    char buffer_recv[BUF_SIZE];
    int sent_len;
    int recv_len;
    int run_count;
    unsigned char bob_id_public_key[32]; //Bob's Identity Public Key
    unsigned char bob_id_private_key[64];//Bob's Identity Private Key
    unsigned char bob_seed[32]; //Seed to generate new keys
    unsigned char bob_spk_public_key[32]; //Bob's Signed prekey public
    unsigned char bob_spk_private_key[64]; //Bob's Signed prekey private
    unsigned char alice_id_public_key[32]; //Alice's Identity Public Key
    unsigned char alice_ephemeral_public_key[32]; 
    unsigned char bob_spk_signature[64];
    unsigned char dh1_bob[32];
    unsigned char dh2_bob[32];
    unsigned char dh3_bob[32];
    unsigned char dh_final_bob[96];
    unsigned char hex_hkdf_output_bob[128];
    
} TCP_SERVER_T;

static TCP_SERVER_T* tcp_server_init(void) {
    TCP_SERVER_T *state = calloc(1, sizeof(TCP_SERVER_T));
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return NULL;
    }
    return state;
}

static err_t tcp_server_close(void *arg) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    err_t err = ERR_OK;
    if (state->client_pcb != NULL) {
        tcp_arg(state->client_pcb, NULL);
        tcp_poll(state->client_pcb, NULL, 0);
        tcp_sent(state->client_pcb, NULL);
        tcp_recv(state->client_pcb, NULL);
        tcp_err(state->client_pcb, NULL);
        err = tcp_close(state->client_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(state->client_pcb);
            err = ERR_ABRT;
        }
        state->client_pcb = NULL;
    }
    if (state->server_pcb) {
        tcp_arg(state->server_pcb, NULL);
        tcp_close(state->server_pcb);
        state->server_pcb = NULL;
    }
    return err;
}

static err_t tcp_server_result(void *arg, int status) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (status =! 0) {
        DEBUG_printf("test success\n");
    } else {
        DEBUG_printf("test failed %d\n", status);
    }
    state->complete = true;
   
   return tcp_server_close(arg);
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    DEBUG_printf("Glucose reading sent %u\n", len);
    state->sent_len += len;

    if (state->sent_len >= BUF_SIZE) {

        // We should get the data back from the client
        state->recv_len = 0;
        DEBUG_printf("Waiting for response from glucose meter\n");
    }

    return ERR_OK;
    
}

err_t tcp_server_send_data(void *arg, struct tcp_pcb *tpcb)
{
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
     
    
    if(state->run_count < 1)
    {
    
    ed25519_create_seed(state->bob_seed); //create randome seed
    ed25519_create_keypair(state->bob_id_public_key, state->bob_id_private_key, state->bob_seed); 

//Generate SignedPreKey Pair for bob
    ed25519_create_seed(state->bob_seed); //create random seed 
    ed25519_create_keypair(state->bob_spk_public_key, state->bob_spk_private_key, state-> bob_seed);
    ed25519_sign(state->bob_spk_signature, state->bob_id_public_key, state->bob_id_private_key);
    
    if (ed25519_verify(state->bob_spk_signature, state-> bob_id_public_key)) {
        printf("\nvalid signature of ALice\n");
    } else {
        printf("\ninvalid signature\n");
        // Abort();
    } 
    
    
   /* for (int i = 0; i < 64 ; i++)
    {
        state->bob_spk[i] = bob_spk_private_key[i];
    }*/

   
    }
   // unsigned char dh1_bob[32], dh2_bob[32], dh3_bob[32]; //DH exchanges - no opk so only 3 outputs

    //  BOB'S KEY EXCHANGES
    //DH1 = DH(IKA, SPKB)
    //ed25519_key_exchange(dh1_bob, alice_id_public_key, bob_spk_private_key);

    //DH2 = DH(EKA, IKB)
    //ed25519_key_exchange(dh2_bob, alice_ephemeral_public_key, bob_id_private_key);

    //DH3 = DH(EKA, SPKB)
    //ed25519_key_exchange(dh3_bob, alice_ephemeral_public_key, bob_spk_private_key);

    
    /*
    for(int i=0; i< BUF_SIZE; i++) {
    
    state->buffer_sent[i] =   //state->conn[i];
    
    }*/
    
    if (state->run_count == 0) 
       {
           DEBUG_printf("Writing %ld bytes to phone\n", BUF_SIZE);
        err_t err = tcp_write(tpcb, state->bob_spk_public_key, 32, TCP_WRITE_FLAG_COPY);
         
        if (err != ERR_OK) {
        DEBUG_printf("Failed to write data %d\n", err);
        return tcp_server_result(arg, -1);}
        	
        }
        
         if (state->run_count == 1) 
       {
           DEBUG_printf("Writing %ld bytes to phone\n", BUF_SIZE);
        err_t err = tcp_write(tpcb, state -> bob_id_public_key, 32 ,TCP_WRITE_FLAG_COPY);
         if (err != ERR_OK) {
        DEBUG_printf("Failed to write data %d\n", err);
        return tcp_server_result(arg, -1);}
        
        }
        
         if (state->run_count == 2) 
       {
           DEBUG_printf("Writing %ld bytes to phone\n", BUF_SIZE);
        err_t err = tcp_write(tpcb, state -> bob_id_public_key, 32 ,TCP_WRITE_FLAG_COPY);
         if (err != ERR_OK) {
        DEBUG_printf("Failed to write data %d\n", err);
        return tcp_server_result(arg, -1);}
        
        }
    
    state->sent_len = 0;
    DEBUG_printf("Writing %ld bytes to phone\n", BUF_SIZE);
    // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
    // can use this method to cause an assertion in debug mode, if this method is called when
    //cyw43_arch_lwip_begin IS needed
    
   // cyw43_arch_lwip_check();
    //err_t err = tcp_write(tpcb, state->buffer_sent, BUF_SIZE, TCP_WRITE_FLAG_COPY);
   
   /* if (err != ERR_OK) {
        DEBUG_printf("Failed to write data %d\n", err);
        return tcp_server_result(arg, -1);
    }*/
   // return ERR_OK;
    return 0;
}



err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
	
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
   //if (!p) {
      //  return tcp_server_result(arg, -1);
    //}
    // this method is callback from lwIP, so cyw43_arch_lwip_begin is not required, however you
    // can use this method to cause an assertion in debug mode, if this method is called when
    // cyw43_arch_lwip_begin IS needed
    cyw43_arch_lwip_check();
    if (p->tot_len > 0) {
        DEBUG_printf("tcp_server_recv %d/%d err %d\n", p->tot_len, state->recv_len, err);

        // Receive the buffer
        const uint16_t buffer_left = BUF_SIZE - state->recv_len;
        state->recv_len += pbuf_copy_partial(p, state->buffer_recv + state->recv_len,
                                             p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
        tcp_recved(tpcb, p->tot_len);
    }
    pbuf_free(p);
	
    DEBUG_printf("\n");
    
   
    printf("\n");
    
    if(state->run_count == 0)
    {
    	
    	
    	//DH1 = DH(IKA, SPKB)
       
    	for (int i = 0; i < 32; i++)
        {
            state->alice_id_public_key[i] = state -> buffer_recv[i];
        }
        
    	 ed25519_key_exchange(state->dh1_bob, state->alice_id_public_key, state->bob_spk_private_key);
    	  printf("Exchanging DH1\n");
    
           
    
    }
    
    if(state->run_count == 1)
    {
    	//DH1 = DH(IKA, SPKB)
       
    	for (int i = 0; i < 32; i++)
        {
            state->alice_ephemeral_public_key[i] = state -> buffer_recv[i];
        }
        
    	 ed25519_key_exchange(state->dh2_bob, state->alice_ephemeral_public_key, state->bob_id_private_key);
    	  printf("Exchanging DH2\n");
    
           
    
    }
    
     if(state->run_count == 2)
    {
    	//DH1 = DH(IKA, SPKB)
       
    	ed25519_key_exchange(state->dh3_bob, state->alice_ephemeral_public_key, state->bob_spk_private_key);
    	 
    	  printf("Exchanging DH3\n");
   
           
           for(int j=0; j<96;j++)
    {
        if(j<32)state-> dh_final_bob[j] =state-> dh1_bob[j]; 
        if(j>=32 && j< 64) state-> dh_final_bob[j] = state->dh2_bob[j%32]; 
        if(j>=64)  state->dh_final_bob[j] = state->dh3_bob[j%32]; 
    }
    get_shared_key(state->dh_final_bob, SHA512, NULL, NULL, state->hex_hkdf_output_bob, 128);
     for(int i=0; i<128;i++)
    {
        // if (i%16 == 0) printf("\t");
        printf("%d\n",state -> hex_hkdf_output_bob[i]);
        
    }
    
    }
    
    // Have we have received the whole buffer
   if (state->recv_len == BUF_SIZE || state->recv_len != BUF_SIZE) {

        // check it matches
      //  if (memcmp(state->buffer_sent, state->buffer_recv, BUF_SIZE) != 0) {
           // DEBUG_printf("buffer mismatch\n");
            //return tcp_server_result(arg, -1);
        //}
        DEBUG_printf("tcp_server_recv buffer ok\n");

        // Test complete?
        state->run_count++;
        if (state->run_count >= TEST_ITERATIONS) {
            tcp_server_result(arg, 0);
            return ERR_OK;
        }
	 
    DEBUG_printf("\n");
        // Send another buffer
       return tcp_server_send_data(arg, state->client_pcb);
    }
   return ERR_OK;
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb) {
    DEBUG_printf("tcp_server_poll_fn\n");
    return tcp_server_result(arg, -1); // no response is an error?
}

static void tcp_server_err(void *arg, err_t err) {
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err_fn %d\n", err);
       tcp_server_result(arg, err);
    }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (err != ERR_OK || client_pcb == NULL) {
        DEBUG_printf("Failure in accept\n");
       tcp_server_result(arg, err);
        return ERR_VAL;
    }
    DEBUG_printf("Smartphone connected\n");

    state->client_pcb = client_pcb;
    tcp_arg(client_pcb, state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_poll(client_pcb, tcp_server_poll, POLL_TIME_S * 2);
    tcp_err(client_pcb, tcp_server_err);

    return tcp_server_send_data(arg, state->client_pcb);
}

static bool tcp_server_open(void *arg) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    DEBUG_printf("Starting server at %s on port %u\n", ip4addr_ntoa(netif_ip4_addr(netif_list)), TCP_PORT);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    err_t err = tcp_bind(pcb, NULL, TCP_PORT);
    if (err) {
        DEBUG_printf("failed to bind to port %d\n");
        return false;
    }

    state->server_pcb = tcp_listen_with_backlog(pcb, 1);
    if (!state->server_pcb) {
        DEBUG_printf("failed to listen\n");
        if (pcb) {
            tcp_close(pcb);
        }
        return false;
    }

    tcp_arg(state->server_pcb, state);
    tcp_accept(state->server_pcb, tcp_server_accept);

    return true;
}

void run_tcp_server_test(int conn) {
    TCP_SERVER_T *state = tcp_server_init();
int n = log10(conn) + 1;
    int i;
    
    for (i = n-1; i >= 0; --i, conn /= 10)
    {
        state->conn[i] = (conn % 10) + '0';
    }
    state->conn[3] = 'm';
    state->conn[4] = 'g';
    state->conn[5] = '/';
    state->conn[6] = 'd';
    state->conn[7] = 'L';
    
     
    if (!state) {
        return;
    }
    if (!tcp_server_open(state)) {
        tcp_server_result(state, -1);
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

// Function to compute `a^m mod n`
int compute(int a, int m, int n)
{
    int r;
    int y = 1;
 
    while (m > 0)
    {
        r = m % 2;
 
        // fast exponention
        if (r == 1) {
            y = (y*a) % n;
        }
        a = a*a % n;
        m = m / 2;
    }
 
    return y;
}

int FetchPreKeyBundle(unsigned char *bob_id_public_key, unsigned char *bob_spk_public_key, unsigned char *bob_spk_signature, int message_type){};
void get_dh_output(unsigned char *bob_id_public_key, unsigned char *ephemeral_private_key, unsigned char *id_private_key,
                   unsigned char *bob_spk_public_key, unsigned char *dh_final);
void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt_len, const unsigned char *info,
                    unsigned char *output_key, int okm_len);
void encrypt(const unsigned char *m, unsigned long long mlen, const unsigned char *k, char* c, uint64_t* c_length);

int main() {
    char ssid[] = "TP-Link_A15C";
    char pass[] = "43193455";
    stdio_init_all();


   const uint SENSOR_PIN = 0;
    
// measurement starts if transimpedance amp output voltage > threshold
   float threshold = 2.8;
    

    adc_init();
    gpio_init(SENSOR_PIN);
    gpio_set_dir(SENSOR_PIN, GPIO_IN);

    // Make sure GPIO is high-impedance, no pullups etc
    adc_gpio_init(26);
    // Select ADC input 0 (GPIO26)
    adc_select_input(0);
    
    while(1){
    
    if(gpio_get(SENSOR_PIN) != 0) break;
    }
    
    printf("APPLY BLOOD\n");
    
    float current_voltage;
    while(1) {
    current_voltage = adc_read() * (3.3f / (1 << 12));
    if(current_voltage > threshold) break;
    }
    printf("Reading will be ready in 5 seconds\n");
    // count down timer
  for(int i = 5; i > 0; i--) {
   sleep_ms(1000);
    printf("%d",i);
    if(i > 1) printf(", \n");
    else printf("\n");
    
  }
 current_voltage = adc_read() * (3.3f / (1 << 12));
   // compute concentration
  current_voltage = adc_read() * (3.3f / (1 << 12));

  float conn = 495.6 * current_voltage - 1266 + 150 + 1000;
  
printf("Check phone for results\n");
  //unit8_t concentration = conn;
  printf("%f mg/dL\n", conn);
int con = conn;
   
//     int i = 10;
//  while (i--) {
//    printf("Countdown %i\n", i);
//    sleep_ms(1000);
//  }

    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }

    cyw43_arch_enable_sta_mode();

    //printf("Connecting to WiFi...\n");
    if (cyw43_arch_wifi_connect_timeout_ms(ssid, pass, CYW43_AUTH_WPA2_AES_PSK, 50000)) {
        printf("failed to connect.\n");
        return 1;
    } else {
        printf("Connected.\n");
    }
    
  
    run_tcp_server_test(con);
  
    cyw43_arch_deinit();
    return 0;
    }
    
void encrypt(const unsigned char *m, unsigned long long mlen, const unsigned char *k, char* c, uint64_t* c_length)
{
    // unsigned long long c_length = 80;                                                                      // ciphertext length
    // unsigned char c[c_length];                                                                             // ciphertext
    unsigned long long *clen = c_length;                                                                  // ciphertext length pointer
    const unsigned char ad[] = {0x00};                                                                     // associated data
    unsigned long long adlen = sizeof(ad);                                                                 // associated data length
    const unsigned char *nsec;                                                                             // secret message number
    const unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}; // public message number

    crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

    printf("Ciphertext = ");
    for (int i = 0; i < *c_length; i++)
    {
        printf("%02X|", c[i]);
    }
}

void get_dh_output(unsigned char *bob_id_public_key, unsigned char *alice_ephemeral_private_key, unsigned char *alice_id_private_key,
                   unsigned char *bob_spk_public_key, unsigned char *dh_final)
{
    // DH outputs
    unsigned char dh1[32], dh2[32], dh3[32]; // DH exchanges - no opk so only 3 outputs

    ed25519_key_exchange(dh1, bob_spk_public_key, alice_id_private_key);

    // DH2 = DH(EKA, IKB)
    ed25519_key_exchange(dh2, bob_id_public_key, alice_ephemeral_private_key);

    // DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3, bob_spk_public_key, alice_ephemeral_private_key);

    // Concatenating dh outputs - because strcat, strncat and memcpy doesn't seem to work.
    for (int j = 0; j < 96; j++)
    {
        if (j < 32)
            dh_final[j] = dh1[j];
        if (j >= 32 && j < 64)
            dh_final[j] = dh2[j % 32];
        if (j >= 64)
            dh_final[j] = dh3[j % 32];
    }
}

void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
                    unsigned char *output_key, int okm_len)
{
    int salt_len; // The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    int info_len; // The length of optional context and application (ignored if info==NULL)
    int ikm_len;  // The length of the input keying material
    uint8_t okm_integer[okm_len];
    ikm_len = 96;

    if (salt == NULL)
        salt_len = 0;
    if (info == NULL)
        info_len = 0;

    if (hkdf(whichSha, salt, salt_len, dh_final, ikm_len, info, info_len, okm_integer, okm_len) == 0)
    {
        printf("HKDF (shared secret):\n");
    }
    else
    {
        fprintf(stderr, "HKDF is invalid\n");
    }

    for (int i = 0; i < okm_len; i++)
    {
        output_key[i] = okm_integer[i];
        //printf("%d", output_key[i]);
    }
}
    
    
    
    
   
