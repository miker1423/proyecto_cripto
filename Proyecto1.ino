#include <hydrogen.h>
#include <AESLib.h>

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(\
    b ^= ROTL(a + d, 7),\
    c ^= ROTL(b + a, 9),\
    d ^= ROTL(c + b, 13),\
    a ^= ROTL(d + c, 18))
#define ROUNDS 20

uint32_t C[4] = { 0x4868, 0x57856, 0x165865, 0x456465};
uint32_t key[8] = { 0x168436, 0x1684, 0x6874685, 0x468, 0x14568, 0x16846, 0x11684, 0x45786};
uint32_t iv[2] = { 0x46854, 0x16584};
uint32_t counter[2] = { 0x0, 0x0};

void chacha20_block(uint32_t const in[16], uint32_t out[16]) {
    int i = 0;
    uint32_t x[16];

    memcpy(x, in, 16 * sizeof(uint32_t));
    for (i = 0; i < ROUNDS; i += 2)
    {
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 1], x[ 5], x[ 9], x[13]);
        QR(x[ 2], x[ 6], x[10], x[14]);
        QR(x[ 3], x[ 7], x[11], x[15]);
        
        QR(x[ 0], x[ 5], x[10], x[15]);
        QR(x[ 1], x[ 6], x[11], x[12]);
        QR(x[ 2], x[ 7], x[ 8], x[13]);
        QR(x[ 3], x[ 4], x[ 9], x[14]);
    }
    for(i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

void init_block_chacha(uint32_t C[8], uint32_t key[8], 
                       uint32_t counter[2], uint32_t iv[2],
                       uint32_t stateBlock[16]) {
    memcpy(stateBlock, C, 4);
    memcpy(stateBlock + 4, key, 8);
    memcpy(stateBlock + 12, counter, 2);
    memcpy(stateBlock + 14, iv, 2);
}

void cypher_chachca20(uint32_t stateBlock[16], uint8_t const *bytes, uint8_t *output, size_t length) {
    uint32_t auxBlock[16];
    uint8_t *auxStateBlock;

    for(int i = 0; i < length; i++){
        chacha20_block(auxBlock, stateBlock);
        auxStateBlock = (uint8_t *)stateBlock;
        output[i] = bytes[i] ^ auxStateBlock[i];
    }
}

// the setup function runs once when you press reset or power the board
void setup() {
  // initialize digital pin LED_BUILTIN as an output.
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(9600);

  if(hydro_init() == 0)
  {
    Serial.write("TRUE");
    Serial.println();
  }
  
    const uint32_t size = 16;
    uint32_t* state = (uint32_t *)malloc(size * sizeof(uint32_t));
    uint8_t* buffer = (uint8_t *)malloc(size * sizeof(uint8_t));
    uint8_t* enc_buffer = (uint8_t *)malloc(size * sizeof(uint8_t));
    uint8_t* dec_buffer = (uint8_t *)malloc(size * sizeof(uint8_t));

    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);

    uint8_t signature[hydro_sign_BYTES];

    init_block_chacha(C, key, counter, iv, state);
  
    uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    char data[] = "0123456789012345";

    hydro_sign_create(signature, data, 16, "EXAMPLE", key_pair.sk);
    Serial.print("signed\n");
    if(hydro_sign_verify(signature, data, 16, "EXAMPLE", key_pair.sk)) {
      Serial.print("Ok sign");
    }
    Serial.println();
    
    aes256_enc_single(key, data);
    
    Serial.print("encrypted: ");
    for (int i=0; i<sizeof(data); i++)
    {
        Serial.print(data[i], HEX);
        Serial.print(" "); //separator
    }
    Serial.println();
    
    cypher_chachca20(state, data, enc_buffer, size);

    Serial.print("encrypted chacha: ");
    for (int i=0; i<size; i++)
    {
        Serial.print(enc_buffer[i], HEX);
        Serial.print(" "); //separator
    }
    Serial.println();


    cypher_chachca20(state, enc_buffer, data, size);
    Serial.print("decrypted chacha: ");
    for(int i=0; i<sizeof(data); i++){
      Serial.print(data[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
    
    aes256_dec_single(key, data);
    Serial.print("decrypted:");
    Serial.println(data);
}

// the loop function runs over and over again forever
void loop() {
  digitalWrite(LED_BUILTIN, HIGH);   // turn the LED on (HIGH is the voltage level)
  delay(1000);                       // wait for a second
  digitalWrite(LED_BUILTIN, LOW);    // turn the LED off by making the voltage LOW
  delay(1000);                       // wait for a second
}
