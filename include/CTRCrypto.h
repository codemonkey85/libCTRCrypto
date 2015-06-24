#ifndef CTRCRYPTO_H
#define CTRCRYPTO_H

#include <types.h>

#define AES_BUFFERSIZE_MAX (0xFFFF0)


#define REG_AESCNT                (*(volatile uint32_t*)0x10009000)
#define REG_AESBLKCNT             (*(volatile uint32_t*)0x10009004)
#define REG_AESBLKCNTH1           (*(volatile uint16_t*)0x10009004)
#define REG_AESBLKCNTH2           (*(volatile uint16_t*)0x10009006)
#define REG_AESWRFIFO             (*(volatile uint32_t*)0x10009008)
#define REG_AESRDFIFO             (*(volatile uint32_t*)0x1000900C)
#define REG_AESKEYSEL             (*(volatile uint8_t*)0x10009010)
#define REG_AESKEYCNT             (*(volatile uint8_t*)0x10009011)
#define REG_AESCTR                ((volatile uint32_t*)0x10009020) //16
#define REG_AESMAC                ((volatile uint32_t*)0x10009030) //16
#define REG_AESKEY0               ((volatile uint32_t*)0x10009040) //48
#define REG_AESKEY1               ((volatile uint32_t*)0x10009070) //48
#define REG_AESKEY2               ((volatile uint32_t*)0x100090A0) //48
#define REG_AESKEY3               ((volatile uint32_t*)0x100090D0) //48
#define REG_AESKEYFIFO            (*(volatile uint32_t*)0x10009100)
#define REG_AESKEYXFIFO           (*(volatile uint32_t*)0x10009104)
#define REG_AESKEYYFIFO           (*(volatile uint32_t*)0x10009108)

#define AES_WRITE_FIFO_COUNT      ((REG_AESCNT>>0) & 0x1F)
#define AES_READ_FIFO_COUNT       ((REG_AESCNT>>5) & 0x1F)
#define AES_BUSY                  (1U<<31)

#define AES_FLUSH_READ_FIFO       (1<<10)
#define AES_FLUSH_WRITE_FIFO      (1<<11)
#define AES_BIT12                 (1<<12)
#define AES_BIT13                 (1<<13)
#define AES_MAC_SIZE(n)           ((n & 7)<<16)
#define AES_MAC_REGISTER_SOURCE   (1<<20)
#define AES_MAC_STATUS            (1<<21) // AES_UNKNOWN_21
#define AES_OUTPUT_BIG_ENDIAN     (1<<22)
#define AES_INPUT_BIG_ENDIAN      (1<<23)
#define AES_OUTPUT_NORMAL_ORDER   (1<<24)
#define AES_INPUT_NORMAL_ORDER    (1<<25)
#define AES_UPDATE_KEYSLOT        (1<<26) // AES_UNKNOWN_26
#define AES_MODE(n)               ((n&7)<<27)
#define AES_INTERRUPT_ENABLE      (1<<30)
#define AES_ENABLE                (1U<<31)

#define AES_MODE_CCM_DECRYPT      (0)
#define AES_MODE_CCM_ENCRYPT      (1)
#define AES_MODE_CTR2             (2)
#define AES_MODE_CTR3             (3)
#define AES_MODE_CBC_DECRYPT      (4)
#define AES_MODE_CBC_ENCRYPT      (5)
#define AES_MODE_CTR6             (6)
#define AES_MODE_CTR7             (7)


#define AES_CRYPT_SET_NORMAL_KEY  (1)
#define AES_CRYPT_SET_TWL_KEY     (1<<1)
#define AES_CRYPT_SET_KEYY1       (1<<2)
#define AES_CRYPT_SET_KEYY2       (1<<3)
#define AES_CRYPT_SET_KEYX1       (1<<4)
#define AES_CRYPT_SET_KEYX2       (1<<5)
#define AES_CRYPT_SELECT_KEYSLOT  (1<<6)


typedef struct
{
  u8 keyslot;
  u32 key[13];          // 12+1 for use with TWL key (+1 for key endianess & word order
                        // params)
  u32 key2[5];          // +1 same as above
  u32 CTR_IV_Nonce[5];  // +1 same as above
  u8 update;            // Bit 0 = Key (without the keyscrambler), Bit 1 = TWLKey,
                        // Bit 2 = KeyY (Key), Bit 3 = KeyY (Key2),
                        // Bit 4 = KeyX (Key), Bit 5 = KeyX (Key2)
                        // Bit 6 = Just select keyslot
  u32 params;           // REG_AESCNT bits including endianess/word order params
                        // (for the actual en-/decryption)
} AES_CTX;


void AES_SetControl(u32 cnt);
void AES_SetBlockControl(u32 cnt);
void AES_SetKey(u8 key);
void AES_SetKeyControl(u8 key);
void AES_SetCTRIV(u32 *CTR_IV);
void AES_SetNonce(u32 *Nonce);
void AES_SetMAC(u32 *AES_MAC);
void AES_SetNormalKey(u32 *Key);
void AES_SetTWLKey(u32 *TWLKey, u8 keyslot);
void AES_SetKeyX(u32 *KeyX);
void AES_SetKeyY(u32 *KeyY);
u32 AES_ReadFifo(void);
void AES_WriteFifo(u32 val);
void AES_WaitTillReady(u32 num);
u32 AES_crypt(AES_CTX *ctx, u32 *in_buf, u32 *out_buf, u32 size);
#endif
