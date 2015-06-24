/*
 *  CTRCrypto library is a basic interface for the 3DS crypto hardware.
 *  Copyright (C) 2014 Normmatt, profi200
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/
 */


#include <types.h>
#include <CTRCrypto.h>


void AES_SetControl(u32 cnt)
{
	REG_AESCNT = cnt;
}


void AES_SetBlockControl(u32 cnt)
{
	REG_AESBLKCNT = cnt;
}


void AES_SetKey(u8 key)
{
	REG_AESKEYSEL = key;
}


void AES_SetKeyControl(u8 key)
{
	REG_AESKEYCNT = key | 0x80;
}


void AES_SetCTRIV(u32 *CTR_IV)
{
  u32 i;

  for(i=0; i<4; i++) REG_AESCTR[i] = CTR_IV[i];
}


void AES_SetNonce(u32 *Nonce)
{
  u32 i;

  for(i=0; i<3; i++) REG_AESCTR[i] = Nonce[i];
}


void AES_SetMAC(u32 *AES_MAC)
{
  u32 i;

  for(i=0; i<4; i++) REG_AESMAC[i] = AES_MAC[i];
}


void AES_SetNormalKey(u32 *Key)
{
  u32 i;

  for(i=0; i<4; i++) REG_AESKEYFIFO = Key[i];
}


void AES_SetTWLKey(u32 *TWLKey, u8 keyslot)
{
  u32 i;

  for(i=0; i<12; i++) REG_AESKEY0[i + keyslot * 12] = TWLKey[i];
}


void AES_SetKeyX(u32 *KeyX)
{
  u32 i;

  for(i=0; i<4; i++) REG_AESKEYXFIFO = KeyX[i];
}


void AES_SetKeyY(u32 *KeyY)
{
  u32 i;

  for(i=0; i<4; i++) REG_AESKEYYFIFO = KeyY[i];
}


u32 AES_ReadFifo(void)
{
	return REG_AESRDFIFO;
}


void AES_WriteFifo(u32 val)
{
	REG_AESWRFIFO = val;
}


void AES_WaitTillReady(u32 num)
{
	while(AES_READ_FIFO_COUNT != num);
}


u32 AES_crypt(AES_CTX *ctx, u32 *in_buf, u32 *out_buf, u32 size)
{
  u32 j;


  if(!size || size>AES_BUFFERSIZE_MAX) return 1;

  if(ctx->update)
  {
    if(ctx->update & 0b00000001) // Normal key
    {
      AES_SetControl(ctx->key[12]); // Endianess & word order
      AES_SetKeyControl(ctx->keyslot);
      AES_SetNormalKey(ctx->key);
      AES_SetKey(ctx->keyslot);
    }

    if(ctx->update & 0b00000010) // TWL key
    {
      AES_SetControl(ctx->key[12]); // Endianess & word order
      AES_SetKeyControl(ctx->keyslot);
      AES_SetTWLKey(ctx->key, ctx->keyslot);
      AES_SetKey(ctx->keyslot);
    }

    if(ctx->update & 0b00001100) // KeyY
    {
      AES_SetKeyControl(ctx->keyslot);
      if(ctx->update & 0b00000100) // Use key
      {
        AES_SetControl(ctx->key[12]); // Endianess & word order
        AES_SetKeyY(ctx->key);
      }
      else if(ctx->update & 0b00001000) // Use key2
      {
        AES_SetControl(ctx->key2[4]); // Endianess & word order
        AES_SetKeyY(ctx->key2);
      }
      AES_SetKey(ctx->keyslot);
    }

    if(ctx->update & 0b00110000) // KeyX
    {
      AES_SetKeyControl(ctx->keyslot);
      if(ctx->update & 0b00010000) // Use key
      {
        AES_SetControl(ctx->key[12]); // Endianess & word order
        AES_SetKeyX(ctx->key);
      }
      else if(ctx->update & 0b00100000) // Use key2
      {
        AES_SetControl(ctx->key2[4]); // Endianess & word order
        AES_SetKeyX(ctx->key2);
      }
      AES_SetKey(ctx->keyslot);
    }

    if(ctx->update & 0b01000000) AES_SetKey(ctx->keyslot);

    if(ctx->update & 0b01111101) AES_SetControl(AES_UPDATE_KEYSLOT);
  }


  if(((ctx->params>>27)&7)<2)
  {
    AES_SetControl(ctx->CTR_IV_Nonce[4]); // Endianess & word order
    AES_SetNonce(ctx->CTR_IV_Nonce);
  }
  else
  {
    AES_SetControl(ctx->CTR_IV_Nonce[4]); // Endianess & word order
    AES_SetCTRIV(ctx->CTR_IV_Nonce);
  }

  REG_AESBLKCNT = (size>>4)<<16;
  AES_SetControl(AES_ENABLE | ctx->params);


  for(j=0; j<size / 4; j += 4)
  {
    REG_AESWRFIFO = in_buf[0 + j];
    REG_AESWRFIFO = in_buf[1 + j];
    REG_AESWRFIFO = in_buf[2 + j];
    REG_AESWRFIFO = in_buf[3 + j];

    while(AES_READ_FIFO_COUNT != 4);

    out_buf[0 + j] = REG_AESRDFIFO;
    out_buf[1 + j] = REG_AESRDFIFO;
    out_buf[2 + j] = REG_AESRDFIFO;
    out_buf[3 + j] = REG_AESRDFIFO;
  }


  ctx->update = 0;

  return 0;
}
