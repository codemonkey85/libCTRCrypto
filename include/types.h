#ifndef TYPES_H
#define TYPES_H

#define u8 unsigned char
#define uint8 unsigned char
#define uint8_t unsigned char
#define vu8 volatile unsigned char
#define vuint8 volatile unsigned char
#define vuint8_t volatile unsigned char

#define s8 signed char
#define sint8 signed char
#define sint8_t signed char
#define vs8 volatile signed char
#define vsint8 volatile signed char
#define vsint8_t volatile signed char

#define u16 unsigned short
#define uint16 unsigned short
#define uint16_t unsigned short
#define vu16 volatile unsigned short
#define vuint16 volatile unsigned short
#define vuint16_t volatile unsigned short

#define s16 signed short
#define sint16 signed short
#define sint16_t signed short
#define vs16 volatile signed short
#define vsint16 volatile signed short
#define vsint16_t volatile signed short

#define u32 unsigned int
#define uint32 unsigned int
#define uint32_t unsigned int
#define vu32 volatile unsigned int
#define vuint32 volatile unsigned int
#define vuint32_t volatile unsigned int

#define s32 signed int
#define sint32 signed int
#define sint32_t signed int
#define vs32 volatile signed int
#define vsint32 volatile signed int
#define vsint32_t volatile signed int

#define u64 unsigned long long int
#define uint64 unsigned long long int
#define uint64_t unsigned long long int
#define vu64 volatile unsigned long long int
#define vuint64 volatile unsigned long long int
#define vuint64_t volatile unsigned long long int

#define s64 signed long long int
#define sint64 signed long long int
#define sint64_t signed long long int
#define vs64 volatile signed long long int
#define vsint64 volatile signed long long int
#define vsint64_t volatile signed long long int

#define NULL (void*) 0
#define bool unsigned int
#define BIT(n) (1<<(n))
#endif
