#ifndef _RABBIT_H
#define _RABBIT_H
#include <stddef.h>
// Type declarations of 32-bit and 8-bit unsigned integers
typedef unsigned int rabbit_uint32;
typedef unsigned char rabbit_byte;
// Structure to store the instance data (internal state)
typedef struct
{
rabbit_uint32 x[8];
rabbit_uint32 c[8];
rabbit_uint32 carry;
} rabbit_instance;
#ifdef __cplusplus
extern "C" {
#endif
// All function calls returns zero on success
int rabbit_key_setup(rabbit_instance *p_instance, const rabbit_byte *p_key, size_t key_size);
int rabbit_iv_setup(const rabbit_instance *p_master_instance,
rabbit_instance *p_instance, const rabbit_byte *p_iv, size_t iv_size);
int rabbit_cipher(rabbit_instance *p_instance, const rabbit_byte *p_src,
rabbit_byte *p_dest, size_t data_size, size_t h);
#ifdef __cplusplus
}
#endif
#endif
