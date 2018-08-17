#ifndef __KLIB_PRINTF_TYPE_FN_H
#define __KLIB_PRINTF_TYPE_FN_H

#ifndef AZALEA_TEST_CODE
uint32_t klib_snprintf(char *out_str, uint64_t max_out_len, const char *fmt, ...);
uint32_t klib_vsnprintf(char *out_str, uint64_t max_out_len, const char *fmt, va_list args);
#endif

#endif