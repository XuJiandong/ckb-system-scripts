#ifndef CKB_SYSCALLS_H_
#define CKB_SYSCALLS_H_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ckb_consts.h"

#define memory_barrier() asm volatile("fence" ::: "memory")

static inline long __internal_syscall(long n, long _a0, long _a1, long _a2,
                                      long _a3, long _a4, long _a5) {
  register long a0 asm("a0") = _a0;
  register long a1 asm("a1") = _a1;
  register long a2 asm("a2") = _a2;
  register long a3 asm("a3") = _a3;
  register long a4 asm("a4") = _a4;
  register long a5 asm("a5") = _a5;

#ifdef __riscv_32e
  register long syscall_id asm("t0") = n;
#else
  register long syscall_id asm("a7") = n;
#endif

  asm volatile("scall"
               : "+r"(a0)
               : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(syscall_id));
  /*
   * Syscalls might modify memory sent as pointer, adding a barrier here ensures
   * gcc won't do incorrect optimization.
   */
  memory_barrier();

  return a0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_exit(int8_t code) { return syscall(SYS_exit, code, 0, 0, 0, 0, 0); }

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_tx_hash, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_script_hash, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_cell, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_input, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_header, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_witness, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_script, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_cell_by_field, addr, &inner_len, offset, index,
                    source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_header_by_field, addr, &inner_len, offset,
                    index, source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_input_by_field, addr, &inner_len, offset,
                    index, source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source) {
  return syscall(SYS_ckb_load_cell_data_as_code, addr, memory_size,
                 content_offset, content_size, index, source);
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_cell_data, addr, &inner_len, offset, index,
                    source, 0);
  *len = inner_len;
  return ret;
}

int ckb_debug(const char* s) {
  return syscall(SYS_ckb_debug, s, 0, 0, 0, 0, 0);
}

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify input/output.
 */
int load_actual_type_witness(uint8_t *buf, uint64_t *len, size_t index,
                             size_t *type_source) {
  *type_source = CKB_SOURCE_GROUP_INPUT;
  uint64_t tmp_len = 0;
  if (ckb_load_cell_by_field(NULL, &tmp_len, 0, 0, CKB_SOURCE_GROUP_INPUT,
                             CKB_CELL_FIELD_CAPACITY) ==
      CKB_INDEX_OUT_OF_BOUND) {
    *type_source = CKB_SOURCE_GROUP_OUTPUT;
  }

  return ckb_load_witness(buf, len, 0, index, *type_source);
}

#ifdef CKB_C_STDLIB_PRINTF

#ifndef CKB_C_STDLIB_PRINTF_BUFFER_SIZE
#define CKB_C_STDLIB_PRINTF_BUFFER_SIZE 256
#endif

#ifdef PRINTF_INCLUDE_CONFIG_H
#include "printf_config.h"
#endif

#ifndef PRINTF_NTOA_BUFFER_SIZE
#define PRINTF_NTOA_BUFFER_SIZE 32U
#endif

#ifndef PRINTF_FTOA_BUFFER_SIZE
#define PRINTF_FTOA_BUFFER_SIZE 32U
#endif

#ifndef PRINTF_DISABLE_SUPPORT_FLOAT
#define PRINTF_SUPPORT_FLOAT
#endif

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
#define PRINTF_SUPPORT_EXPONENTIAL
#endif

#ifndef PRINTF_DEFAULT_FLOAT_PRECISION
#define PRINTF_DEFAULT_FLOAT_PRECISION 6U
#endif

#ifndef PRINTF_MAX_FLOAT
#define PRINTF_MAX_FLOAT 1e9
#endif

#ifndef PRINTF_DISABLE_SUPPORT_LONG_LONG
#define PRINTF_SUPPORT_LONG_LONG
#endif

#define FLAGS_ZEROPAD (1U << 0U)
#define FLAGS_LEFT (1U << 1U)
#define FLAGS_PLUS (1U << 2U)
#define FLAGS_SPACE (1U << 3U)
#define FLAGS_HASH (1U << 4U)
#define FLAGS_UPPERCASE (1U << 5U)
#define FLAGS_CHAR (1U << 6U)
#define FLAGS_SHORT (1U << 7U)
#define FLAGS_LONG (1U << 8U)
#define FLAGS_LONG_LONG (1U << 9U)
#define FLAGS_PRECISION (1U << 10U)
#define FLAGS_ADAPT_EXP (1U << 11U)

typedef void (*out_fct_type)(char character, void *buffer, size_t idx,
                             size_t maxlen);

typedef struct {
  void (*fct)(char character, void *arg);
  void *arg;
} out_fct_wrap_type;

static inline void _out_buffer(char character, void *buffer, size_t idx,
                               size_t maxlen) {
  if (idx < maxlen) {
    ((char *)buffer)[idx] = character;
  }
}

static inline void _out_null(char character, void *buffer, size_t idx,
                             size_t maxlen) {
  (void)character;
  (void)buffer;
  (void)idx;
  (void)maxlen;
}

static inline void _out_fct(char character, void *buffer, size_t idx,
                            size_t maxlen) {
  (void)idx;
  (void)maxlen;
  if (character) {
    ((out_fct_wrap_type *)buffer)
        ->fct(character, ((out_fct_wrap_type *)buffer)->arg);
  }
}

static inline unsigned int _strnlen_s(const char *str, size_t maxsize) {
  const char *s;
  for (s = str; *s && maxsize--; ++s)
    ;
  return (unsigned int)(s - str);
}

static inline bool _is_digit(char ch) { return (ch >= '0') && (ch <= '9'); }

static unsigned int _atoi(const char **str) {
  unsigned int i = 0U;
  while (_is_digit(**str)) {
    i = i * 10U + (unsigned int)(*((*str)++) - '0');
  }
  return i;
}

static size_t _out_rev(out_fct_type out, char *buffer, size_t idx,
                       size_t maxlen, const char *buf, size_t len,
                       unsigned int width, unsigned int flags) {
  const size_t start_idx = idx;

  if (!(flags & FLAGS_LEFT) && !(flags & FLAGS_ZEROPAD)) {
    for (size_t i = len; i < width; i++) {
      out(' ', buffer, idx++, maxlen);
    }
  }

  while (len) {
    out(buf[--len], buffer, idx++, maxlen);
  }

  if (flags & FLAGS_LEFT) {
    while (idx - start_idx < width) {
      out(' ', buffer, idx++, maxlen);
    }
  }

  return idx;
}

static size_t _ntoa_format(out_fct_type out, char *buffer, size_t idx,
                           size_t maxlen, char *buf, size_t len, bool negative,
                           unsigned int base, unsigned int prec,
                           unsigned int width, unsigned int flags) {
  if (!(flags & FLAGS_LEFT)) {
    if (width && (flags & FLAGS_ZEROPAD) &&
        (negative || (flags & (FLAGS_PLUS | FLAGS_SPACE)))) {
      width--;
    }
    while ((len < prec) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
      buf[len++] = '0';
    }
    while ((flags & FLAGS_ZEROPAD) && (len < width) &&
           (len < PRINTF_NTOA_BUFFER_SIZE)) {
      buf[len++] = '0';
    }
  }

  if (flags & FLAGS_HASH) {
    if (!(flags & FLAGS_PRECISION) && len &&
        ((len == prec) || (len == width))) {
      len--;
      if (len && (base == 16U)) {
        len--;
      }
    }
    if ((base == 16U) && !(flags & FLAGS_UPPERCASE) &&
        (len < PRINTF_NTOA_BUFFER_SIZE)) {
      buf[len++] = 'x';
    } else if ((base == 16U) && (flags & FLAGS_UPPERCASE) &&
               (len < PRINTF_NTOA_BUFFER_SIZE)) {
      buf[len++] = 'X';
    } else if ((base == 2U) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
      buf[len++] = 'b';
    }
    if (len < PRINTF_NTOA_BUFFER_SIZE) {
      buf[len++] = '0';
    }
  }

  if (len < PRINTF_NTOA_BUFFER_SIZE) {
    if (negative) {
      buf[len++] = '-';
    } else if (flags & FLAGS_PLUS) {
      buf[len++] = '+';
    } else if (flags & FLAGS_SPACE) {
      buf[len++] = ' ';
    }
  }

  return _out_rev(out, buffer, idx, maxlen, buf, len, width, flags);
}

static size_t _ntoa_long(out_fct_type out, char *buffer, size_t idx,
                         size_t maxlen, unsigned long value, bool negative,
                         unsigned long base, unsigned int prec,
                         unsigned int width, unsigned int flags) {
  char buf[PRINTF_NTOA_BUFFER_SIZE];
  size_t len = 0U;

  if (!value) {
    flags &= ~FLAGS_HASH;
  }

  if (!(flags & FLAGS_PRECISION) || value) {
    do {
      const char digit = (char)(value % base);
      buf[len++] = digit < 10
                       ? '0' + digit
                       : (flags & FLAGS_UPPERCASE ? 'A' : 'a') + digit - 10;
      value /= base;
    } while (value && (len < PRINTF_NTOA_BUFFER_SIZE));
  }

  return _ntoa_format(out, buffer, idx, maxlen, buf, len, negative,
                      (unsigned int)base, prec, width, flags);
}

#if defined(PRINTF_SUPPORT_LONG_LONG)
static size_t _ntoa_long_long(out_fct_type out, char *buffer, size_t idx,
                              size_t maxlen, unsigned long long value,
                              bool negative, unsigned long long base,
                              unsigned int prec, unsigned int width,
                              unsigned int flags) {
  char buf[PRINTF_NTOA_BUFFER_SIZE];
  size_t len = 0U;

  if (!value) {
    flags &= ~FLAGS_HASH;
  }

  if (!(flags & FLAGS_PRECISION) || value) {
    do {
      const char digit = (char)(value % base);
      buf[len++] = digit < 10
                       ? '0' + digit
                       : (flags & FLAGS_UPPERCASE ? 'A' : 'a') + digit - 10;
      value /= base;
    } while (value && (len < PRINTF_NTOA_BUFFER_SIZE));
  }

  return _ntoa_format(out, buffer, idx, maxlen, buf, len, negative,
                      (unsigned int)base, prec, width, flags);
}
#endif

static int _vsnprintf(out_fct_type out, char *buffer, const size_t maxlen,
                      const char *format, va_list va) {
  unsigned int flags, width, precision, n;
  size_t idx = 0U;

  if (!buffer) {
    out = _out_null;
  }

  while (*format) {
    if (*format != '%') {
      out(*format, buffer, idx++, maxlen);
      format++;
      continue;
    } else {
      format++;
    }

    flags = 0U;
    do {
      switch (*format) {
        case '0':
          flags |= FLAGS_ZEROPAD;
          format++;
          n = 1U;
          break;
        case '-':
          flags |= FLAGS_LEFT;
          format++;
          n = 1U;
          break;
        case '+':
          flags |= FLAGS_PLUS;
          format++;
          n = 1U;
          break;
        case ' ':
          flags |= FLAGS_SPACE;
          format++;
          n = 1U;
          break;
        case '#':
          flags |= FLAGS_HASH;
          format++;
          n = 1U;
          break;
        default:
          n = 0U;
          break;
      }
    } while (n);

    width = 0U;
    if (_is_digit(*format)) {
      width = _atoi(&format);
    } else if (*format == '*') {
      const int w = va_arg(va, int);
      if (w < 0) {
        flags |= FLAGS_LEFT;
        width = (unsigned int)-w;
      } else {
        width = (unsigned int)w;
      }
      format++;
    }

    precision = 0U;
    if (*format == '.') {
      flags |= FLAGS_PRECISION;
      format++;
      if (_is_digit(*format)) {
        precision = _atoi(&format);
      } else if (*format == '*') {
        const int prec = (int)va_arg(va, int);
        precision = prec > 0 ? (unsigned int)prec : 0U;
        format++;
      }
    }

    switch (*format) {
      case 'l':
        flags |= FLAGS_LONG;
        format++;
        if (*format == 'l') {
          flags |= FLAGS_LONG_LONG;
          format++;
        }
        break;
      case 'h':
        flags |= FLAGS_SHORT;
        format++;
        if (*format == 'h') {
          flags |= FLAGS_CHAR;
          format++;
        }
        break;
      case 'j':
        flags |=
            (sizeof(uint64_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
        format++;
        break;
      case 'z':
        flags |=
            (sizeof(size_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
        format++;
        break;
      default:
        break;
    }

    switch (*format) {
      case 'd':
      case 'i':
      case 'u':
      case 'x':
      case 'X':
      case 'o':
      case 'b': {
        unsigned int base;
        if (*format == 'x' || *format == 'X') {
          base = 16U;
        } else if (*format == 'o') {
          base = 8U;
        } else if (*format == 'b') {
          base = 2U;
        } else {
          base = 10U;
          flags &= ~FLAGS_HASH;
        }
        if (*format == 'X') {
          flags |= FLAGS_UPPERCASE;
        }

        if ((*format != 'i') && (*format != 'd')) {
          flags &= ~(FLAGS_PLUS | FLAGS_SPACE);
        }

        if (flags & FLAGS_PRECISION) {
          flags &= ~FLAGS_ZEROPAD;
        }

        if ((*format == 'i') || (*format == 'd')) {
          if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
            const long long value = va_arg(va, long long);
            idx = _ntoa_long_long(
                out, buffer, idx, maxlen,
                (unsigned long long)(value > 0 ? value : 0 - value), value < 0,
                base, precision, width, flags);
#endif
          } else if (flags & FLAGS_LONG) {
            const long value = va_arg(va, long);
            idx = _ntoa_long(out, buffer, idx, maxlen,
                             (unsigned long)(value > 0 ? value : 0 - value),
                             value < 0, base, precision, width, flags);
          } else {
            const int value = (flags & FLAGS_CHAR) ? (char)va_arg(va, int)
                              : (flags & FLAGS_SHORT)
                                  ? (short int)va_arg(va, int)
                                  : va_arg(va, int);
            idx = _ntoa_long(out, buffer, idx, maxlen,
                             (unsigned int)(value > 0 ? value : 0 - value),
                             value < 0, base, precision, width, flags);
          }
        } else {
          if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
            idx = _ntoa_long_long(out, buffer, idx, maxlen,
                                  va_arg(va, unsigned long long), false, base,
                                  precision, width, flags);
#endif
          } else if (flags & FLAGS_LONG) {
            idx =
                _ntoa_long(out, buffer, idx, maxlen, va_arg(va, unsigned long),
                           false, base, precision, width, flags);
          } else {
            const unsigned int value =
                (flags & FLAGS_CHAR) ? (unsigned char)va_arg(va, unsigned int)
                : (flags & FLAGS_SHORT)
                    ? (unsigned short int)va_arg(va, unsigned int)
                    : va_arg(va, unsigned int);
            idx = _ntoa_long(out, buffer, idx, maxlen, value, false, base,
                             precision, width, flags);
          }
        }
        format++;
        break;
      }
      case 'c': {
        unsigned int l = 1U;
        if (!(flags & FLAGS_LEFT)) {
          while (l++ < width) {
            out(' ', buffer, idx++, maxlen);
          }
        }
        out((char)va_arg(va, int), buffer, idx++, maxlen);
        if (flags & FLAGS_LEFT) {
          while (l++ < width) {
            out(' ', buffer, idx++, maxlen);
          }
        }
        format++;
        break;
      }

      case 's': {
        const char *p = va_arg(va, char *);
        unsigned int l = _strnlen_s(p, precision ? precision : (size_t)-1);
        if (flags & FLAGS_PRECISION) {
          l = (l < precision ? l : precision);
        }
        if (!(flags & FLAGS_LEFT)) {
          while (l++ < width) {
            out(' ', buffer, idx++, maxlen);
          }
        }
        while ((*p != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
          out(*(p++), buffer, idx++, maxlen);
        }
        if (flags & FLAGS_LEFT) {
          while (l++ < width) {
            out(' ', buffer, idx++, maxlen);
          }
        }
        format++;
        break;
      }

      case 'p': {
        width = sizeof(void *) * 2U;
        flags |= FLAGS_ZEROPAD | FLAGS_UPPERCASE;
#if defined(PRINTF_SUPPORT_LONG_LONG)
        const bool is_ll = sizeof(uintptr_t) == sizeof(long long);
        if (is_ll) {
          idx = _ntoa_long_long(out, buffer, idx, maxlen,
                                (uintptr_t)va_arg(va, void *), false, 16U,
                                precision, width, flags);
        } else {
#endif
          idx = _ntoa_long(out, buffer, idx, maxlen,
                           (unsigned long)((uintptr_t)va_arg(va, void *)),
                           false, 16U, precision, width, flags);
#if defined(PRINTF_SUPPORT_LONG_LONG)
        }
#endif
        format++;
        break;
      }

      case '%':
        out('%', buffer, idx++, maxlen);
        format++;
        break;

      default:
        out(*format, buffer, idx++, maxlen);
        format++;
        break;
    }
  }

  out((char)0, buffer, idx < maxlen ? idx : maxlen - 1U, maxlen);

  return (int)idx;
}

static int vsnprintf_(char *buffer, size_t count, const char *format,
                      va_list va) {
  return _vsnprintf(_out_buffer, buffer, count, format, va);
}

static int ckb_printf(const char *format, ...) {
  static char buf[CKB_C_STDLIB_PRINTF_BUFFER_SIZE];
  va_list va;
  va_start(va, format);
  int ret = vsnprintf_(buf, CKB_C_STDLIB_PRINTF_BUFFER_SIZE, format, va);
  va_end(va);
  ckb_debug(buf);
  return ret;
}

#define printf ckb_printf

#endif /* CKB_C_STDLIB_PRINTF */

#endif /* CKB_SYSCALLS_H_ */
