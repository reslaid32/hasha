/**
 * @file hasha/internal/bits.h
 */

#if !defined(LIBHASHA_BITS_H_LOADED)
#define LIBHASHA_BITS_H_LOADED

#if !defined(HASHA_bB)
/* bits to Bytes (bB) */
#define HASHA_bB(n) n / 8
#endif  // HASHA_bB

#if !defined(HASHA_Bb)
/* Bytes to bits (Bb) */
#define HASHA_Bb(n) n * 8
#endif  // HASHA_Bb

#if !defined(ha_bB)
#define ha_bB(n) HASHA_bB(n)
#endif

#if !defined(ha_Bb)
#define ha_Bb(n) HASHA_Bb(n)
#endif

#endif  // LIBHASHA_BITS_H_LOADED
