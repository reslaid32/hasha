/**
 * @file hasha/internal/bits.h
 */

#if !defined(__HASHA_INTERNAL_BITS_H)
#define __HASHA_INTERNAL_BITS_H

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

#endif  // __HASHA_INTERNAL_BITS_H
