#if !defined(HASHA_EXPORT_H_LOADED)
#define HASHA_EXPORT_H_LOADED

#if !defined(HASHA_DEPRECATED)
#define HASHA_DEPRECATED(msg) __attribute__((deprecated(msg)))
#endif  // HASHA_DEPRECATED

#ifdef HASHA_WITH_EXECUTABLE
#define HASHA_EXPORT
#else
#if defined(_WIN32) || defined(WIN32)
#ifdef HASHA_LIBRARY_BUILD
#define HASHA_EXPORT __declspec(dllexport)
#else
#define HASHA_EXPORT __declspec(dllimport)
#endif
#else
#ifdef HASHA_LIBRARY_BUILD
#define HASHA_EXPORT __attribute__((visibility("default")))
#else
#define HASHA_EXPORT
#endif
#endif
#endif

#if !defined(HASHA_PUBLIC_FUNC)
#define HASHA_PUBLIC_FUNC HASHA_EXPORT
#endif  // HASHA_PUBLIC_FUNC

#if !defined(HASHA_PRIVATE_FUNC)
#if defined(_MSC_VER)
#define HASHA_PRIVATE_FUNC static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define HASHA_PRIVATE_FUNC static __inline__ __attribute__((always_inline))
#else
#define HASHA_PRIVATE_FUNC static inline
#endif
#endif  // HASHA_PRIVATE_FUNC

#if !defined(HASHA_PUBLIC_HO_FUNC)
/* public header only function */
#define HASHA_PUBLIC_HO_FUNC HASHA_PRIVATE_FUNC
#endif  // HASHA_PUBLIC_HO_FUNC

#if !defined(HASHA_EXTERN_C)
#if defined(__cplusplus)
#define HASHA_EXTERN_C extern "C"
#else
#define HASHA_EXTERN_C
#endif  // __cplusplus
#endif  // HASHA_EXTERN_C

#if !defined(HASHA_EXTERN_C_BEG)
#if defined(__cplusplus)
#define HASHA_EXTERN_C_BEG \
  HASHA_EXTERN_C           \
  {
#else
#define HASHA_EXTERN_C_BEG
#endif  // __cplusplus
#endif  // HASHA_EXTERN_C_BEG

#if !defined(HASHA_EXTERN_C_END)
#if defined(__cplusplus)
#define HASHA_EXTERN_C_END }
#else
#define HASHA_EXTERN_C_END
#endif  // __cplusplus
#endif  // HASHA_EXTERN_C_END

// #if !defined(HASHA_VER)
// #define HASHA_VER hashaver()
// #endif // HASHA_VER

#if !defined(HASHA_CONSTRUCTOR)
#define HASHA_CONSTRUCTOR __attribute__((constructor))
#endif /* HASHA_CONSTRUCTOR */

#if !defined(HASHA_DESTRUCTOR)
#define HASHA_DESTRUCTOR __attribute__((destructor))
#endif /* HASHA_DESTRUCTOR */

#endif  // HASHA_EXPORT_H_LOADED
