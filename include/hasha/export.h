#if !defined(HASHA_EXPORT_H_LOADED)
#define HASHA_EXPORT_H_LOADED

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

#if defined(HASHA_WITH_EXECUTABLE)
#define HASHA_INLINE inline
#else
#define HASHA_INLINE
#endif // HASHA_WITH_EXECUTABLE

#if !defined(HASHA_EXTERN_C)
#if defined(__cplusplus)
#define HASHA_EXTERN_C extern "C"
#else
#define HASHA_EXTERN_C
#endif // __cplusplus
#endif // HASHA_EXTERN_C

#if !defined(HASHA_EXTERN_C_BEG)
#if defined(__cplusplus)
#define HASHA_EXTERN_C_BEG HASHA_EXTERN_C {
#else
#define HASHA_EXTERN_C_BEG
#endif // __cplusplus
#endif // HASHA_EXTERN_C_BEG

#if !defined(HASHA_EXTERN_C_END)
#if defined(__cplusplus)
#define HASHA_EXTERN_C_END }
#else
#define HASHA_EXTERN_C_END
#endif // __cplusplus
#endif // HASHA_EXTERN_C_END

#endif // HASHA_EXPORT_H_LOADED
