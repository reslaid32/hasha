#if !defined(HASHA_ONESHOT_H_LOADED)
#define HASHA_ONESHOT_H_LOADED

#if !defined(HASHA_ONESHOT)
#define HASHA_ONESHOT(fn, ...) fn##_oneshot(__VA_ARGS__)
#endif /* HASHA_ONESHOT */

#endif /* HASHA_ONESHOT_H_LOADED */