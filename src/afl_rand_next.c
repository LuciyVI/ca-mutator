#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <afl-fuzz.h>

#ifndef WORD_SIZE_64
#define WORD_SIZE_64 1
#endif

#define ROTL(d, bits) ((d << (bits)) | (d >> (8u * sizeof(d) - (bits))))

#if WORD_SIZE_64
AFL_RAND_RETURN rand_next(afl_state_t *afl) {
    AFL_RAND_RETURN xp = afl ? afl->rand_seed[0] : (AFL_RAND_RETURN)0;
    afl->rand_seed[0] = (AFL_RAND_RETURN)15241094284759029579u * afl->rand_seed[1];
    afl->rand_seed[1] = afl->rand_seed[1] - xp;
    afl->rand_seed[1] = ROTL(afl->rand_seed[1], 27);
    return xp;
}
#else
AFL_RAND_RETURN rand_next(afl_state_t *afl) {
    AFL_RAND_RETURN xp = afl ? afl->rand_seed[0] : (AFL_RAND_RETURN)0;
    AFL_RAND_RETURN yp = afl ? afl->rand_seed[1] : (AFL_RAND_RETURN)0;
    AFL_RAND_RETURN zp = afl ? afl->rand_seed[2] : (AFL_RAND_RETURN)0;

    if (afl) {
        afl->rand_seed[0] = (AFL_RAND_RETURN)3323815723u * zp;
        afl->rand_seed[1] = yp - xp;
        afl->rand_seed[1] = ROTL(afl->rand_seed[1], 6);
        afl->rand_seed[2] = zp - yp;
        afl->rand_seed[2] = ROTL(afl->rand_seed[2], 22);
    }
    return xp;
}
#endif

#undef ROTL
