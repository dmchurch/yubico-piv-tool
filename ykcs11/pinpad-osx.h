#ifndef PINPAD_OSX_H
#define PINPAD_OSX_H

#include "ykpiv.h"

char *osx_pinpad_get_pin();
ykpiv_rc osx_pinpad_sign_data(ykpiv_state *state, const unsigned char *sign_in,
                        size_t in_len, unsigned char *sign_out, size_t *out_len,
                        unsigned char algorithm, unsigned char key, const char *label);

#endif