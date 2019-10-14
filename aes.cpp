#include "aes.h"

CuteAES::CuteAES(aes_mode_t _aes_mode, crypt_mode_t _crypt_mode)
{
    // for now only AES128 with EBC is implemented, so others are forbidden
    if (aes_mode != AES_128_MODE and crypt_mode != ECB_MODE)
        throw("Сan only use AES128 with EBC");

    this->aes_mode = _aes_mode;
    this->crypt_mode = _crypt_mode;

    switch (aes_mode) {
        case (AES_128_MODE):
            this->aes_info.nk = 4;
            this->aes_info.nr = 10;
            this->aes_info.key_length = 16;
            break;

        case (AES_192_MODE):
            this->aes_info.nk = 6;
            this->aes_info.nr = 12;
            this->aes_info.key_length = 24;
            break;

        case (AES_256_MODE):
            this->aes_info.nk = 8;
            this->aes_info.nr = 14;
            this->aes_info.key_length = 32;
            break;

        default:
            throw("Unknown AES mode!");
    }
}
