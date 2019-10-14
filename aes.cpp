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

QByteArray CuteAES::Encrypt(QByteArray &text, QByteArray &key)
{
    CuteAES aes(AES_128_MODE, ECB_MODE);
    return aes.encrypt(text, key, nullptr);
}

QByteArray CuteAES::Decrypt(QByteArray &text, QByteArray &key)
{
    CuteAES aes(AES_128_MODE, ECB_MODE);
    return aes.decrypt(text, key, nullptr);
}

QByteArray CuteAES::encrypt(QByteArray &text, QByteArray &key, const QByteArray &iv)
{
    if (text == nullptr or key == nullptr)
        return nullptr;

    QByteArray ret;
    QByteArray expanded_key = expandKey(key);
    QByteArray aligned_text = alignText(text);

    switch (crypt_mode) {
        case (ECB_MODE):
            for (int i = 0; i < aligned_text.size(); i += blocklen)
                ret.append(cipher(expanded_key, aligned_text.mid(i, blocklen)));

            break;

        default:
            return nullptr;
    }

    return ret;
}

QByteArray CuteAES::decrypt(QByteArray &text, QByteArray &key, const QByteArray &iv)
{
    if (text == nullptr or key == nullptr)
        return nullptr;

    QByteArray ret;
    QByteArray expanded_key = expandKey(key);

    switch (crypt_mode) {
        case (ECB_MODE):
            for (int i = 0; i < text.size(); i += blocklen)
                ret.append(cipher(expanded_key, text.mid(i, blocklen)));

            break;

        default:
            return nullptr;
    }

    return ret;
}

QByteArray CuteAES::expandKey(QByteArray &key)
{
    return nullptr;
}

QByteArray CuteAES::alignText(QByteArray &text)
{
    return nullptr;
}

QByteArray CuteAES::cipher(QByteArray &ext_key, const QByteArray &in)
{
    return nullptr;
}

QByteArray CuteAES::decipher(QByteArray &ext_key, const QByteArray &in)
{
    return nullptr;
}
