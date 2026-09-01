#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <stdexcept>

// RFC 3526 Group 14 (2048-bit MODP Group)
const char *PRIME_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

class DHE
{

public:
    BIGNUM *p, *g, *priv_key, *pub_key;
    BN_CTX *ctx;
    std::vector<unsigned char> aes_key;

    DHE()
    {
        p = BN_new();
        g = BN_new();
        priv_key = BN_new();
        pub_key = BN_new();
        ctx = BN_CTX_new();

        BN_hex2bn(&p, PRIME_HEX);
        BN_set_word(g, 2);
    }

    ~DHE()
    {
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        BN_free(pub_key);
        BN_CTX_free(ctx);
    }

    void generateKeys()
    {
        BN_rand_range(priv_key, p);
        BN_mod_exp(pub_key, g, priv_key, p, ctx);
    }

    void compute_key(BIGNUM *peer_pub_key)
    {
        BIGNUM *shared_secret = BN_new();
        BN_mod_exp(shared_secret, peer_pub_key, priv_key, p, ctx);

        // FIX: Pad the shared secret to the exact length of the prime modulus
        int pad_len = BN_num_bytes(p);
        std::vector<unsigned char> secret_bytes(pad_len);
        BN_bn2binpad(shared_secret, secret_bytes.data(), pad_len);

        aes_key.resize(32); // SHA-256 output is 32 bytes

        unsigned int hash_len = 0;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, secret_bytes.data(), secret_bytes.size());
        EVP_DigestFinal_ex(mdctx, aes_key.data(), &hash_len);
        EVP_MD_CTX_free(mdctx);

        BN_free(shared_secret);
    }

    std::string getFingerPrint()
    {
        unsigned char hash[32];
        unsigned int hash_len = 0;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, aes_key.data(), aes_key.size());
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);

        char hex_buf[17];
        for (int i = 0; i < 8; ++i)
        {
            snprintf(&hex_buf[i * 2], 3, "%02x", hash[i]);
        }
        return std::string(hex_buf);
    }

    std::vector<unsigned char> encrypt(const std::string &plaintext)
    {
        unsigned char nonce[12];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
            throw std::runtime_error("Failed to generate random nonce");
        }

        std::vector<unsigned char> ciphertext(plaintext.length());
        unsigned char tag[16];

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aes_key.data(), nonce);

        int outlen;
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                          (const unsigned char *)plaintext.c_str(), plaintext.length());

        EVP_EncryptFinal_ex(ctx, nullptr, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        EVP_CIPHER_CTX_free(ctx);

        std::vector<unsigned char> payload;
        payload.reserve(12 + 16 + ciphertext.size());
        payload.insert(payload.end(), nonce, nonce + 12);
        payload.insert(payload.end(), tag, tag + 16);
        payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

        return payload;
    }

    std::string decrypt(const std::vector<unsigned char>& payload) {
        if (payload.size() < 28) {
            return "<ERROR: Payload too small>";
        }

        unsigned char nonce[12];
        unsigned char tag[16];
        std::vector<unsigned char> ciphertext(payload.size() - 28);

        std::memcpy(nonce, payload.data(), 12);
        std::memcpy(tag, payload.data() + 12, 16);
        std::memcpy(ciphertext.data(), payload.data() + 28, ciphertext.size());

        std::vector<unsigned char> plaintext(ciphertext.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aes_key.data(), nonce);

        int outlen;
        EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size());
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) {
            return "<DECRYPTION_FAILED_TAMPERING_DETECTED>";
        }

        return std::string(plaintext.begin(), plaintext.end());
    }
};