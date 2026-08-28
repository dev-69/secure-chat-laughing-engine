#include <openssl/bn.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>


// RFC 3526 Group 14 (2048-bit MODP Group)
const char* PRIME_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
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

class DHE {

public:
    BIGNUM* p, *g, *priv_key, *pub_key;
    BN_CTX* ctx;
    std::vector<unsigned char> aes_key; 

    DHE() {
        p = BN_new();
        g = BN_new();
        priv_key = BN_new();
        pub_key = BN_new();
        ctx = BN_CTX_new();

        BN_hex2bn(&p, PRIME_HEX);
        BN_set_word(g, 2);
    }

    ~DHE() {
        BN_free(p);
        BN_free(g);
        BN_free(priv_key);
        BN_free(pub_key);
        BN_CTX_free(ctx);
    }

    void generateKeys() {
        BN_rand_range(priv_key, p);
        BN_mod_exp(pub_key, g, priv_key, p, ctx);
    }

    void compute_key(BIGNUM* peer_pub_key) {
        BIGNUM* shared_secret = BN_new();
        BN_mod_exp(shared_secret, peer_pub_key, priv_key, p, ctx);

        int shared_secret_len = BN_num_bytes(shared_secret);
        std::vector<unsigned char> secret_bytes(shared_secret_len);
        BN_bn2bin(shared_secret, secret_bytes.data());

        aes_key.resize(32); // SHA-256 output is 32 bytes
        
        unsigned int hash_len = 0;
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, secret_bytes.data(), shared_secret_len);
        EVP_DigestFinal_ex(mdctx, aes_key.data(), &hash_len);
        EVP_MD_CTX_free(mdctx);

        BN_free(shared_secret);
    }   

    std::string getFingerPrint() {
        unsigned char hash[32];
        unsigned int hash_len = 0;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, aes_key.data(), aes_key.size());
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx); 

        char hex_buf[17]; 
        for (int i = 0; i < 8; ++i) {
            sprintf(&hex_buf[i * 2], "%02x", hash[i]);
        }
        return std::string(hex_buf);
    }

};