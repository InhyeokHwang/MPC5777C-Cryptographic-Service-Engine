/* 
 * Copyright 2018 NXP                                                                    
 * All rights reserved.                                                                  
 *                                                                                       
 * THIS SOFTWARE IS PROVIDED BY NXP "AS IS" AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NXP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.                          
 */
#include <stdint.h>
#include <stdbool.h>
#include "cse_utils.h"
/* AuthId is the MASTER_ECU key */
uint8_t g_emptyKey[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t g_authIdKey[16] __attribute__((aligned(4))) = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
cse_key_id_t g_authId = CSE_MASTER_ECU;
/* Constants defined by the SHE spec */
uint8_t key_update_enc_c[6] = {0x01, 0x01, 0x53, 0x48, 0x45, 0x00};
uint8_t key_update_mac_c[6] = {0x01, 0x02, 0x53, 0x48, 0x45, 0x00};
uint8_t key_debug_key_c[6] = {0x01, 0x03, 0x53, 0x48, 0x45, 0x00};
/* Derives a key with a given constant */
status_t deriveKey(const uint8_t *key, uint8_t *constant, uint8_t *derivedKey)
{
    uint8_t concat[32] __attribute__((aligned(4)));
    int i;
    for (i = 0; i < 16; i++)
    {
        concat[i] = key[i];
        concat[i+16] = constant[i];
    }
    return CSE_DRV_MPCompress(concat, 176U, derivedKey, CSE_TIMEOUT);
}
/* Computes the M1-M3 values */
status_t computeM1M2M3(uint8_t *authKey, cse_key_id_t authId, cse_key_id_t keyId, const uint8_t *key, uint32_t counter,
                                uint8_t *uid, uint8_t *m1, uint8_t *m2, uint8_t *m3)
{
    status_t stat;
    int i;
    uint8_t iv[16] __attribute__((aligned(4))) = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t k1[16] __attribute__((aligned(4)));
    uint8_t k2[16] __attribute__((aligned(4)));
    uint8_t m2Plain[32] __attribute__((aligned(4)));
    uint8_t m1m2[48] __attribute__((aligned(4)));
    /* Derive K1 and K2 from AuthID */
    deriveKey(authKey, key_update_enc_c, k1);
    deriveKey(authKey, key_update_mac_c, k2);
    /* Compute M1 = UID | ID | AuthID */
    for (i = 0; i < 15; i++)
    {
        m1[i] = uid[i];
    }
    m1[15] = ((keyId & 0xF) << 4) | (authId & 0xF);
    /* Compute M2 (C = counter, F = 0) */
    for(i = 0; i < 16; i++)
    {
        m2Plain[i] = 0;
        m2Plain[16 + i] = key[i];
    }
    m2Plain[0] = (counter & 0xFF00000) >> 20;
    m2Plain[1] = (counter & 0xFF000) >> 12;
    m2Plain[2] = (counter & 0xFF0) >> 4;
    m2Plain[3] = (counter & 0xF) << 4;
    /* Encrypt M2 */
    stat = CSE_DRV_LoadPlainKey(k1, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    stat = CSE_DRV_EncryptCBC(CSE_RAM_KEY, m2Plain, 32U, iv, m2, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    /* Compute M3 as CMAC(key=k2, m1|m2)*/
    for (i = 0; i < 16; i++)
    {
        m1m2[i] = m1[i];
    }
    for(i = 0; i < 32; i++)
    {
        m1m2[16 + i] = m2[i];
    }
    stat = CSE_DRV_LoadPlainKey(k2, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    stat = CSE_DRV_GenerateMAC(CSE_RAM_KEY, m1m2, 384U, m3, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    return STATUS_SUCCESS;
}
/* Computes the M4 and M5 values */
status_t computeM4M5(cse_key_id_t authId, cse_key_id_t keyId, const uint8_t *key, uint32_t counter,
                                uint8_t *uid, uint8_t *m4, uint8_t *m5)
{
    status_t stat;
    int i;
    uint8_t k3[16] __attribute__((aligned(4)));
    uint8_t k4[16] __attribute__((aligned(4)));
    uint8_t m4StarPlain[16] __attribute__((aligned(4))) = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t m4StarCipher[16] __attribute__((aligned(4)));
    /* Derive K4 and K5 from key ID */
    deriveKey(key, key_update_enc_c, k3);
    deriveKey(key, key_update_mac_c, k4);
    m4StarPlain[0] = (counter & 0xFF00000) >> 20;
    m4StarPlain[1] = (counter & 0xFF000) >> 12;
    m4StarPlain[2] = (counter & 0xFF0) >> 4;
    m4StarPlain[3] = ((counter & 0xF) << 4) | 0x8;
    /* Encrypt M4* */
    stat = CSE_DRV_LoadPlainKey(k3, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    stat = CSE_DRV_EncryptECB(CSE_RAM_KEY, m4StarPlain, 16U, m4StarCipher, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    /* Compute M4 = UID | ID | AuthID | M4* */
    for (i = 0; i < 15; i++)
    {
        m4[i] = uid[i];
    }
    m4[15] = ((keyId & 0xF) << 4) | (authId & 0xF);
    for (i = 0; i < 16; i++)
    {
        m4[16 + i] = m4StarCipher[i];
    }
    stat = CSE_DRV_LoadPlainKey(k4, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    stat = CSE_DRV_GenerateMAC(CSE_RAM_KEY, m4, 256U, m5, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return stat;
    return STATUS_SUCCESS;
}
/* Sets the AuthID key (MASTER_ECU_KEY) for the first time */
bool setAuthKey(void)
{
    uint8_t uid[15] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t m1[16] __attribute__((aligned(4)));
    uint8_t m2[32] __attribute__((aligned(4)));
    uint8_t m3[16] __attribute__((aligned(4)));
    uint8_t m4[32] __attribute__((aligned(4)));
    uint8_t m5[16] __attribute__((aligned(4)));
    status_t stat;
    stat = computeM1M2M3(g_emptyKey, g_authId, CSE_MASTER_ECU, g_authIdKey, 1, uid, m1, m2, m3);
    if (stat != STATUS_SUCCESS)
        return false;
    stat = CSE_DRV_LoadKey(CSE_MASTER_ECU, m1, m2, m3, m4, m5, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    return true;
}
/* Extracts the UID. */
bool getUID(uint8_t *uid)
{
    status_t stat;
    uint8_t challenge[16] __attribute__((aligned(4))) = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t sreg __attribute__((aligned(4)));
    uint8_t mac[16] __attribute__((aligned(4)));
    uint8_t verif[32] __attribute__((aligned(4)));
    bool verifStatus;
    uint8_t i;
    stat = CSE_DRV_GetID(challenge, uid, &sreg, mac, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    for (i = 0; i < 16; i++) {
        verif[i] = challenge[i];
    }
    for (i = 0; i < 15; i++) {
        verif[16 + i] = uid[i];
    }
    verif[31] = sreg;
    stat = CSE_DRV_LoadPlainKey(g_authIdKey, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    stat = CSE_DRV_VerifyMAC(CSE_RAM_KEY, verif, 256U, mac, 128U, &verifStatus, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    return verifStatus;
}
/* Erases all the keys. */
bool eraseKeys(void)
{
    status_t stat;
    uint8_t challenge[16] __attribute__((aligned(4)));
    uint8_t auth[16] __attribute__((aligned(4)));
    uint8_t authPlain[31] __attribute__((aligned(4)));
    uint8_t k[16] __attribute__((aligned(4)));
    uint8_t uid[15] __attribute__((aligned(4)));
    uint8_t i;
    CSE_DRV_InitRNG(CSE_TIMEOUT);
    getUID(uid);
    deriveKey(g_authIdKey, key_debug_key_c, k);
    stat = CSE_DRV_LoadPlainKey(k, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    stat = CSE_DRV_DbgChal(challenge, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    for (i = 0; i < 16; i++)
    {
        authPlain[i] = challenge[i];
    }
    for (i = 0; i < 15; i++)
    {
        authPlain[i + 16] = uid[i];
    }
    stat = CSE_DRV_GenerateMAC(CSE_RAM_KEY, authPlain, 248U, auth, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    stat = CSE_DRV_DbgAuth(auth, 1000U);
    if (stat != STATUS_SUCCESS)
        return false;
    return true;
}
/* Loads/updates a non-volatile key. */
bool loadKey(cse_key_id_t keyId, uint8_t *keyNew, uint8_t counter)
{
    uint8_t uid[15] __attribute__((aligned(16))) = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t m1[16] __attribute__((aligned(16)));
    uint8_t m2[32] __attribute__((aligned(16)));
    uint8_t m3[16] __attribute__((aligned(16)));
    uint8_t m4[32] __attribute__((aligned(16)));
    uint8_t m5[16] __attribute__((aligned(16)));
    status_t stat;
    stat = computeM1M2M3(g_authIdKey, g_authId, keyId, keyNew, counter, uid, m1, m2, m3);
    if (stat != STATUS_SUCCESS)
        return false;
    stat = CSE_DRV_LoadKey(keyId, m1, m2, m3, m4, m5, CSE_TIMEOUT);
    if (stat != STATUS_SUCCESS)
        return false;
    return true;
}
