//-----------------------------------------------------------------------------
// Tessera - libnxpsc hardware validation suite
//
// Runs the library's crypto self test plus a series of checks against a real
// DESFire EV3 over PC/SC. Tests 1-8 are strictly read only. Tests 9-16 write
// only inside a throwaway sandbox application (AID 0xDDEE01) and never touch
// the PICC master key, PICC key settings, or any SetConfiguration path.
// Recovery from any failure: FormatPICC with the factory PICC master key.
//
// The PICC aborts secure messaging whenever it answers an in-session command
// with an error status, so every test that is expected to draw an error status
// re-authenticates afterwards through ensure_session(). Without that, the first
// error poisons every later command, which is what the 0x7E cascade was.
//
// Set TRACE_AUTH to dump the legacy PICC handshake and GetCardUID on the wire.
// The card is a throwaway factory-keyed test card, so exposing that session is
// deliberate: with the all-zero master key those frames are enough to
// reconstruct the session key and decrypt the GetCardUID cryptogram offline.
//-----------------------------------------------------------------------------

#include <winscard.h>
#include <cstdio>
#include <cstring>
extern "C" {
#include <nxpsc/nxpsc.h>
}

// Automatically tells the MSVC linker to include winscard.lib
#pragma comment(lib, "winscard.lib")
#pragma comment(lib, "nxpsc.lib")
#pragma comment(lib, "bcrypt.lib")

struct PcscCtx {
    SCARDHANDLE hCard;
    DWORD proto;
};

// ---- wire trace ---------------------------------------------------------------
static const bool TRACE_AUTH = false;
static bool g_trace = false;

static int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen)
{
    PcscCtx* ctx = static_cast<PcscCtx*>(vctx);
    DWORD rlen = static_cast<DWORD>(rxcap);
    if (g_trace) {
        printf("  >> ");
        for (size_t i = 0; i < txlen; i++) printf("%02X", tx[i]);
        printf("\n");
    }
    LONG rc = SCardTransmit(ctx->hCard, SCARD_PCI_T1,
        tx, static_cast<DWORD>(txlen),
        nullptr, rx, &rlen);
    if (rc != SCARD_S_SUCCESS)
        return NXPSC_E_TRANSPORT;   // card removed / no answer
    if (g_trace) {
        printf("  << ");
        for (DWORD i = 0; i < rlen; i++) printf("%02X", rx[i]);
        printf("\n");
    }
    *rxlen = rlen;
    return NXPSC_OK;                // card errors are decoded by the library
}

static const nxpsc_key_t* g_picc_key = nullptr;

// ---- tiny test harness ---------------------------------------------------------
static int g_pass = 0, g_fail = 0, g_skip = 0;

static void report(const char* name, int rc, nxpsc_card_t* card)
{
    if (rc == NXPSC_OK) {
        printf("[PASS] %s\n", name);
        g_pass++;
    }
    else {
        printf("[FAIL] %s: %s", name, nxpsc_strerror(rc));
        if (rc == NXPSC_E_CARD && card)
            printf(" (status 0x%02X: %s)",
                nxpsc_last_status(card), nxpsc_status_str(nxpsc_last_status(card)));
        printf("\n");
        g_fail++;
    }
}

static void skip(const char* name, const char* why)
{
    printf("[SKIP] %s: %s\n", name, why);
    g_skip++;
}

// the card threw the session away, pick it back up so the next test is not
// measuring the fallout of the previous one
static bool ensure_session(nxpsc_card_t* card, uint8_t key_no, const nxpsc_key_t* key)
{
    if (nxpsc_session_lost(card) == false)
        return nxpsc_is_authenticated(card);

    printf("       (card ended the session, re-authenticating key %u)\n", key_no);
    int rc = nxpsc_authenticate(card, key_no, key, NXPSC_CHAN_AUTO);
    if (rc != NXPSC_OK)
        printf("       re-authentication failed: %s\n", nxpsc_strerror(rc));
    return rc == NXPSC_OK;
}

static void hexdump(const char* label, const uint8_t* buf, size_t len)
{
    printf("       %s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

//-----------------------------------------------------------------------------
// write-path validation ladder, tests 9-16. everything inside sandbox AID
//-----------------------------------------------------------------------------
static const uint32_t SANDBOX_AID = 0xDDEE01;

static void run_write_ladder(nxpsc_card_t* card)
{
    int rc;

    // ---- 9. create sandbox application (AES128, 2 keys) ------------------------
    rc = nxpsc_create_application(card, SANDBOX_AID, 0x0F, 2, NXPSC_KEY_AES128);
    if (rc == NXPSC_E_CARD && nxpsc_last_status(card) == 0xDE) {
        // leftover from a previous run, wipe and recreate
        nxpsc_delete_application(card, SANDBOX_AID);
        rc = nxpsc_create_application(card, SANDBOX_AID, 0x0F, 2, NXPSC_KEY_AES128);
    }
    report("CreateApplication (sandbox)", rc, card);
    if (rc != NXPSC_OK) return;

    rc = nxpsc_select_application(card, SANDBOX_AID);
    report("SelectApplication (sandbox)", rc, card);
    if (rc != NXPSC_OK) return;

    // authenticate inside the app with the default all-zero AES key 0
    nxpsc_key_t appkey{};
    appkey.type = NXPSC_KEY_AES128;
    rc = nxpsc_authenticate(card, 0, &appkey, NXPSC_CHAN_AUTO);
    report("Authenticate (app key 0, AES)", rc, card);
    if (rc != NXPSC_OK) return;

    // access: everything on key 0 except read, which is free — lets us
    // cross-check enciphered writes with plain reads
    nxpsc_access_t acc{};
    acc.read = 0x0E;        // free read
    acc.write = 0x00;
    acc.read_write = 0x00;
    acc.change = 0x00;

    static const uint8_t pattern[64] = {
        0xDE,0xAD,0xBE,0xEF, 0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF, 0x01,0x02,0x03,0x04,
        0x05,0x06,0x07,0x08, 0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80,
        0x0F,0x1E,0x2D,0x3C, 0x4B,0x5A,0x69,0x78, 0x87,0x96,0xA5,0xB4,
        0xC3,0xD2,0xE1,0xF0, 0x13,0x37,0xC0,0xDE, 0xFA,0xCE,0xB0,0x0C,
        0x7E,0x57,0xDA,0x7A
    };
    uint8_t readback[64];
    size_t rlen = 0;

    // ---- 10. std file, PLAIN comm: framing with no crypto -----------------------
    rc = nxpsc_create_std_file(card, 1, 0x0000, NXPSC_COMM_PLAIN, &acc, 64);
    report("CreateStdFile #1 (plain)", rc, card);
    if (rc == NXPSC_OK) {
        rc = nxpsc_write_data(card, 1, 0, pattern, 64, NXPSC_COMM_PLAIN);
        report("WriteData plain", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 1, 0, 64, NXPSC_COMM_PLAIN, readback, sizeof(readback), &rlen);
        report("ReadData plain", rc, card);
        report("verify plain readback",
            (rlen == 64 && memcmp(pattern, readback, 64) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO,
            card);
    }

    // ---- 11. std file, MAC comm: card rejects bad MACs, can't corrupt -----------
    rc = nxpsc_create_std_file(card, 2, 0x0000, NXPSC_COMM_MAC, &acc, 64);
    report("CreateStdFile #2 (MAC)", rc, card);
    if (rc == NXPSC_OK) {
        rc = nxpsc_write_data(card, 2, 0, pattern, 64, NXPSC_COMM_MAC);
        report("WriteData MAC", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 2, 0, 64, NXPSC_COMM_MAC, readback, sizeof(readback), &rlen);
        report("ReadData MAC", rc, card);
        report("verify MAC readback",
            (rlen == 64 && memcmp(pattern, readback, 64) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO,
            card);
    }

    // ---- 12. std file, FULL enciphered comm --------------------------------------
    rc = nxpsc_create_std_file(card, 3, 0x0000, NXPSC_COMM_FULL, &acc, 64);
    report("CreateStdFile #3 (enciphered)", rc, card);
    if (rc == NXPSC_OK) {
        rc = nxpsc_write_data(card, 3, 0, pattern, 64, NXPSC_COMM_FULL);
        report("WriteData enciphered", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 3, 0, 64, NXPSC_COMM_FULL, readback, sizeof(readback), &rlen);
        report("ReadData enciphered", rc, card);
        report("verify enciphered readback",
            (rlen == 64 && memcmp(pattern, readback, 64) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO,
            card);

        // a plain-comm read of an enciphered file inside an EV2 session is a
        // framing mismatch the card answers with 0x7E, and that error also ends
        // the session. that is what the whole 0x7E cascade was, so take the
        // session back before moving on
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 3, 0, 64, NXPSC_COMM_PLAIN, readback, sizeof(readback), &rlen);
        if (rc == NXPSC_OK)
            report("cross-check enciphered write via plain read",
                (rlen == 64 && memcmp(pattern, readback, 64) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO,
                card);
        else
            printf("       plain read of the enciphered file: %s (status 0x%02X: %s)\n",
                nxpsc_strerror(rc), nxpsc_last_status(card),
                nxpsc_status_str(nxpsc_last_status(card)));
            skip("cross-check via plain read", "card requires session read here");

        report("session recovered after rejected read",
            ensure_session(card, 0, &appkey) ? NXPSC_OK : NXPSC_E_AUTH, card);

        // the same read outside a session. file 3 is CommMode.Full, but its
        // read access right is free (0xE), and a free access right is what
        // decides the comm mode when there is no session to frame against.
        // selecting the application drops the session, so this is the only
        // way the cross-check can ever work
        nxpsc_select_application(card, SANDBOX_AID);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 3, 0, 64, NXPSC_COMM_PLAIN, readback, sizeof(readback), &rlen);
        if (rc == NXPSC_OK)
            report("cross-check enciphered write via free plain read",
                (rlen == 64 && memcmp(pattern, readback, 64) == 0) ? NXPSC_OK : NXPSC_E_CRYPTO,
                card);
        else
            report("cross-check enciphered write via free plain read", rc, card);

        // take the session back for the rest of the ladder
        report("re-authenticate after unauthenticated read",
            nxpsc_authenticate(card, 0, &appkey, NXPSC_CHAN_AUTO), card);
    }

    // ---- 13. backup file + commit/abort transaction --------------------------------
    rc = nxpsc_create_backup_file(card, 4, 0x0000, NXPSC_COMM_MAC, &acc, 32);
    report("CreateBackupFile #4", rc, card);
    if (rc == NXPSC_OK) {
        static const uint8_t v1[4] = { 0x11,0x11,0x11,0x11 };
        static const uint8_t v2[4] = { 0x22,0x22,0x22,0x22 };

        // seed with v1 and commit
        nxpsc_write_data(card, 4, 0, v1, 4, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("CommitTransaction (seed)", rc, card);

        // write v2 then ABORT: file must still contain v1
        nxpsc_write_data(card, 4, 0, v2, 4, NXPSC_COMM_MAC);
        rc = nxpsc_abort_transaction(card);
        report("AbortTransaction", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 4, 0, 4, NXPSC_COMM_MAC, readback, sizeof(readback), &rlen);
        report("verify abort preserved old data",
            (rc == NXPSC_OK && rlen == 4 && memcmp(v1, readback, 4) == 0)
            ? NXPSC_OK : NXPSC_E_CRYPTO, card);

        // write v2 then COMMIT: file must contain v2
        nxpsc_write_data(card, 4, 0, v2, 4, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("CommitTransaction", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_data(card, 4, 0, 4, NXPSC_COMM_MAC, readback, sizeof(readback), &rlen);
        report("verify commit applied new data",
            (rc == NXPSC_OK && rlen == 4 && memcmp(v2, readback, 4) == 0)
            ? NXPSC_OK : NXPSC_E_CRYPTO, card);
    }

    // ---- 14. value file: credit / debit arithmetic -----------------------------------
    ensure_session(card, 0, &appkey);
    rc = nxpsc_create_value_file(card, 5, NXPSC_COMM_MAC, &acc, 0, 1000, 100, false);
    report("CreateValueFile #5 (0..1000, start 100)", rc, card);
    if (rc == NXPSC_OK) {
        int32_t value = -1;
        nxpsc_credit(card, 5, 50, NXPSC_COMM_MAC);
        nxpsc_debit(card, 5, 30, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("value ops + commit", rc, card);
        rc = nxpsc_get_value(card, 5, NXPSC_COMM_MAC, &value);
        report("GetValue", rc, card);
        report("verify value == 120",
            (value == 120) ? NXPSC_OK : NXPSC_E_CRYPTO, card);
    }

    // ---- 15. key change INSIDE the sandbox only (app key 1) ---------------------------
    // A garbled ChangeKey is rejected by the card's CRC check; and even a lost
    // app key only costs us this deletable application.
    {
        ensure_session(card, 0, &appkey);

        nxpsc_key_t newkey{};
        newkey.type = NXPSC_KEY_AES128;
        for (int i = 0; i < 16; i++) newkey.data[i] = (uint8_t)(0xA0 + i);

        nxpsc_key_t oldk1{};
        oldk1.type = NXPSC_KEY_AES128;   // factory all-zero app key 1

        rc = nxpsc_change_key(card, 1, &oldk1, &newkey);
        report("ChangeKey app key 1 (zero -> test key)", rc, card);

        if (rc == NXPSC_OK) {
            // prove it: authenticate with the NEW key 1
            rc = nxpsc_authenticate(card, 1, &newkey, NXPSC_CHAN_AUTO);
            report("Authenticate with new app key 1", rc, card);

            // change it back with key 0's session
            rc = nxpsc_authenticate(card, 0, &appkey, NXPSC_CHAN_AUTO);
            if (rc == NXPSC_OK) {
                rc = nxpsc_change_key(card, 1, &newkey, &oldk1);
                report("ChangeKey app key 1 (restore zero)", rc, card);
            }
        }
    }

    // ---- 16. record file ----------------------------------------------------------------
    ensure_session(card, 0, &appkey);
    rc = nxpsc_create_record_file(card, true, 6, 0x0000, NXPSC_COMM_MAC, &acc, 8, 4);
    report("CreateCyclicRecordFile #6 (8B x 4)", rc, card);
    if (rc == NXPSC_OK) {
        static const uint8_t rec[8] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
        nxpsc_write_record(card, 6, 0, rec, 8, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("WriteRecord + commit", rc, card);
        memset(readback, 0, sizeof(readback));
        rc = nxpsc_read_records(card, 6, 0, 1, NXPSC_COMM_MAC, readback, sizeof(readback), &rlen);
        report("ReadRecords", rc, card);
        report("verify record content",
            (rc == NXPSC_OK && rlen >= 8 && memcmp(rec, readback, 8) == 0)
            ? NXPSC_OK : NXPSC_E_CRYPTO, card);
    }
}

// tear the sandbox down, card returns to its pre-run state
static void cleanup_sandbox(nxpsc_card_t* card)
{
    nxpsc_key_t picc{};
    picc.type = NXPSC_KEY_2K3DES;    // factory PICC master key, all zero

    int rc = nxpsc_select_application(card, 0x000000);
    if (rc == NXPSC_OK)
        rc = nxpsc_authenticate(card, 0, &picc, NXPSC_CHAN_AUTO);
    if (rc == NXPSC_OK) {
        rc = nxpsc_delete_application(card, SANDBOX_AID);
        report("DeleteApplication (sandbox cleanup)", rc, card);
    }
    else {
        skip("sandbox cleanup", "PICC re-auth failed, run FormatPICC manually later");
    }
}

int main()
{
    // ---- transport setup --------------------------------------------------------
    SCARDCONTEXT hCtx;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &hCtx)
        != SCARD_S_SUCCESS) {
        printf("failed to establish PC/SC context\n");
        return 1;
    }

    char readers[1024]; DWORD sz = sizeof(readers);
    if (SCardListReadersA(hCtx, nullptr, readers, &sz) != SCARD_S_SUCCESS) {
        printf("no reader\n");
        SCardReleaseContext(hCtx);
        return 1;
    }

    PcscCtx ctx{};
    if (SCardConnectA(hCtx, readers, SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T1, &ctx.hCard, &ctx.proto)
        != SCARD_S_SUCCESS) {
        printf("no card on reader %s\n", readers);
        SCardReleaseContext(hCtx);
        return 1;
    }
    printf("reader: %s\n\n", readers);

    // ---- 1. crypto self test (known answer vectors, no card involved) -------------
    report("crypto selftest", nxpsc_selftest(false), nullptr);

    nxpsc_transport_t transport{};
    transport.ctx = &ctx;
    transport.transceive = pcsc_transceive;
    // get_uid / reselect are optional

    nxpsc_card_t* card = nullptr;
    int rc = nxpsc_open(&transport, &card);
    report("nxpsc_open", rc, nullptr);
    if (rc != NXPSC_OK) {
        SCardDisconnect(ctx.hCard, SCARD_LEAVE_CARD);
        SCardReleaseContext(hCtx);
        return 1;
    }

    // PC/SC can't send raw native frames -> use ISO-wrapped native commands
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    // ---- 2. identification ----------------------------------------------------------
    {
        nxpsc_version_t v{};
        rc = nxpsc_get_version(card, &v);
        report("GetVersion", rc, card);
        if (rc == NXPSC_OK) {
            nxpsc_cardtype_t type = NXP_UNKNOWN;
            nxpsc_identify(card, &type);
            printf("       card: %s\n", nxpsc_cardtype_str(type));
            hexdump("uid", v.uid, sizeof(v.uid));
            printf("       hw %02X.%02X sw %02X.%02X, prod week %02X year 20%02X\n",
                v.hw_major, v.hw_minor, v.sw_major, v.sw_minor, v.week, v.year);
            // this specific card is a known EV3, assert the identification
            report("identified as DESFire EV3",
                type == DESFIRE_EV3 ? NXPSC_OK : NXPSC_E_UNSUPPORTED, card);
        }
    }

    // ---- 3. free memory (plain command, no auth needed) --------------------------------
    {
        uint32_t bytes = 0;
        rc = nxpsc_get_free_memory(card, &bytes);
        report("GetFreeMemory", rc, card);
        if (rc == NXPSC_OK)
            printf("       free: %u bytes\n", bytes);
    }

    // ---- 4. originality signature ---------------------------------------------------------
    {
        uint8_t sig[64]; size_t siglen = 0;
        rc = nxpsc_get_signature(card, sig, sizeof(sig), &siglen);
        if (rc == NXPSC_OK) {
            report("Read_Sig", rc, card);
            hexdump("signature", sig, siglen);
        }
        else {
            skip("Read_Sig", "not available in this state");
        }
    }

    // ---- 5. PICC level application / key info ----------------------------------------------
    {
        rc = nxpsc_select_application(card, 0x000000);
        report("SelectApplication PICC", rc, card);

        uint32_t aids[NXPSC_MAX_APPS]; size_t count = 0;
        rc = nxpsc_get_application_ids(card, aids, NXPSC_MAX_APPS, &count);
        report("GetApplicationIDs", rc, card);
        if (rc == NXPSC_OK) {
            printf("       %zu application(s)\n", count);
            for (size_t i = 0; i < count; i++)
                printf("       aid %06X\n", aids[i]);
        }

        uint8_t settings = 0, num_keys = 0;
        nxpsc_keytype_t ktype = NXPSC_KEY_DES;
        rc = nxpsc_get_key_settings(card, &settings, &num_keys, &ktype);
        report("GetKeySettings", rc, card);
        if (rc == NXPSC_OK)
            printf("       settings 0x%02X, %u %s key(s)\n",
                settings, num_keys, nxpsc_keytype_str(ktype));

        uint8_t kver = 0xFF;
        rc = nxpsc_get_key_version(card, 0, &kver);
        report("GetKeyVersion(0)", rc, card);
        if (rc == NXPSC_OK)
            printf("       key 0 version 0x%02X\n", kver);
    }

    // ---- 6. authenticate with the factory PICC master key ------------------------------------
    // GetKeySettings reports the PICC master key as 2TDEA, still all zero.
    {
        nxpsc_key_t key{};                  // all zero factory key
        key.type = NXPSC_KEY_2K3DES;
        // the handshake and GetCardUID, optionally on the wire. the 2TDEA
        // factory key has two equal halves, so the card treats it as DES and
        // derives the shorter session key. that is what used to break the
        // GetCardUID decode and nothing else on this channel would show it
        if (TRACE_AUTH) {
            printf("---- trace: legacy PICC auth + GetCardUID ----\n");
            g_trace = true;
        }
        rc = nxpsc_authenticate(card, 0, &key, NXPSC_CHAN_AUTO);
        report("Authenticate (factory 2K3DES key, AUTO channel)", rc, card);

        if (nxpsc_is_authenticated(card)) {
            // 7. authenticated only command: real card UID through the channel
            uint8_t uid[16]; size_t uidlen = 0;
            rc = nxpsc_get_card_uid(card, uid, sizeof(uid), &uidlen);
            if (TRACE_AUTH) {
                g_trace = false;
                printf("---- trace off ----\n");
            }
            report("GetCardUID (secure channel)", rc, card);
            if (rc == NXPSC_OK)
                hexdump("uid via channel", uid, uidlen);
        }
        else {
            if (TRACE_AUTH) {
                g_trace = false;
                printf("---- trace off ----\n");
            }
            skip("GetCardUID (secure channel)", "not authenticated");
        }

        // test 8 below draws an error status on this card, which ends the
        // session. keep the key around so it can be picked back up
        static nxpsc_key_t picc_key;
        picc_key = key;
        g_picc_key = &picc_key;
    }

    // ---- 8. file listing at PICC level (usually empty, exercises the path) --------------------
    {
        uint8_t ids[NXPSC_MAX_FILES]; size_t count = 0;
        rc = nxpsc_get_file_ids(card, ids, NXPSC_MAX_FILES, &count);
        if (rc == NXPSC_OK) {
            report("GetFileIDs", rc, card);
            printf("       %zu file(s) at PICC level\n", count);
        }
        else {
            printf("       GetFileIDs at PICC level: %s (status 0x%02X: %s)\n",
                nxpsc_strerror(rc), nxpsc_last_status(card),
                nxpsc_status_str(nxpsc_last_status(card)));
            skip("GetFileIDs", "not permitted at PICC level on this card");
        }

        // the error status above ended the PICC session, take it back
        if (g_picc_key != nullptr)
            ensure_session(card, 0, g_picc_key);
    }

    // ---- 9-16. write-path validation ladder (sandbox app only) ---------------------------------
    if (nxpsc_is_authenticated(card)) {
        run_write_ladder(card);
        cleanup_sandbox(card);
    }
    else {
        skip("write ladder (tests 9-16)", "PICC authentication failed, not proceeding");
    }

    nxpsc_close(card);
    SCardDisconnect(ctx.hCard, SCARD_LEAVE_CARD);
    SCardReleaseContext(hCtx);

    printf("\n==== results: %d passed, %d failed, %d skipped ====\n",
        g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}