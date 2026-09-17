//-----------------------------------------------------------------------------
// Crucible - libnxpsc extended hardware validation, tier 1
//
// Tessera covers the paths a normal application uses. Crucible covers what it
// deliberately left out, starting with everything that is still recoverable.
//
// Tier 1, what this program does today: every call happens inside a throwaway
// application (AID 0xDDEE02, distinct from Tessera's sandbox) created and
// deleted by this run. Nothing here touches the PICC master key, the PICC key
// settings, or any SetConfiguration path. If any step wedges the application,
// DeleteApplication under the PICC master key undoes it, and FormatPICC is the
// backstop behind that.
//
// Tier 3, not implemented yet: PICC master key change and PICC key settings.
// Those are recoverable only while nothing goes wrong, so they wait until
// tier 1 is green.
//
// Never in this program: SetConfiguration in any form. Disabling FormatPICC or
// enabling random UID is one way on this silicon and would cost the card.
//-----------------------------------------------------------------------------

#include <winscard.h>
#include <cstdio>
#include <cstring>
extern "C" {
#include <nxpsc/nxpsc.h>
}

#pragma comment(lib, "winscard.lib")
#pragma comment(lib, "nxpsc.lib")
#pragma comment(lib, "bcrypt.lib")

struct PcscCtx {
    SCARDHANDLE hCard;
    DWORD proto;
};

static int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen)
{
    PcscCtx* ctx = static_cast<PcscCtx*>(vctx);
    DWORD rlen = static_cast<DWORD>(rxcap);
    if (SCardTransmit(ctx->hCard, SCARD_PCI_T1,
        tx, static_cast<DWORD>(txlen), nullptr, rx, &rlen) != SCARD_S_SUCCESS)
        return NXPSC_E_TRANSPORT;
    *rxlen = rlen;
    return NXPSC_OK;
}

// PreparePC puts the card into proximity check mode and it stays there until
// the sequence finishes or the field drops, answering 0x0B to everything else.
// PC/SC disconnects with SCARD_LEAVE_CARD, so without this the state survives
// the process and poisons the next run.
static PcscCtx* g_pcsc = nullptr;

static bool reset_card()
{
    if (g_pcsc == nullptr) return false;
    DWORD proto = 0;
    LONG rc = SCardReconnect(g_pcsc->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        SCARD_RESET_CARD, &proto);
    return rc == SCARD_S_SUCCESS;
}

// ---- harness -------------------------------------------------------------------
static int g_pass = 0, g_fail = 0, g_skip = 0;

static void report(const char* name, int rc, nxpsc_card_t* card)
{
    if (rc == NXPSC_OK) {
        printf("[PASS] %s\n", name);
        g_pass++;
        return;
    }
    printf("[FAIL] %s: %s", name, nxpsc_strerror(rc));
    if (rc == NXPSC_E_CARD && card)
        printf(" (status 0x%02X: %s)",
            nxpsc_last_status(card), nxpsc_status_str(nxpsc_last_status(card)));
    printf("\n");
    g_fail++;
}

static void check(const char* name, bool ok, nxpsc_card_t* card)
{
    report(name, ok ? NXPSC_OK : NXPSC_E_CRYPTO, card);
}

// for paths the card may legitimately not offer. prints what it actually said
static void unsupported(const char* name, int rc, nxpsc_card_t* card)
{
    printf("[SKIP] %s: %s", name, nxpsc_strerror(rc));
    if (rc == NXPSC_E_CARD && card)
        printf(" (status 0x%02X: %s)",
            nxpsc_last_status(card), nxpsc_status_str(nxpsc_last_status(card)));
    printf("\n");
    g_skip++;
}

// the DESFire CRC32 is the JAMCRC variant, reimplemented here because the
// library keeps its own copy internal to the build
static void nxpsc_crc32_helper(const uint8_t* data, size_t len, uint8_t* out)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (~((crc & 1) - 1)));
    }
    out[0] = static_cast<uint8_t>(crc & 0xFF);
    out[1] = static_cast<uint8_t>((crc >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((crc >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((crc >> 24) & 0xFF);
}

static const uint32_t CRUCIBLE_AID = 0xDDEE02;
static const char DF_NAME[] = "nxpsc.crucible";

// Always authenticate, never assume the running session is on the key we want.
// Checking only "am I authenticated" hides the case where an earlier step left
// the session on a different key, and the card then answers 0xAE.
static bool use_key(nxpsc_card_t* card, uint8_t key_no, const nxpsc_key_t* key)
{
    int rc = nxpsc_authenticate(card, key_no, key, NXPSC_CHAN_AUTO);
    if (rc != NXPSC_OK)
        printf("       could not take key %u: %s\n", key_no, nxpsc_strerror(rc));
    return rc == NXPSC_OK;
}

// A full key set rotation in its own throwaway application: build a set, fill
// it, freeze it, switch to it, and prove the new keys are the live ones. The
// application is deleted either way, so a rotation that leaves keys in an
// unknown state costs nothing.
//
// Three things here were only learnt from the card. InitializeKeySet's second
// byte is the new set's key type carried unshifted, so AES is 0x02, and a set
// built as 2TDEA inside an AES application takes 2TDEA shaped ChangeKeyEV2
// payloads and can never be rolled. The low nibble of the rollKey access right
// names the key allowed to issue the roll. And the roll swaps out the key the
// running session was built from, so the card answers it without a MAC.
static void run_key_set_rotation(nxpsc_card_t* card, uint8_t roll_key)
{
    const uint32_t AID = 0xDDEE03;
    nxpsc_key_t picc{};
    picc.type = NXPSC_KEY_2K3DES;
    nxpsc_key_t appkey{};
    appkey.type = NXPSC_KEY_AES128;

    nxpsc_key_t fresh[3]{};
    for (int k = 0; k < 3; k++) {
        fresh[k].type = NXPSC_KEY_AES128;
        for (int i = 0; i < 16; i++)
            fresh[k].data[i] = static_cast<uint8_t>(0x90 + k * 0x10 + i);
    }

    nxpsc_select_application(card, 0x000000);
    if (use_key(card, 0, &picc) == false) return;
    nxpsc_delete_application(card, AID);
    use_key(card, 0, &picc);

    nxpsc_app_config_t cfg{};
    cfg.key_settings = 0x0F;
    cfg.num_keys = 3;
    cfg.key_type = NXPSC_KEY_AES128;
    cfg.num_key_sets = 2;           // NoKeySets has to be 2..16
    cfg.key_set_version = 0x00;
    cfg.max_key_size = 16;          // 16 or 24, nothing else
    cfg.key_set_settings = roll_key;

    int rc = nxpsc_create_application_ex(card, AID, &cfg);
    report("CreateApplicationEx (2 key sets, AES)", rc, card);
    if (rc != NXPSC_OK) { use_key(card, 0, &picc); return; }

    if (nxpsc_select_application(card, AID) != NXPSC_OK || use_key(card, 0, &appkey) == false) {
        report("SelectApplication (key set app)", NXPSC_E_AUTH, card);
        return;
    }

    rc = nxpsc_init_key_set(card, 1, NXPSC_KEY_AES128);
    report("InitializeKeySet 1 as AES", rc, card);

    for (int k = 0; k < 3 && rc == NXPSC_OK; k++) {
        use_key(card, 0, &appkey);
        rc = nxpsc_change_key_ev2(card, 1, static_cast<uint8_t>(k), &appkey, &fresh[k]);
        char label[64];
        snprintf(label, sizeof(label), "ChangeKeyEV2 into key set 1, key %d", k);
        report(label, rc, card);
    }

    if (rc == NXPSC_OK) {
        use_key(card, 0, &appkey);
        rc = nxpsc_finalize_key_set(card, 1, 0x01);
        report("FinalizeKeySet 1", rc, card);
    }

    if (rc == NXPSC_OK) {
        // the active set still holds the factory keys, so the nominated
        // authority can be taken whichever key number it is
        if (use_key(card, roll_key, &appkey)) {
            rc = nxpsc_roll_key_set(card, 1);
            report("RollKeySet 1", rc, card);
        }
        else {
            report("RollKeySet 1", NXPSC_E_AUTH, card);
            rc = NXPSC_E_AUTH;
        }
    }

    if (rc == NXPSC_OK) {
        report("Authenticate with the rolled key 1",
            nxpsc_authenticate(card, 1, &fresh[1], NXPSC_CHAN_AUTO), card);
        check("the key the rotation replaced no longer authenticates",
            nxpsc_authenticate(card, 1, &appkey, NXPSC_CHAN_AUTO) != NXPSC_OK, card);
    }

    nxpsc_select_application(card, 0x000000);
    if (use_key(card, 0, &picc))
        report("DeleteApplication (key set app)",
            nxpsc_delete_application(card, AID), card);
}

//-----------------------------------------------------------------------------
// tier 1
//-----------------------------------------------------------------------------
static void run_tier1(nxpsc_card_t* card)
{
    int rc;
    nxpsc_key_t appkey{};
    appkey.type = NXPSC_KEY_AES128;      // factory all-zero app keys

    // ---- application with an ISO file id and a DF name -------------------------
    rc = nxpsc_create_application_iso(card, CRUCIBLE_AID, 0x0F, 3, NXPSC_KEY_AES128,
        0xE110, reinterpret_cast<const uint8_t*>(DF_NAME), sizeof(DF_NAME) - 1);
    if (rc == NXPSC_E_CARD && nxpsc_last_status(card) == 0xDE) {
        // a leftover from an interrupted run. the 0xDE ended the session, so
        // take it back before trying to clear the application away
        nxpsc_key_t picc{};
        picc.type = NXPSC_KEY_2K3DES;
        use_key(card, 0, &picc);
        nxpsc_delete_application(card, CRUCIBLE_AID);
        use_key(card, 0, &picc);
        rc = nxpsc_create_application_iso(card, CRUCIBLE_AID, 0x0F, 3, NXPSC_KEY_AES128,
            0xE110, reinterpret_cast<const uint8_t*>(DF_NAME), sizeof(DF_NAME) - 1);
    }
    report("CreateApplicationISO (fid 0xE110, df name)", rc, card);
    if (rc != NXPSC_OK) return;

    // GetDFNames reports what the card stored for it
    {
        nxpsc_app_t apps[8]{};
        size_t count = 0;
        rc = nxpsc_get_df_names(card, apps, 8, &count);
        if (rc == NXPSC_OK) {
            report("GetDFNames", rc, card);
            bool found = false;
            for (size_t i = 0; i < count; i++) {
                if (apps[i].aid != CRUCIBLE_AID) continue;
                found = apps[i].iso_fid == 0xE110
                    && apps[i].df_name_len == sizeof(DF_NAME) - 1
                    && memcmp(apps[i].df_name, DF_NAME, sizeof(DF_NAME) - 1) == 0;
                break;
            }
            check("DF name and ISO fid survived the round trip", found, card);
        }
        else {
            unsupported("GetDFNames", rc, card);
        }
    }

    rc = nxpsc_select_application(card, CRUCIBLE_AID);
    report("SelectApplication (crucible)", rc, card);
    if (rc != NXPSC_OK) return;

    rc = nxpsc_authenticate(card, 0, &appkey, NXPSC_CHAN_AUTO);
    report("Authenticate (app key 0, AES, EV2First)", rc, card);
    if (rc != NXPSC_OK) return;

    nxpsc_access_t acc{};
    acc.read = 0x0E;        // free read, so the cross-checks can run unauthenticated
    acc.write = 0x00;
    acc.read_write = 0x00;
    acc.change = 0x00;

    // ---- 1. file settings round trip ---------------------------------------------
    rc = nxpsc_create_std_file(card, 1, 0xE111, NXPSC_COMM_PLAIN, &acc, 64);
    report("CreateStdFile #1 (iso fid 0xE111)", rc, card);

    if (rc == NXPSC_OK) {
        nxpsc_file_settings_t fs{};
        rc = nxpsc_get_file_settings(card, 1, &fs);
        report("GetFileSettings #1", rc, card);
        if (rc == NXPSC_OK) {
            check("settings match what CreateStdFile asked for",
                fs.type == NXPSC_FILE_STD && fs.comm == NXPSC_COMM_PLAIN && fs.size == 64
                && fs.access.read == 0x0E && fs.access.write == 0x00
                && fs.access.read_write == 0x00 && fs.access.change == 0x00, card);
        }

        // flip the comm mode and read it back
        nxpsc_access_t tighter = acc;
        tighter.read = 0x00;
        rc = nxpsc_change_file_settings(card, 1, NXPSC_COMM_FULL, &tighter);
        report("ChangeFileSettings #1 -> enciphered, key 0 read", rc, card);
        if (rc == NXPSC_OK) {
            nxpsc_file_settings_t after{};
            rc = nxpsc_get_file_settings(card, 1, &after);
            if (rc == NXPSC_OK)
                check("the change is what the card reports back",
                    after.comm == NXPSC_COMM_FULL && after.access.read == 0x00, card);
            else
                report("GetFileSettings #1 after change", rc, card);

            // put it back, later steps want the free read
            rc = nxpsc_change_file_settings(card, 1, NXPSC_COMM_PLAIN, &acc);
            report("ChangeFileSettings #1 -> back to plain", rc, card);
        }
    }

    // ---- 2. ISO fids are mandatory here, then delete a file ---------------------------
    // the application carries an ISO file id, which makes one mandatory for every
    // file inside it. asking for a file without one builds a frame two bytes
    // shorter than the card expects, and it answers 0x7E
    use_key(card, 0, &appkey);
    rc = nxpsc_create_std_file(card, 2, 0x0000, NXPSC_COMM_PLAIN, &acc, 16);
    check("a file with no ISO fid is refused in an ISO application",
        rc == NXPSC_E_CARD && nxpsc_last_status(card) == 0x7E, card);

    use_key(card, 0, &appkey);
    rc = nxpsc_create_std_file(card, 2, 0xE113, NXPSC_COMM_PLAIN, &acc, 16);
    report("CreateStdFile #2 (iso fid 0xE113)", rc, card);
    if (rc == NXPSC_OK) {
        rc = nxpsc_delete_file(card, 2);
        report("DeleteFile #2", rc, card);

        uint8_t ids[NXPSC_MAX_FILES]{};
        size_t count = 0;
        if (nxpsc_get_file_ids(card, ids, NXPSC_MAX_FILES, &count) == NXPSC_OK) {
            bool gone = true;
            for (size_t i = 0; i < count; i++)
                if (ids[i] == 2) gone = false;
            check("deleted file is no longer listed", gone, card);
        }
    }

    use_key(card, 0, &appkey);

    // ---- 3. ISO file ids -------------------------------------------------------------
    {
        uint16_t iso_ids[NXPSC_MAX_FILES]{};
        size_t count = 0;
        rc = nxpsc_get_iso_file_ids(card, iso_ids, NXPSC_MAX_FILES, &count);
        if (rc == NXPSC_OK) {
            report("GetISOFileIDs", rc, card);
            bool found = false;
            for (size_t i = 0; i < count; i++)
                if (iso_ids[i] == 0xE111) found = true;
            check("file 1 reports its ISO fid 0xE111", found, card);
        }
        else {
            unsupported("GetISOFileIDs", rc, card);
        }
    }

    use_key(card, 0, &appkey);

    // ---- 4. records: update in place and clear ----------------------------------------
    rc = nxpsc_create_record_file(card, false, 3, 0xE112, NXPSC_COMM_MAC, &acc, 8, 4);
    report("CreateLinearRecordFile #3 (8B x 4)", rc, card);
    if (rc == NXPSC_OK) {
        static const uint8_t rec_a[8] = { 0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7 };
        static const uint8_t rec_b[8] = { 0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7 };
        static const uint8_t patch[4] = { 0xC0,0xC1,0xC2,0xC3 };
        uint8_t back[64]{};
        size_t blen = 0;

        // a record file holds one pending record per transaction, so two
        // records means two commits. writing twice before a commit just
        // rewrites the same pending record
        nxpsc_write_record(card, 3, 0, rec_a, 8, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("WriteRecord + commit (record 1)", rc, card);

        use_key(card, 0, &appkey);
        nxpsc_write_record(card, 3, 0, rec_b, 8, NXPSC_COMM_MAC);
        rc = nxpsc_commit_transaction(card);
        report("WriteRecord + commit (record 2)", rc, card);

        use_key(card, 0, &appkey);

        rc = nxpsc_read_records(card, 3, 0, 2, NXPSC_COMM_MAC, back, sizeof(back), &blen);
        report("ReadRecords", rc, card);

        // Two facts, and they pull in opposite directions. Record numbers count
        // back from the newest, so record 0 is rec_b and record 1 is rec_a. But
        // a multi record read hands the span back in chronological order, so
        // asking for two records starting at 0 gives rec_a then rec_b. Assert
        // both, a test that only pinned one would pass on the wrong ordering.
        if (rc == NXPSC_OK) {
            bool chronological = (blen == 16 && memcmp(back, rec_a, 8) == 0
                && memcmp(back + 8, rec_b, 8) == 0);
            if (chronological == false) {
                printf("       got %zu bytes: ", blen);
                for (size_t i = 0; i < blen && i < 32; i++) printf("%02X", back[i]);
                printf("\n");
            }
            check("a two record read comes back oldest first", chronological, card);
        }

        use_key(card, 0, &appkey);
        memset(back, 0, sizeof(back));
        rc = nxpsc_read_records(card, 3, 0, 1, NXPSC_COMM_MAC, back, sizeof(back), &blen);
        if (rc == NXPSC_OK)
            check("record 0 on its own is the newest record",
                blen == 8 && memcmp(back, rec_b, 8) == 0, card);
        else
            report("ReadRecords (record 0 alone)", rc, card);

        use_key(card, 0, &appkey);
        memset(back, 0, sizeof(back));
        rc = nxpsc_read_records(card, 3, 1, 1, NXPSC_COMM_MAC, back, sizeof(back), &blen);
        if (rc == NXPSC_OK)
            check("record 1 is the one written before it",
                blen == 8 && memcmp(back, rec_a, 8) == 0, card);
        else
            report("ReadRecords (record 1 alone)", rc, card);

        // patch the first four bytes of the newest record in place
        use_key(card, 0, &appkey);
        rc = nxpsc_update_record(card, 3, 0, 0, patch, sizeof(patch), NXPSC_COMM_MAC);
        report("UpdateRecord (patch record 0 in place)", rc, card);
        if (rc == NXPSC_OK) {
            rc = nxpsc_commit_transaction(card);
            report("commit the update", rc, card);

            memset(back, 0, sizeof(back));
            rc = nxpsc_read_records(card, 3, 0, 1, NXPSC_COMM_MAC, back, sizeof(back), &blen);
            if (rc == NXPSC_OK)
                check("update landed and left the tail alone",
                    blen == 8 && memcmp(back, patch, 4) == 0
                    && memcmp(back + 4, rec_b + 4, 4) == 0, card);
            else
                report("ReadRecords after update", rc, card);
        }

        use_key(card, 0, &appkey);
        rc = nxpsc_clear_record_file(card, 3);
        report("ClearRecordFile #3", rc, card);
        if (rc == NXPSC_OK) {
            rc = nxpsc_commit_transaction(card);
            report("commit the clear", rc, card);

            nxpsc_file_settings_t fs{};
            if (nxpsc_get_file_settings(card, 3, &fs) == NXPSC_OK)
                check("record count is back to zero", fs.cur_records == 0, card);
        }
    }

    use_key(card, 0, &appkey);

    // ---- 5. value file with limited credit ---------------------------------------------
    rc = nxpsc_create_value_file(card, 4, NXPSC_COMM_MAC, &acc, 0, 1000, 500, true);
    report("CreateValueFile #4 (limited credit enabled)", rc, card);
    if (rc == NXPSC_OK) {
        int32_t value = -1;

        rc = nxpsc_debit(card, 4, 200, NXPSC_COMM_MAC);
        if (rc == NXPSC_OK) rc = nxpsc_commit_transaction(card);
        report("Debit 200 + commit", rc, card);

        // limited credit may only put back what this session debited
        rc = nxpsc_limited_credit(card, 4, 100, NXPSC_COMM_MAC);
        if (rc == NXPSC_OK) {
            rc = nxpsc_commit_transaction(card);
            report("LimitedCredit 100 + commit", rc, card);
            if (nxpsc_get_value(card, 4, NXPSC_COMM_MAC, &value) == NXPSC_OK)
                check("value is 500 - 200 + 100 == 400", value == 400, card);
        }
        else {
            unsupported("LimitedCredit 100", rc, card);
            use_key(card, 0, &appkey);
        }
    }

    use_key(card, 0, &appkey);

    // ---- 6. EV2 AuthenticateNonFirst -----------------------------------------------------
    rc = nxpsc_authenticate_nonfirst(card, 1, &appkey);
    if (rc == NXPSC_OK) {
        report("AuthenticateNonFirst (app key 1)", rc, card);

        // the session has to keep working, and on the new key
        uint8_t version = 0xFF;
        rc = nxpsc_get_key_version(card, 1, &version);
        report("MACed command on the NonFirst session", rc, card);
    }
    else {
        unsupported("AuthenticateNonFirst (app key 1)", rc, card);
        use_key(card, 0, &appkey);
    }

    // ---- 7. ChangeKeyEV2 on a sandbox app key -----------------------------------------------
    {
        use_key(card, 0, &appkey);

        nxpsc_key_t newkey{};
        newkey.type = NXPSC_KEY_AES128;
        for (int i = 0; i < 16; i++) newkey.data[i] = static_cast<uint8_t>(0x50 + i);

        rc = nxpsc_change_key_ev2(card, 0, 2, &appkey, &newkey);
        if (rc == NXPSC_OK) {
            report("ChangeKeyEV2 (key set 0, app key 2)", rc, card);

            rc = nxpsc_authenticate(card, 2, &newkey, NXPSC_CHAN_AUTO);
            report("Authenticate with the changed key 2", rc, card);

            if (rc == NXPSC_OK && use_key(card, 0, &appkey)) {
                rc = nxpsc_change_key_ev2(card, 0, 2, &newkey, &appkey);
                report("ChangeKeyEV2 (restore app key 2)", rc, card);
            }
        }
        else {
            unsupported("ChangeKeyEV2 (key set 0, app key 2)", rc, card);
            use_key(card, 0, &appkey);
        }
    }

    // ---- 8. ISO 7816-4 access to the same files ---------------------------------------------
    {
        use_key(card, 0, &appkey);

        rc = nxpsc_iso_select_df_name(card, reinterpret_cast<const uint8_t*>(DF_NAME),
            sizeof(DF_NAME) - 1);
        if (rc == NXPSC_OK) report("ISO SelectFile by DF name", rc, card);
        else unsupported("ISO SelectFile by DF name", rc, card);

        rc = nxpsc_iso_select_fid(card, 0xE111, true);
        if (rc == NXPSC_OK) report("ISO SelectFile by fid 0xE111", rc, card);
        else unsupported("ISO SelectFile by fid 0xE111", rc, card);

        uint8_t iso_buf[32]{};
        size_t iso_len = 0;
        rc = nxpsc_iso_read_binary(card, 0, 0, 16, iso_buf, sizeof(iso_buf), &iso_len);
        if (rc == NXPSC_OK) report("ISO ReadBinary", rc, card);
        else unsupported("ISO ReadBinary", rc, card);

        // an ISO select drops the DESFire session, take the application back
        nxpsc_select_application(card, CRUCIBLE_AID);
        use_key(card, 0, &appkey);
    }

    // ---- 9. ISO chaining opcodes --------------------------------------------------------------
    {
        bool was = nxpsc_get_iso_chaining(card);
        nxpsc_set_iso_chaining(card, true);
        check("SetISOChaining is reflected by the getter",
            nxpsc_get_iso_chaining(card) == true, card);

        uint8_t buf[64]{};
        size_t blen = 0;
        rc = nxpsc_read_data(card, 1, 0, 16, NXPSC_COMM_PLAIN, buf, sizeof(buf), &blen);
        if (rc == NXPSC_OK) report("ReadData over the ISO chaining opcode 0xAD", rc, card);
        else unsupported("ReadData over the ISO chaining opcode 0xAD", rc, card);

        nxpsc_set_iso_chaining(card, was);
        use_key(card, 0, &appkey);
    }

    // ---- 11. transaction MAC file ------------------------------------------------------------------
    // ordered late: once a TMAC file exists every later commit in this
    // application wants a reader id alongside it
    {
        use_key(card, 0, &appkey);

        nxpsc_key_t tm_key{};
        tm_key.type = NXPSC_KEY_AES128;
        for (int i = 0; i < 16; i++) tm_key.data[i] = static_cast<uint8_t>(0x70 + i);

        // the ReadWrite right is what switches CommitReaderID on for a TMAC
        // file: 0x0F disables it, 0x0E is free access, 0x00..0x04 names a key
        nxpsc_access_t tm_acc{};
        tm_acc.read = 0x0E;
        tm_acc.write = 0x0F;        // writing a TMAC file is always denied
        tm_acc.read_write = 0x00;   // CommitReaderID under key 0
        tm_acc.change = 0x00;

        rc = nxpsc_create_transaction_mac_file(card, 5, NXPSC_COMM_PLAIN, &tm_acc, &tm_key, 0);
        if (rc != NXPSC_OK) {
            unsupported("CreateTransactionMACFile #5", rc, card);
            use_key(card, 0, &appkey);
        }
        else {
            report("CreateTransactionMACFile #5", rc, card);

            static const uint8_t reader_id[16] = {
                0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
            };
            uint8_t prev[32]{};
            size_t prev_len = 0;
            rc = nxpsc_commit_reader_id(card, reader_id, sizeof(reader_id),
                prev, sizeof(prev), &prev_len);
            if (rc == NXPSC_OK) {
                report("CommitReaderID", rc, card);
            }
            else {
                unsupported("CommitReaderID", rc, card);
                printf("       the TMAC file has to carry the reader id option, and\n"
                       "       nxpsc_create_transaction_mac_file() has no parameter\n"
                       "       for it, so this path is unreachable from the library\n");
                use_key(card, 0, &appkey);
            }

            rc = nxpsc_notify_transaction_success(card);
            if (rc == NXPSC_OK) report("NotifyTransactionSuccess", rc, card);
            else { unsupported("NotifyTransactionSuccess", rc, card); use_key(card, 0, &appkey); }
        }
    }

    // ---- 10. proximity check ---------------------------------------------------------------------
    // What holds on EV3, established here rather than assumed:
    //   - PreparePC answers 0x90, not 0x00. libnxpsc used to call that an error
    //   - it answers Option 0x01, published response time 0x0320, PPS1 0x0A,
    //     and bit 0 of Option is what says the PPS1 byte is there
    //   - it is application scoped. at PICC level it answers 0x0B
    //   - it puts the card into proximity check mode, where everything else
    //     answers 0x0B until the sequence finishes or the field drops
    //   - the MAC construction in libnxpsc matches LogicalAccess exactly, so
    //     the reason it does not verify is the key, not the layout. the card
    //     MACs with its VC Proximity Key, key 0x21 of the application, which an
    //     application only owns when it was created with specific VC keys
    {
        use_key(card, 0, &appkey);

        uint8_t prep[32]{};
        size_t prep_len = 0;
        int prc = nxpsc_command(card, 0xF0, nullptr, 0, NXPSC_COMM_PLAIN,
                                NXPSC_COMM_PLAIN, prep, sizeof(prep), &prep_len);
        printf("       PreparePC -> %s, status 0x%02X, %zu bytes: ",
            prc == NXPSC_OK ? "ok" : nxpsc_strerror(prc),
            nxpsc_last_status(card), prep_len);
        for (size_t i = 0; i < prep_len; i++) printf("%02X", prep[i]);
        printf("\n");
        check("PreparePC answers Option, published response time and PPS1",
            prc == NXPSC_OK && prep_len == 4 && (prep[0] & 0x01) != 0, card);

        // a second PreparePC while the card is already prepared answers 0x0B
        check("the card is in proximity check mode and refuses other commands",
            nxpsc_get_free_memory(card, nullptr) != NXPSC_OK
                || nxpsc_last_status(card) == 0x0B, card);
        check("a reset recovers the card from proximity check mode", reset_card(), card);

        nxpsc_reset_channel(card);
        nxpsc_select_application(card, CRUCIBLE_AID);
        use_key(card, 0, &appkey);

        // an application that carries its own VC keys has a key 0x21, which is
        // what the card MACs the proximity check with
        {
            const uint32_t VC_AID = 0xDDEE05;
            nxpsc_key_t picc{};
            picc.type = NXPSC_KEY_2K3DES;

            nxpsc_select_application(card, 0x000000);
            use_key(card, 0, &picc);
            nxpsc_delete_application(card, VC_AID);
            use_key(card, 0, &picc);

            nxpsc_app_config_t vcfg{};
            vcfg.key_settings = 0x0F;
            vcfg.num_keys = 3;
            vcfg.key_type = NXPSC_KEY_AES128;
            vcfg.specific_vc_keys = true;

            int vrc = nxpsc_create_application_ex(card, VC_AID, &vcfg);
            if (vrc == NXPSC_OK) {
                report("CreateApplicationEx (specific VC keys)", vrc, card);
            }
            else {
                unsupported("CreateApplicationEx (specific VC keys)", vrc, card);
                printf("       the PICC refuses an application with its own VC keys in\n"
                       "       its current configuration. turning virtual card support on\n"
                       "       is a SetConfiguration path, which is out of scope here, so\n"
                       "       key 0x21 cannot be reached and the proximity check MAC\n"
                       "       stays unverifiable on this card\n");
                use_key(card, 0, &picc);
            }

            if (vrc == NXPSC_OK && nxpsc_select_application(card, VC_AID) == NXPSC_OK) {
                use_key(card, 0, &appkey);

                nxpsc_key_t vc_prox{};
                vc_prox.type = NXPSC_KEY_AES128;    // key 0x21, factory all zero

                bool mac_ok = false;
                int prc2 = nxpsc_proximity_check(card, &vc_prox, 8, &mac_ok);
                printf("       ProximityCheck with the VC proximity key -> %s",
                    prc2 == NXPSC_OK ? "ok" : nxpsc_strerror(prc2));
                if (prc2 == NXPSC_E_CARD) printf(" (status 0x%02X)", nxpsc_last_status(card));
                printf(", MAC %s\n", mac_ok ? "VERIFIED" : "mismatch");

                if (prc2 == NXPSC_OK) {
                    report("ProximityCheck", prc2, card);
                    check("proximity check MAC verified", mac_ok, card);
                }
                else {
                    unsupported("ProximityCheck", prc2, card);
                }

                reset_card();
                nxpsc_reset_channel(card);
            }

            nxpsc_select_application(card, 0x000000);
            if (use_key(card, 0, &picc))
                nxpsc_delete_application(card, VC_AID);
        }

        reset_card();
        nxpsc_reset_channel(card);
        nxpsc_select_application(card, CRUCIBLE_AID);
        use_key(card, 0, &appkey);
    }

    // ---- 12. key sets ----------------------------------------------------------------
    // Everything but RollKeySet is settled. What is known about the roll:
    //   - it takes exactly one byte, two answers 0x7E
    //   - the low nibble of AppKeySetSett names the key allowed to issue it.
    //     authenticating as any other key answers 0xAE, as that key answers 0x9D
    //   - ordering does not matter, it answers the same before and after
    //     FinalizeKeySet, with every key in the set written
    //   - there is no key set selector in the Authenticate key number, 0x10,
    //     0x40 and 0x80 all fail to authenticate at all
    // So the low nibble is the authority and something else still gates it.
    // Sweep AppKeySetSett and run the whole rotation under each value the card
    // accepts, authenticating as the key that value nominates.
    {
        // the high nibble of AppKeySetSett is refused outright, so the field is
        // just a key number. two sets makes the rotation unambiguous, four
        // leaves sets 2 and 3 untouched, which may be what it objects to
        run_key_set_rotation(card, 0x01);
    }

}

//-----------------------------------------------------------------------------
// offline helpers, no card involved
//-----------------------------------------------------------------------------
static void run_offline(void)
{
    // AN10922 diversification is deterministic, so it can be checked for shape
    nxpsc_key_t master{};
    master.type = NXPSC_KEY_AES128;
    for (int i = 0; i < 16; i++) master.data[i] = static_cast<uint8_t>(i);

    static const uint8_t div_input[8] = { 0x04,0x11,0x22,0x33,0x44,0x55,0x66,0x77 };
    nxpsc_key_t out_a{}, out_b{};

    int rc = nxpsc_diversify_an10922(&master, div_input, sizeof(div_input), &out_a);
    report("AN10922 diversify", rc, nullptr);
    if (rc == NXPSC_OK) {
        check("a diversified key is not the master key",
            memcmp(out_a.data, master.data, 16) != 0, nullptr);
        check("the diversified key keeps the master key type",
            out_a.type == NXPSC_KEY_AES128, nullptr);

        rc = nxpsc_diversify_an10922(&master, div_input, sizeof(div_input), &out_b);
        check("diversification is deterministic",
            rc == NXPSC_OK && memcmp(out_a.data, out_b.data, 16) == 0, nullptr);

        uint8_t other[8];
        memcpy(other, div_input, sizeof(other));
        other[0] ^= 0xFF;
        rc = nxpsc_diversify_an10922(&master, other, sizeof(other), &out_b);
        check("a different input gives a different key",
            rc == NXPSC_OK && memcmp(out_a.data, out_b.data, 16) != 0, nullptr);
    }

    // access rights pack into 16 bits as read<<12 | write<<8 | rw<<4 | change
    nxpsc_access_t acc{};
    nxpsc_unpack_access(0xE01F, &acc);
    check("UnpackAccess splits the nibbles in the documented order",
        acc.read == 0x0E && acc.write == 0x00 && acc.read_write == 0x01
        && acc.change == 0x0F, nullptr);
}

//-----------------------------------------------------------------------------
int main()
{
    SCARDCONTEXT hCtx;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &hCtx) != SCARD_S_SUCCESS) {
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
    if (SCardConnectA(hCtx, readers, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1,
        &ctx.hCard, &ctx.proto) != SCARD_S_SUCCESS) {
        printf("no card on reader %s\n", readers);
        SCardReleaseContext(hCtx);
        return 1;
    }
    g_pcsc = &ctx;
    // a previous run may have left the card in proximity check mode
    reset_card();
    printf("reader: %s\n\n", readers);

    report("crypto selftest", nxpsc_selftest(false), nullptr);
    run_offline();

    nxpsc_transport_t transport{};
    transport.ctx = &ctx;
    transport.transceive = pcsc_transceive;

    nxpsc_card_t* card = nullptr;
    int rc = nxpsc_open(&transport, &card);
    report("nxpsc_open", rc, nullptr);
    if (rc != NXPSC_OK) {
        SCardDisconnect(ctx.hCard, SCARD_LEAVE_CARD);
        SCardReleaseContext(hCtx);
        return 1;
    }
    nxpsc_set_cmdset(card, NXPSC_CMDSET_NATIVE_ISO);

    nxpsc_version_t v{};
    rc = nxpsc_get_version(card, &v);
    report("GetVersion", rc, card);
    if (rc == NXPSC_OK) {
        nxpsc_cardtype_t type = NXP_UNKNOWN;
        nxpsc_identify(card, &type);
        printf("       card: %s\n       uid: ", nxpsc_cardtype_str(type));
        for (size_t i = 0; i < sizeof(v.uid); i++) printf("%02X", v.uid[i]);
        printf("\n");
    }

    uint32_t before = 0, after = 0;
    if (nxpsc_get_free_memory(card, &before) == NXPSC_OK)
        printf("       free: %u bytes\n", before);

    nxpsc_key_t picc{};
    picc.type = NXPSC_KEY_2K3DES;        // factory PICC master key, all zero

    rc = nxpsc_select_application(card, 0x000000);
    report("SelectApplication PICC", rc, card);
    if (rc == NXPSC_OK) {
        rc = nxpsc_authenticate(card, 0, &picc, NXPSC_CHAN_AUTO);
        report("Authenticate (factory PICC master key)", rc, card);
    }

    if (rc == NXPSC_OK) {
        run_tier1(card);

        // tear the sandbox down whatever happened inside it
        nxpsc_select_application(card, 0x000000);
        if (use_key(card, 0, &picc)) {
            rc = nxpsc_delete_application(card, CRUCIBLE_AID);
            report("DeleteApplication (crucible cleanup)", rc, card);
        }
        else {
            report("DeleteApplication (crucible cleanup)", NXPSC_E_AUTH, card);
        }
    }
    else {
        printf("[SKIP] tier 1: PICC authentication failed, not proceeding\n");
        g_skip++;
    }

    if (nxpsc_get_free_memory(card, &after) == NXPSC_OK)
        printf("       free: %u bytes after (%d)\n", after, (int)after - (int)before);

    nxpsc_close(card);
    SCardDisconnect(ctx.hCard, SCARD_LEAVE_CARD);
    SCardReleaseContext(hCtx);

    printf("\n==== results: %d passed, %d failed, %d skipped ====\n",
        g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
