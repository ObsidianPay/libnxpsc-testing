//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// libnxpsc - portable low level programming library for NXP smartcards
// (DESFire / DESFire Light / MIFARE Plus / NTAG 4xx DNA / DUOX)
//-----------------------------------------------------------------------------

#ifndef NXPSC_H__
#define NXPSC_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NXPSC_VERSION_MAJOR     0
#define NXPSC_VERSION_MINOR     1
#define NXPSC_VERSION_PATCH     0

#define NXPSC_MAX_KEY_SIZE      32
#define NXPSC_MAX_APDU          264
// biggest supported reassembled response, a file read is chunked above this
#define NXPSC_MAX_RESPONSE      4096
#define NXPSC_MAX_FILES         32
#define NXPSC_MAX_APPS          64
#define NXPSC_MAX_KEYS          16

//-----------------------------------------------------------------------------
// return codes. all API calls return NXPSC_OK or a negative value below
//-----------------------------------------------------------------------------
typedef enum {
    NXPSC_OK            =  0,
    NXPSC_E_PARAM       = -1,   // bad argument from the caller
    NXPSC_E_TRANSPORT   = -2,   // reader/transport layer failed
    NXPSC_E_CARD        = -3,   // card answered with an error status, see nxpsc_last_status()
    NXPSC_E_CRYPTO      = -4,   // local crypto operation failed
    NXPSC_E_AUTH        = -5,   // authentication failed / not authenticated
    NXPSC_E_LENGTH      = -6,   // response length not as expected, or buffer too small
    NXPSC_E_UNSUPPORTED = -7,   // not supported by this card or not implemented
    NXPSC_E_MEMORY      = -8,
} nxpsc_error_t;

//-----------------------------------------------------------------------------
// card families. values kept stable, detection lives in nxpsc_card_type()
//-----------------------------------------------------------------------------
typedef enum {
    NXP_UNKNOWN = 0,
    DESFIRE_MF3ICD40,
    DESFIRE_EV1,
    DESFIRE_EV2,
    DESFIRE_EV2_XL,
    DESFIRE_EV3,
    DESFIRE_LIGHT,
    PLUS_EV1,
    PLUS_EV2,
    NTAG413DNA,
    NTAG424,
    DUOX,
} nxpsc_cardtype_t;

//-----------------------------------------------------------------------------
// keys
//-----------------------------------------------------------------------------
typedef enum {
    NXPSC_KEY_DES = 0,      // 8 byte single DES
    NXPSC_KEY_2K3DES,       // 16 byte 2 key 3DES
    NXPSC_KEY_3K3DES,       // 24 byte 3 key 3DES
    NXPSC_KEY_AES128,       // 16 byte AES
    NXPSC_KEY_AES256,       // 32 byte AES, DESFire Light / EV2 originality only
} nxpsc_keytype_t;

typedef struct {
    nxpsc_keytype_t type;
    uint8_t data[NXPSC_MAX_KEY_SIZE];
    uint8_t version;        // only meaningful for (2K3)DES keys, AES carries it separately
} nxpsc_key_t;

// secure channel / authentication variant
typedef enum {
    NXPSC_CHAN_AUTO = 0,    // pick from card type and key type
    NXPSC_CHAN_D40,         // legacy native authenticate (0x0A / 0x1A)
    NXPSC_CHAN_EV1,         // AuthenticateISO / AuthenticateAES (0x1A / 0xAA)
    NXPSC_CHAN_EV2,         // AuthenticateEV2First / NonFirst (0x71 / 0x77)
    NXPSC_CHAN_LRP,         // leakage resilient primitive (DESFire Light, EV2+)
} nxpsc_channel_t;

// per command communication mode
typedef enum {
    NXPSC_COMM_PLAIN = 0,
    NXPSC_COMM_MAC,
    NXPSC_COMM_FULL,        // fully enciphered
} nxpsc_commmode_t;

// command set used on the wire
typedef enum {
    NXPSC_CMDSET_NATIVE = 0,    // raw native frames
    NXPSC_CMDSET_NATIVE_ISO,    // native commands wrapped in ISO 7816-4 APDUs (CLA 0x90)
    NXPSC_CMDSET_ISO,           // real ISO 7816-4 commands
} nxpsc_cmdset_t;

//-----------------------------------------------------------------------------
// transport. the backend only has to move an ISO 14443-4 payload (INF field),
// i.e. everything but framing/CRC, between the caller and the card
//-----------------------------------------------------------------------------
typedef struct {
    void *ctx;
    // returns NXPSC_OK and sets rxlen, or a negative nxpsc_error_t
    int (*transceive)(void *ctx, const uint8_t *tx, size_t txlen,
                      uint8_t *rx, size_t rxcap, size_t *rxlen);
    // optional. UID of the selected card, used for key diversification helpers
    int (*get_uid)(void *ctx, uint8_t *uid, size_t uidcap, size_t *uidlen);
    // optional. re-select the card, needed by some ISO authenticate flows
    int (*reselect)(void *ctx);
} nxpsc_transport_t;

typedef struct nxpsc_card nxpsc_card_t;

//-----------------------------------------------------------------------------
// version / identification
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t hw_vendor;
    uint8_t hw_type;
    uint8_t hw_subtype;
    uint8_t hw_major;
    uint8_t hw_minor;
    uint8_t hw_storage;
    uint8_t hw_protocol;

    uint8_t sw_vendor;
    uint8_t sw_type;
    uint8_t sw_subtype;
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_storage;
    uint8_t sw_protocol;

    uint8_t uid[7];
    uint8_t batch[5];
    uint8_t week;
    uint8_t year;
    bool has_batch_extra;       // EV2 and later return 2 extra bytes
} nxpsc_version_t;

//-----------------------------------------------------------------------------
// files
//-----------------------------------------------------------------------------
typedef enum {
    NXPSC_FILE_STD       = 0x00,
    NXPSC_FILE_BACKUP    = 0x01,
    NXPSC_FILE_VALUE     = 0x02,
    NXPSC_FILE_LINEAR    = 0x03,
    NXPSC_FILE_CYCLIC    = 0x04,
    NXPSC_FILE_TRANSMAC  = 0x05,
} nxpsc_filetype_t;

typedef struct {
    uint8_t read;       // key number, 0x0E free, 0x0F denied
    uint8_t write;
    uint8_t read_write;
    uint8_t change;
} nxpsc_access_t;

typedef struct {
    nxpsc_filetype_t type;
    uint8_t options;            // raw file option byte
    nxpsc_commmode_t comm;
    nxpsc_access_t access;

    uint32_t size;              // data files
    int32_t lower_limit;        // value files
    int32_t upper_limit;
    int32_t value;
    uint8_t limited_credit;
    uint32_t record_size;       // record files
    uint32_t max_records;
    uint32_t cur_records;

    bool sdm_enabled;           // NTAG 4xx DNA / EV3 secure dynamic messaging
    uint32_t sdm_options;
} nxpsc_file_settings_t;

typedef struct {
    uint32_t aid;
    uint16_t iso_fid;
    char df_name[17];
    uint8_t df_name_len;
    uint8_t key_settings;
    uint8_t num_keys;
    nxpsc_keytype_t key_type;
    bool iso_fid_enabled;
} nxpsc_app_t;

//-----------------------------------------------------------------------------
// life cycle
//-----------------------------------------------------------------------------
// the transport pointer contents are copied, the ctx pointer must stay valid
int nxpsc_open(const nxpsc_transport_t *transport, nxpsc_card_t **out);
void nxpsc_close(nxpsc_card_t *card);
void nxpsc_reset_channel(nxpsc_card_t *card);

const char *nxpsc_strerror(int rc);
// status byte of the last card response, and its text
uint8_t nxpsc_last_status(const nxpsc_card_t *card);
const char *nxpsc_status_str(uint8_t status);
const char *nxpsc_cardtype_str(nxpsc_cardtype_t type);
const char *nxpsc_keytype_str(nxpsc_keytype_t type);
size_t nxpsc_key_size(nxpsc_keytype_t type);

void nxpsc_set_cmdset(nxpsc_card_t *card, nxpsc_cmdset_t cmdset);
nxpsc_cmdset_t nxpsc_get_cmdset(const nxpsc_card_t *card);
// default communication mode for commands that do not derive one from a file
void nxpsc_set_commmode(nxpsc_card_t *card, nxpsc_commmode_t mode);
bool nxpsc_is_authenticated(const nxpsc_card_t *card);
// the PICC aborts secure messaging whenever it answers an in session command
// with an error status. when that happens the session is dropped on both sides
// and every later command that needs it fails with NXPSC_E_AUTH until the
// caller authenticates again or calls nxpsc_reset_channel()
bool nxpsc_session_lost(const nxpsc_card_t *card);
uint32_t nxpsc_selected_aid(const nxpsc_card_t *card);

//-----------------------------------------------------------------------------
// identification
//-----------------------------------------------------------------------------
int nxpsc_get_version(nxpsc_card_t *card, nxpsc_version_t *version);
int nxpsc_get_card_uid(nxpsc_card_t *card, uint8_t *uid, size_t cap, size_t *len);
int nxpsc_get_free_memory(nxpsc_card_t *card, uint32_t *bytes);
int nxpsc_get_signature(nxpsc_card_t *card, uint8_t *sig, size_t cap, size_t *len);
// cached, call nxpsc_get_version() first or it does it itself
int nxpsc_identify(nxpsc_card_t *card, nxpsc_cardtype_t *type);
nxpsc_cardtype_t nxpsc_card_type(const nxpsc_card_t *card);
// pure function, exposed for offline decoding of a GetVersion answer
nxpsc_cardtype_t nxpsc_card_type_from_version(uint8_t type, uint8_t major, uint8_t minor);

//-----------------------------------------------------------------------------
// authentication and keys
//-----------------------------------------------------------------------------
int nxpsc_select_application(nxpsc_card_t *card, uint32_t aid);
int nxpsc_authenticate(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key,
                       nxpsc_channel_t channel);
// EV2 only. continues an already established EV2 session with another key
int nxpsc_authenticate_nonfirst(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *key);

int nxpsc_change_key(nxpsc_card_t *card, uint8_t key_no, const nxpsc_key_t *old_key,
                     const nxpsc_key_t *new_key);
// ChangeKeyEV2, key set aware (EV2 and later)
int nxpsc_change_key_ev2(nxpsc_card_t *card, uint8_t key_set, uint8_t key_no,
                         const nxpsc_key_t *old_key, const nxpsc_key_t *new_key);
int nxpsc_get_key_version(nxpsc_card_t *card, uint8_t key_no, uint8_t *version);
int nxpsc_get_key_settings(nxpsc_card_t *card, uint8_t *key_settings, uint8_t *num_keys,
                           nxpsc_keytype_t *key_type);
int nxpsc_change_key_settings(nxpsc_card_t *card, uint8_t key_settings);

// AN10922 key diversification. div_input is the diversification data without
// the leading padding constant, typically UID || AID || system identifier
int nxpsc_diversify_an10922(const nxpsc_key_t *master, const uint8_t *div_input,
                            size_t div_input_len, nxpsc_key_t *out);

//-----------------------------------------------------------------------------
// applications
//-----------------------------------------------------------------------------
int nxpsc_create_application(nxpsc_card_t *card, uint32_t aid, uint8_t key_settings,
                             uint8_t num_keys, nxpsc_keytype_t key_type);
// ISO variant, additionally assigns an ISO file id and DF name
int nxpsc_create_application_iso(nxpsc_card_t *card, uint32_t aid, uint8_t key_settings,
                                 uint8_t num_keys, nxpsc_keytype_t key_type,
                                 uint16_t iso_fid, const uint8_t *df_name, size_t df_name_len);
// full CreateApplication payload. the two calls above are the common cases,
// this one reaches the fields they leave out, key sets above all: an
// application only accepts nxpsc_init_key_set() and the rest of the key set
// commands when it was created with num_key_sets >= 2
typedef struct {
    uint8_t key_settings;           // KeySettings1
    uint8_t num_keys;               // 1 to 14
    nxpsc_keytype_t key_type;

    bool iso_fid_enabled;
    uint16_t iso_fid;
    const uint8_t *df_name;         // up to 16 bytes, may be NULL
    size_t df_name_len;

    // key sets, EV2 and later. 0 leaves the application without them
    uint8_t num_key_sets;           // 2 to 16
    uint8_t key_set_version;        // AKSVersion, the active set's version
    uint8_t max_key_size;           // 8, 16 or 24
    uint8_t key_set_settings;       // AppKeySetSett
} nxpsc_app_config_t;

int nxpsc_create_application_ex(nxpsc_card_t *card, uint32_t aid,
                                const nxpsc_app_config_t *config);
int nxpsc_delete_application(nxpsc_card_t *card, uint32_t aid);
int nxpsc_get_application_ids(nxpsc_card_t *card, uint32_t *aids, size_t cap, size_t *count);
int nxpsc_get_df_names(nxpsc_card_t *card, nxpsc_app_t *apps, size_t cap, size_t *count);
int nxpsc_format_picc(nxpsc_card_t *card);
int nxpsc_set_configuration(nxpsc_card_t *card, uint8_t option, const uint8_t *data, size_t len);

//-----------------------------------------------------------------------------
// files
//-----------------------------------------------------------------------------
uint16_t nxpsc_pack_access(const nxpsc_access_t *access);
void nxpsc_unpack_access(uint16_t raw, nxpsc_access_t *access);

int nxpsc_get_file_ids(nxpsc_card_t *card, uint8_t *ids, size_t cap, size_t *count);
int nxpsc_get_iso_file_ids(nxpsc_card_t *card, uint16_t *ids, size_t cap, size_t *count);
int nxpsc_get_file_settings(nxpsc_card_t *card, uint8_t file_no, nxpsc_file_settings_t *settings);
int nxpsc_change_file_settings(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                               const nxpsc_access_t *access);
// raw variant, used for SDM configuration and other vendor specific payloads
int nxpsc_change_file_settings_raw(nxpsc_card_t *card, uint8_t file_no,
                                   const uint8_t *data, size_t len);

int nxpsc_create_std_file(nxpsc_card_t *card, uint8_t file_no, uint16_t iso_fid,
                          nxpsc_commmode_t comm, const nxpsc_access_t *access, uint32_t size);
int nxpsc_create_backup_file(nxpsc_card_t *card, uint8_t file_no, uint16_t iso_fid,
                             nxpsc_commmode_t comm, const nxpsc_access_t *access, uint32_t size);
int nxpsc_create_value_file(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                            const nxpsc_access_t *access, int32_t lower, int32_t upper,
                            int32_t value, bool limited_credit);
int nxpsc_create_record_file(nxpsc_card_t *card, bool cyclic, uint8_t file_no, uint16_t iso_fid,
                             nxpsc_commmode_t comm, const nxpsc_access_t *access,
                             uint32_t record_size, uint32_t max_records);
int nxpsc_delete_file(nxpsc_card_t *card, uint8_t file_no);

// comm == NXPSC_COMM_PLAIN with no session is allowed when the file access
// rights say so. read the file settings first with nxpsc_get_file_settings()
// to learn which mode a file expects
int nxpsc_read_data(nxpsc_card_t *card, uint8_t file_no, uint32_t offset, uint32_t length,
                    nxpsc_commmode_t comm, uint8_t *out, size_t cap, size_t *out_len);
int nxpsc_write_data(nxpsc_card_t *card, uint8_t file_no, uint32_t offset,
                     const uint8_t *data, size_t len, nxpsc_commmode_t comm);

int nxpsc_get_value(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm, int32_t *value);
int nxpsc_credit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm);
int nxpsc_limited_credit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm);
int nxpsc_debit(nxpsc_card_t *card, uint8_t file_no, int32_t delta, nxpsc_commmode_t comm);

int nxpsc_write_record(nxpsc_card_t *card, uint8_t file_no, uint32_t offset,
                       const uint8_t *data, size_t len, nxpsc_commmode_t comm);
// updates part of an existing record, record 0 is the most recent one
int nxpsc_update_record(nxpsc_card_t *card, uint8_t file_no, uint32_t record_no,
                        uint32_t offset, const uint8_t *data, size_t len,
                        nxpsc_commmode_t comm);
int nxpsc_read_records(nxpsc_card_t *card, uint8_t file_no, uint32_t record_no,
                       uint32_t record_count, nxpsc_commmode_t comm,
                       uint8_t *out, size_t cap, size_t *out_len);
int nxpsc_clear_record_file(nxpsc_card_t *card, uint8_t file_no);

int nxpsc_commit_transaction(nxpsc_card_t *card);
int nxpsc_abort_transaction(nxpsc_card_t *card);
// EV2 transaction MAC file support
int nxpsc_commit_reader_id(nxpsc_card_t *card, const uint8_t *reader_id, size_t len,
                           uint8_t *enc_prev_reader_id, size_t cap, size_t *out_len);

//-----------------------------------------------------------------------------
// EV2 and later extras
//-----------------------------------------------------------------------------
// ISO chaining uses the 0xAD / 0x8D / 0xAB / 0x8B / 0xBA file access opcodes
// instead of the native ones. Needed by readers that cannot do native chaining
void nxpsc_set_iso_chaining(nxpsc_card_t *card, bool enable);
bool nxpsc_get_iso_chaining(const nxpsc_card_t *card);

// transaction MAC file, lets the back office verify a committed transaction
int nxpsc_create_transaction_mac_file(nxpsc_card_t *card, uint8_t file_no,
                                      nxpsc_commmode_t comm, const nxpsc_access_t *access,
                                      const nxpsc_key_t *tm_key, uint8_t key_version);

// delegated application management, for multi issuer cards
typedef struct {
    uint8_t dam_slot_version;
    uint16_t quota_limit;
    uint16_t free_blocks;
    uint32_t aid;
} nxpsc_delegate_info_t;

// enck and dam_mac are produced by the DAM authority, see the card manual
int nxpsc_create_delegated_application(nxpsc_card_t *card, uint32_t aid, uint16_t dam_slot,
                                       uint8_t dam_slot_version, uint16_t quota_limit,
                                       uint8_t key_settings, uint8_t num_keys,
                                       nxpsc_keytype_t key_type,
                                       uint16_t iso_fid, const uint8_t *df_name, size_t df_name_len,
                                       const uint8_t *enck, size_t enck_len,
                                       const uint8_t *dam_mac, size_t dam_mac_len);
int nxpsc_get_delegated_info(nxpsc_card_t *card, uint16_t dam_slot, nxpsc_delegate_info_t *info);

// MIFARE Classic mapping of EV2 XL and EV3, payload per card manual
int nxpsc_create_mfc_mapping(nxpsc_card_t *card, const uint8_t *data, size_t len);
int nxpsc_restrict_mfc_update(nxpsc_card_t *card, const uint8_t *data, size_t len);

// used by ECP capable readers to tell the card a transaction completed
int nxpsc_notify_transaction_success(nxpsc_card_t *card);

// key sets. init, fill with nxpsc_change_key_ev2(), then finalize, then roll
// key_set_settings is the settings byte for the new set, not a key count: the
// number of keys and their type come from the application. EV3 accepts 0x00 and
// refuses 0x01 with 0x9D and 0x80 with 0x9E when the application was created
// with AppKeySetSett 0x00
int nxpsc_init_key_set(nxpsc_card_t *card, uint8_t key_set, uint8_t key_set_settings);
int nxpsc_finalize_key_set(nxpsc_card_t *card, uint8_t key_set, uint8_t key_set_version);
int nxpsc_roll_key_set(nxpsc_card_t *card, uint8_t key_set);

// proximity check, the relay attack countermeasure. rounds is 1 to 8. the call
// fails when the card answer MAC does not verify; mac_ok receives the same
// verification result and may be NULL
int nxpsc_proximity_check(nxpsc_card_t *card, const nxpsc_key_t *pc_key, uint8_t rounds,
                          bool *mac_ok);

// SetConfiguration wrappers
int nxpsc_set_picc_config(nxpsc_card_t *card, bool disable_format, bool random_uid);
int nxpsc_set_default_key(nxpsc_card_t *card, const nxpsc_key_t *key);
int nxpsc_set_ats(nxpsc_card_t *card, const uint8_t *ats, size_t len);

//-----------------------------------------------------------------------------
// ISO 7816-4 level access, shared by DESFire ISO mode and NTAG 4xx DNA
//-----------------------------------------------------------------------------
int nxpsc_iso_select_df_name(nxpsc_card_t *card, const uint8_t *df_name, size_t len);
int nxpsc_iso_select_fid(nxpsc_card_t *card, uint16_t fid, bool is_ef);
int nxpsc_iso_read_binary(nxpsc_card_t *card, uint8_t sfi, uint16_t offset, size_t length,
                          uint8_t *out, size_t cap, size_t *out_len);
int nxpsc_iso_update_binary(nxpsc_card_t *card, uint8_t sfi, uint16_t offset,
                            const uint8_t *data, size_t len);

//-----------------------------------------------------------------------------
// NTAG 413 DNA / NTAG 424 DNA secure dynamic messaging
//-----------------------------------------------------------------------------
typedef struct {
    bool enabled;
    bool uid_mirror;
    bool counter_mirror;
    bool read_counter_limit;
    bool enc_file_data;
    uint8_t meta_read_key;      // 0x0E plain mirroring, 0x0F no mirroring
    uint8_t file_read_key;      // key used for the CMAC / enc mirror, 0x0F none
    uint8_t counter_ret_key;
    uint32_t uid_offset;
    uint32_t counter_offset;
    uint32_t picc_data_offset;
    uint32_t mac_input_offset;
    uint32_t enc_offset;
    uint32_t enc_length;
    uint32_t mac_offset;
    uint32_t read_counter_limit_value;
} nxpsc_sdm_settings_t;

int nxpsc_ntag424_select(nxpsc_card_t *card);
int nxpsc_sdm_configure(nxpsc_card_t *card, uint8_t file_no, nxpsc_commmode_t comm,
                        const nxpsc_access_t *access, const nxpsc_sdm_settings_t *sdm);
// builds the ChangeFileSettings payload without talking to a card, for tests
int nxpsc_sdm_build_settings(nxpsc_commmode_t comm, const nxpsc_access_t *access,
                             const nxpsc_sdm_settings_t *sdm,
                             uint8_t *out, size_t cap, size_t *out_len);

//-----------------------------------------------------------------------------
// MIFARE Plus EV1 / EV2, security level 3
//-----------------------------------------------------------------------------
// block numbers are the MIFARE Plus sector/block addressing, key numbers are
// the AES key block addresses (0x4000 + n for data sectors)
int nxpsc_plus_authenticate(nxpsc_card_t *card, uint16_t key_block, const nxpsc_key_t *key,
                            bool first);
int nxpsc_plus_read(nxpsc_card_t *card, uint16_t block, uint8_t count, bool encrypted,
                    bool maced, uint8_t *out, size_t cap, size_t *out_len);
int nxpsc_plus_write(nxpsc_card_t *card, uint16_t block, const uint8_t *data, size_t len,
                     bool encrypted);
int nxpsc_plus_write_perso(nxpsc_card_t *card, uint16_t block, const uint8_t *data, size_t len);
int nxpsc_plus_commit_perso(nxpsc_card_t *card);
int nxpsc_plus_value_op(nxpsc_card_t *card, uint16_t block, int32_t delta, bool credit,
                        bool encrypted);
int nxpsc_plus_transfer(nxpsc_card_t *card, uint16_t block);
// value operation that transfers to the same block in one command
int nxpsc_plus_value_transfer(nxpsc_card_t *card, uint16_t block, int32_t delta, bool credit,
                              bool encrypted);
int nxpsc_plus_restore(nxpsc_card_t *card, uint16_t block);
// ends the session on the card as well as in the library
int nxpsc_plus_reset_auth(nxpsc_card_t *card);
// security level 1 configuration and UID personalisation, payload per manual
int nxpsc_plus_set_config_sl1(nxpsc_card_t *card, const uint8_t *data, size_t len);
int nxpsc_plus_personalize_uid(nxpsc_card_t *card, uint8_t uid_type);
// virtual card support, asks whether the card answered the last ISO level 3
int nxpsc_plus_vc_support_last_iso_l3(nxpsc_card_t *card, uint8_t *out, size_t cap,
                                      size_t *out_len);

//-----------------------------------------------------------------------------
// escape hatch. sends a native DESFire command through the active secure
// channel. resp excludes the status byte, which lands in nxpsc_last_status()
//-----------------------------------------------------------------------------
int nxpsc_command(nxpsc_card_t *card, uint8_t cmd, const uint8_t *data, size_t len,
                  nxpsc_commmode_t tx_mode, nxpsc_commmode_t rx_mode,
                  uint8_t *resp, size_t cap, size_t *resp_len);

// self test of the crypto layer, returns NXPSC_OK when all vectors pass
int nxpsc_selftest(bool verbose);

#ifdef __cplusplus
}
#endif

#endif // NXPSC_H__
