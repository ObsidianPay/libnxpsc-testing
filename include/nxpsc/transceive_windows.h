#pragma once
#include <winscard.h>
#include <nxpsc/nxpsc.h>
#include <stdio.h>
#include <stdint.h>

struct PcscCtx {
    SCARDHANDLE hCard;
    DWORD proto;
};

int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen);
