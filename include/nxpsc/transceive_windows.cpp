#include "transceive_windows.h"

int pcsc_transceive(void* vctx, const uint8_t* tx, size_t txlen,
    uint8_t* rx, size_t rxcap, size_t* rxlen)
{
    PcscCtx* ctx = static_cast<PcscCtx*>(vctx);
    DWORD rlen = static_cast<DWORD>(rxcap);

    // Debug output of the sent data
    printf(">> ");
    for (size_t i = 0; i < txlen; i++) printf("%02X", tx[i]);
    printf("\n");

    // Transmit the APDU to the card
    LONG rc = SCardTransmit(ctx->hCard, SCARD_PCI_T1,
        tx, static_cast<DWORD>(txlen),
        nullptr, rx, &rlen);
    if (rc != SCARD_S_SUCCESS)
        return NXPSC_E_TRANSPORT;   // card removed / no answer

    // Debug output of the received data
    printf("<< ");
    for (DWORD i = 0; i < rlen; i++) printf("%02X", rx[i]);
    printf("\n\n");

    *rxlen = rlen;
    return NXPSC_OK;                // card errors are decoded by the library
}
