/* IKE */

#include "ike.h"
#include "transforms.c"
#include "dh_protocol.c"
#include "mem_clean.c"
#include "hmac/hmac.h"
#include "crypt/aes128.h"

static uint8_t *buff;

static uint8_t *ike_sa_init;
static uint32_t ike_sa_init_len;
static uint8_t *ike_sa_init_resp;
static uint32_t ike_sa_init_resp_len;

static SA_payload                  SAi1;
static SA_payload                  SAi2;
static SA_payload                  SAr1;
static SA_payload                  SAr2;
static key_exchange_payload        KEi;
static key_exchange_payload        KEr;
static identification_payload      IDi;
static identification_payload      IDr;
// static certificate_payload         CERT;
// static certificate_request_payload CERTREQ;
static authentication_payload      AUTH;
static nonce_payload               Ni;
static nonce_payload               Nr;
// static notify_payload              NOTIFY;
// static delete_payload              DELETE;
// static vendor_ID_payload           VID;
static traffic_selector_payload    TSi;
static traffic_selector_payload    TSr;
// static configuration_payload       CFG;
// static eap_payload                 EAP;
static encrypted_payload           SK;

static ike_header                  HDR_recv;
static SA_payload                  SA_recv;
static key_exchange_payload        KE_recv;
static identification_payload      IDi_recv;
static identification_payload      IDr_recv;
// static certificate_payload         CERT_recv;
// static certificate_request_payload CERTREQ_recv;
static authentication_payload      AUTH_recv;
static nonce_payload               NONCE_recv;
// static notify_payload              NOTIFY_recv;
// static delete_payload              DELETE_recv;
// static vendor_ID_payload           VID_recv;
static traffic_selector_payload    TSi_recv;
static traffic_selector_payload    TSr_recv;
// static configuration_payload       CFG_recv;
// static eap_payload                 EAP_recv;
static encrypted_payload           SK_recv;

static uint8_t *SPIi;
static uint8_t *SPIr;
static uint32_t Ni_len;
static uint32_t Nr_len;
static uint8_t *K;

static uint8_t *SK_d;
static uint8_t *SK_ai;
static uint8_t *SK_ar;
static uint8_t *SK_ei;
static uint8_t *SK_er;
static uint8_t *SK_pi;
static uint8_t *SK_pr;

static uint32_t MID;

static uint16_t dh_group;
static uint32_t modp;

static uint16_t acc_prf;
static uint16_t acc_integ;
static uint16_t acc_encr;
static uint16_t encr_key_len;
static uint16_t encr_block_len;
static uint16_t iv_len;
static uint16_t prf_key_len;
static uint16_t integ_key_len;
static proposal *acc_proposal;

void init (void)
{
    dh_initialize ();
    // srand (time (NULL));
    SPIi = calloc (1, sizeof (uint64_t));
    SPIr = calloc (1, sizeof (uint64_t));

    MID = 0;
}

void mem_clr (void)
{
    sa_pl_clr (&SAi1);
    sa_pl_clr (&SAi2);
    sa_pl_clr (&SAr1);
    sa_pl_clr (&SAr2);
    ke_pl_clr (&KEi);
    ke_pl_clr (&KEr);
    id_pl_clr (&IDi);
    id_pl_clr (&IDr);
    // cert_pl_clr (&CERT);
    // cert_req_pl_clr (&CERTREQ);
    auth_pl_clr (&AUTH);
    nonce_pl_clr (&Ni);
    nonce_pl_clr (&Nr);
    ts_pl_clr (&TSi);
    ts_pl_clr (&TSr);

    enc_pl_clr (&SK);

    sa_pl_clr (&SA_recv);
    // ke_pl_clr (&KE_recv);
    id_pl_clr (&IDi_recv);
    id_pl_clr (&IDr_recv);

    auth_pl_clr(&AUTH_recv);
    // nonce_pl_clr (&NONCE_recv);
    // puts ("14");

    ts_pl_clr (&TSi_recv);
    ts_pl_clr (&TSr_recv);

    enc_pl_clr (&SK_recv);
}

void reset (void)
{
    MID = 0;
}

int ike_init (void)
{
    MID++;

    const uint8_t num_transforms = 4;
    const uint8_t num_proposals = 1;

    transform *transforms = calloc (num_transforms, sizeof (transform));
    transforms[0].more = 3;
    transforms[0].transform_type = ENCR;
    transforms[0].transform_ID = ENCR_AES_CBC;
    transforms[0].attribute_format = AF_TV;
    transforms[0].attribute_type = AT_KEY_LEN;
    transforms[0].attribute_value = calloc (1, 2);
    transforms[0].attribute_value[0] = 0;
    transforms[0].attribute_value[1] = 128;

    transforms[1].more = 3;
    transforms[1].transform_type = PRF;
    transforms[1].transform_ID = PRF_HMAC_SHA1;
    transforms[1].attribute_format = AF_TV;
    transforms[1].attribute_type = AT_KEY_LEN;
    transforms[1].attribute_value = calloc (1, 2);
    transforms[1].attribute_value[1] = 160;

    transforms[2].more = 3;
    transforms[2].transform_type = INTEG;
    transforms[2].transform_ID = AUTH_HMAC_SHA1_96;
    transforms[2].attribute_format = AF_TV;
    transforms[2].attribute_type = AT_KEY_LEN;
    transforms[2].attribute_value = calloc (1, 2);
    transforms[2].attribute_value[1] = 160;

    transforms[3].more = 0;
    transforms[3].transform_type = DH_GR;
    transforms[3].transform_ID = MODP_2048;
    transforms[3].attribute_value = NULL;

    uint32_t sum_length = 0;
    for (int i = 0; i < num_transforms; i++)
    {
        if (transforms[i].transform_ID == ENCR_AES_CBC ||
            transforms[i].transform_ID == ENCR_AES_CTR ||
            transforms[i].transform_ID == ENCR_NULL ||
            transforms[i].transform_type == PRF ||
            transforms[i].transform_type == INTEG)
            transforms[i].transform_length = 12;
        else
            transforms[i].transform_length = 8;

        sum_length += transforms[i].transform_length;
    }

    proposal *proposals = calloc (num_proposals, sizeof (proposal));
    proposals[0].more = 0;
    proposals[0].proposal_num = 1;
    proposals[0].protocol_ID = IKE;
    proposals[0].SPI_size = 0;
    proposals[0].SPI = calloc (1, proposals[0].SPI_size);
    proposals[0].num_transforms = num_transforms;
    proposals[0].transforms = transforms;
    proposals[0].proposal_length = 
        sum_length + sizeof (proposal) + proposals[0].SPI_size -
        sizeof (proposals[0].SPI) - sizeof (proposals[0].transforms);

    SAi1.proposals = proposals;
    SAi1.header.next_payload = PL_KE;
    SAi1.header.critical = 0;
    SAi1.header.payload_length = sizeof (generic_payload_header);
    uint32_t prop_num = 0;
    do SAi1.header.payload_length += SAi1.proposals[prop_num].proposal_length;
    while (SAi1.proposals[prop_num++].more != 0);

    dh_group = 0;
    for (int i = 0; i < num_transforms; i++)
        if (SAi1.proposals[0].transforms[i].transform_type == DH_GR &&
            SAi1.proposals[0].transforms[i].transform_ID > dh_group)
            dh_group = SAi1.proposals[0].transforms[i].transform_ID;
    modp = get_modp (dh_group);

    KEi.header.next_payload = PL_NONCE;
    KEi.header.critical = 0;
    KEi.header.payload_length = sizeof (KEi.header) +
        sizeof (KEi.dh_group_num) + sizeof (KEi.reserved) + modp/8;
    KEi.dh_group_num = dh_group;
    KEi.reserved = 0;
    KEi.key_exchange_data = calloc (1, modp/8);
    MEMCHECK (KEi.key_exchange_data);

    mpz_set (dh_a, dh_nsize_random (A_SIZE));
    dh_set_p (modp);
    mpz_powm_sec (dh_A, dh_g, dh_a, dh_p);
    size_t *count = (size_t*) calloc (1, sizeof (size_t));
    uint32_t size = mpz_sizeinbase (dh_A, 256);
    mpz_export (KEi.key_exchange_data + modp/8 - size, count, 1, 1, 1, 0, dh_A);
    free (count);

    Ni.header.next_payload = NO_NEXT_PL;
    Ni.header.critical = 0;
    Ni_len = 4*(4 + (rand() % 60));
    Ni.header.payload_length = sizeof (Ni.header) + Ni_len;
    Ni.nonce_data = calloc (1, Ni_len);
    for (int i = 0; i < Ni_len; i++)
        Ni.nonce_data[i] = rand ();

    ike_header HDR;
    for (int i = 0; i < sizeof (HDR.init_SPI); i++)
        *((uint8_t*)&HDR.init_SPI + i) = rand ();
    HDR.resp_SPI = 0;
    HDR.next_payload = PL_SA;
    HDR.versions = VERSIONS;
    HDR.exchange_type = IKE_SA_INIT;
    HDR.flags = XXI;
    HDR.message_ID = MID;
    HDR.length = ike_sa_init_len = 
        sizeof (ike_header) + SAi1.header.payload_length +
        KEi.header.payload_length + Ni.header.payload_length;

    ike_sa_init = calloc (1, HDR.length);
    uint32_t offset = 0;
    offset += ike_hdr2char  (&HDR,  ike_sa_init + offset);
    offset += sa_pl2char    (&SAi1, ike_sa_init + offset);
    offset += ke_pl2char    (&KEi,  ike_sa_init + offset);
    offset += nonce_pl2char (&Ni,   ike_sa_init + offset);

    free (buff);
    buff = calloc (1, HDR.length);
    memcpy (buff, ike_sa_init, HDR.length);

    return offset;
}

int ike_init_resp (void)
{
    acc_proposal = SA_recv.proposals;
    Ni = NONCE_recv;
    KEi = KE_recv;
    memcpy (SPIi, &HDR_recv.init_SPI, sizeof (uint64_t));
    SAr1.proposals = acc_proposal;
    SAr1.header.next_payload = PL_KE;
    SAr1.header.critical = 0;
    SAr1.header.payload_length = sizeof (generic_payload_header);
    uint32_t prop_num = 0;
    do SAr1.header.payload_length += SAr1.proposals[prop_num].proposal_length;
    while (SAr1.proposals[prop_num++].more != 0);

    dh_group = 0;
    for (int i = 0; i < acc_proposal->num_transforms; i++)
        if (acc_proposal->transforms[i].transform_type == DH_GR &&
            acc_proposal->transforms[i].transform_ID > dh_group)
            dh_group = acc_proposal->transforms[i].transform_ID;
    modp = get_modp (dh_group);

    KEr.header.next_payload = PL_NONCE;
    KEr.header.critical = 0;
    KEr.header.payload_length = sizeof (KEr.header) +
        sizeof (KEr.dh_group_num) + sizeof (KEr.reserved) + modp/8;
    KEr.dh_group_num = dh_group;
    KEr.reserved = 0;
    KEr.key_exchange_data = calloc (modp/8, 1);
    MEMCHECK (KEr.key_exchange_data);

    mpz_set (dh_b, dh_nsize_random (B_SIZE));
    dh_set_p (modp);
    mpz_powm_sec (dh_B, dh_g, dh_b, dh_p);
    size_t *count = (size_t*) calloc (1, sizeof (size_t));
    uint32_t size = mpz_sizeinbase (dh_B, 256);
    mpz_export (KEr.key_exchange_data + modp/8 - size, count, 0, sizeof (char), 1, 0, dh_B);
    free (count);

    Nr.header.next_payload = NO_NEXT_PL;
    Nr.header.critical = 0;
    Nr_len = 4*(4 + (rand() % 60));
    Nr.header.payload_length = sizeof (Nr.header) + Nr_len;
    Nr.nonce_data = calloc (1, Nr_len);
    for (int i = 0; i < Nr_len; i++)
        Nr.nonce_data[i] = rand ();

    ike_header HDR;
    HDR.init_SPI = HDR_recv.init_SPI;
    for (int i = 0; i < sizeof (HDR.resp_SPI); i++)
        SPIr[i] = *((char*)&HDR.resp_SPI + i) = rand ();
    HDR.next_payload = PL_SA;
    HDR.versions = VERSIONS;
    HDR.exchange_type = IKE_SA_INIT;
    HDR.flags = RXX;
    HDR.message_ID = HDR_recv.message_ID;
    HDR.length = ike_sa_init_resp_len = 
        sizeof (ike_header) + SAr1.header.payload_length +
        KEr.header.payload_length + Nr.header.payload_length;

    free (buff);
    buff = calloc (1, HDR.length);
    uint32_t offset = 0;
    offset += ike_hdr2char  (&HDR,  buff + offset);
    offset += sa_pl2char    (&SAr1, buff + offset);
    offset += ke_pl2char    (&KEr,  buff + offset);
    offset += nonce_pl2char (&Nr,   buff + offset);

    ike_sa_init_resp_len = HDR.length;
    ike_sa_init_resp = calloc (1, ike_sa_init_resp_len);
    memcpy (ike_sa_init_resp, buff, ike_sa_init_resp_len);
    return offset;
}

int ike_auth (void)
{
    MID++;

    IDi.ID_type = ID_IPV4_ADDR;
    IDi.reserved = 0;
    uint32_t id_len = get_id_len (ID_IPV4_ADDR);
    IDi.identification_data = calloc (1, id_len);
    IDi.identification_data[0] = 127;
    IDi.identification_data[1] = 0;
    IDi.identification_data[2] = 0;
    IDi.identification_data[3] = 1;
    IDi.header.next_payload = PL_AUTH;
    IDi.header.critical = 0;
    IDi.header.payload_length = 8 + id_len;

    AUTH.auth_method = DSS_DS;
    AUTH.reserved = 0;
    AUTH.authentication_data = calloc (1, integ_key_len);
    integ_func (SK_pi, integ_key_len,
                ike_sa_init, ike_sa_init_len,
                AUTH.authentication_data);
    AUTH.header.next_payload = PL_SA;
    AUTH.header.critical = 0;
    AUTH.header.payload_length = 8 + integ_key_len;

    SAi2 = SAr1;
    SAi2.header.next_payload = PL_TSi;

    TSi.number_of_TSs = 1;
    TSi.reserved = 0;
    TSi.traffic_selectors =
        calloc (TSi.number_of_TSs, sizeof (traffic_selector));
    TSi.traffic_selectors[0].TS_type = TS_IPV4_ADDR_RAN;
    TSi.traffic_selectors[0].IP_protocol_ID = ALL_PROT;
    uint8_t addr_len = get_addr_len (TSi.traffic_selectors[0].TS_type);
    TSi.traffic_selectors[0].selector_length =
        sizeof (generic_payload_header) + 4 + 2*addr_len;
    TSi.traffic_selectors[0].start_port = 0;
    TSi.traffic_selectors[0].end_port = 65535;
    TSi.traffic_selectors[0].starting_address =
        calloc (1, get_addr_len (TSi.traffic_selectors[0].TS_type));
    TSi.traffic_selectors[0].ending_address =
        calloc (1, get_addr_len (TSi.traffic_selectors[0].TS_type));
    TSi.traffic_selectors[0].starting_address[0] = 127;
    TSi.traffic_selectors[0].starting_address[1] = 0;
    TSi.traffic_selectors[0].starting_address[2] = 0;
    TSi.traffic_selectors[0].starting_address[3] = 1;
    TSi.traffic_selectors[0].ending_address[0] = 127;
    TSi.traffic_selectors[0].ending_address[1] = 0;
    TSi.traffic_selectors[0].ending_address[2] = 0;
    TSi.traffic_selectors[0].ending_address[3] = 2;
    TSi.header.next_payload = PL_TSr;
    TSi.header.critical = 0;
    TSi.header.payload_length = 8;
    for (int i = 0; i < TSi.number_of_TSs; i++)
        TSi.header.payload_length += TSi.traffic_selectors[i].selector_length;

    TSr.number_of_TSs = 1;
    TSr.reserved = 0;
    TSr.traffic_selectors =
        calloc (TSr.number_of_TSs, sizeof (traffic_selector));
    TSr.traffic_selectors[0].TS_type = TS_IPV4_ADDR_RAN;
    TSr.traffic_selectors[0].IP_protocol_ID = ALL_PROT;
    addr_len = get_addr_len (TSr.traffic_selectors[0].TS_type);
    TSr.traffic_selectors[0].selector_length =
        sizeof (generic_payload_header) + 4 + 2*addr_len;
    TSr.traffic_selectors[0].start_port = 0;
    TSr.traffic_selectors[0].end_port = 65535;
    TSr.traffic_selectors[0].starting_address =
        calloc (1, get_addr_len (TSr.traffic_selectors[0].TS_type));
    TSr.traffic_selectors[0].ending_address =
        calloc (1, get_addr_len (TSr.traffic_selectors[0].TS_type));
    TSr.traffic_selectors[0].starting_address[0] = 127;
    TSr.traffic_selectors[0].starting_address[1] = 0;
    TSr.traffic_selectors[0].starting_address[2] = 0;
    TSr.traffic_selectors[0].starting_address[3] = 1;
    TSr.traffic_selectors[0].ending_address[0] = 127;
    TSr.traffic_selectors[0].ending_address[1] = 0;
    TSr.traffic_selectors[0].ending_address[2] = 0;
    TSr.traffic_selectors[0].ending_address[3] = 2;
    TSr.header.next_payload = NO_NEXT_PL;
    TSr.header.critical = 0;
    TSr.header.payload_length = 8;
    for (int i = 0; i < TSr.number_of_TSs; i++)
        TSr.header.payload_length += TSr.traffic_selectors[i].selector_length;

    uint32_t data_len = 
        IDi.header.payload_length +
        AUTH.header.payload_length +
        SAi2.header.payload_length +
        TSi.header.payload_length +
        TSr.header.payload_length;
    uint8_t pad_len = (encr_block_len - (data_len+1 % encr_block_len)) % encr_block_len;

    SK.header.next_payload = PL_IDi;
    SK.header.critical = 0;
    SK.header.payload_length =
        sizeof (SK.header) +
        encr_block_len +
        data_len +
        pad_len+1 +
        integ_key_len;

    SK.iv = calloc (1, iv_len);
    for (int i = 0; i < iv_len; i++)
        SK.iv[i] = rand ();

    uint8_t *data = calloc (1, data_len + pad_len+1);
    uint32_t offset = 0;
    offset += id_pl2char   (&IDi,  data + offset);
    offset += auth_pl2char (&AUTH, data + offset);
    offset += sa_pl2char   (&SAi2, data + offset);
    offset += ts_pl2char   (&TSi,  data + offset);
    offset += ts_pl2char   (&TSr,  data + offset);
    data[data_len + pad_len] = pad_len;

    SK.enc_data = calloc (1, data_len + pad_len+1);
    encr_func (SK.enc_data,
               data,
               data_len + pad_len+1,
               SK_ei,
               SK.iv);

    SK.icv = calloc (1, integ_key_len);

    ike_header HDR;
    memcpy (&HDR.init_SPI, SPIi, sizeof (uint64_t));
    memcpy (&HDR.resp_SPI, SPIr, sizeof (uint64_t));
    HDR.next_payload = PL_SK;
    HDR.versions = VERSIONS;
    HDR.exchange_type = IKE_AUTH;
    HDR.flags = XXI;
    HDR.message_ID = MID;
    HDR.length = 
        sizeof (ike_header) +
        SK.header.payload_length;

    free (buff);
    buff = calloc (1, HDR.length);
    offset = 0;
    offset += ike_hdr2char (&HDR, buff + offset);
    offset += enc_pl2char  (&SK,  buff + offset,
                            iv_len, integ_key_len);
    offset -= integ_key_len;
    integ_func (SK_ai, integ_key_len,
                buff, offset,
                SK.icv);
    memcpy (buff + offset, SK.icv, integ_key_len);
    offset += integ_key_len;
    return offset;
}

int ike_auth_resp (void)
{
    IDr.ID_type = ID_IPV4_ADDR;
    IDr.reserved = 0;
    uint32_t id_len = get_id_len (ID_IPV4_ADDR);
    IDr.identification_data = calloc (1, id_len);
    IDr.identification_data[0] = 127;
    IDr.identification_data[1] = 0;
    IDr.identification_data[2] = 0;
    IDr.identification_data[3] = 2;
    IDr.header.next_payload = PL_AUTH;
    IDr.header.critical = 0;
    IDr.header.payload_length = 8 + id_len;

    AUTH.auth_method = DSS_DS;
    AUTH.reserved = 0;
    free (AUTH.authentication_data);
    AUTH.authentication_data = calloc (1, integ_key_len);
    integ_func (SK_pr, integ_key_len,
                ike_sa_init_resp, ike_sa_init_resp_len,
                AUTH.authentication_data);
    AUTH.header.next_payload = PL_SA;
    AUTH.header.critical = 0;
    AUTH.header.payload_length = 8 + integ_key_len;

    SAr2 = SAr1;
    SAr2.header.next_payload = PL_TSi;

    TSi.number_of_TSs = 1;
    TSi.reserved = 0;
    free (TSi.traffic_selectors);
    TSi.traffic_selectors =
        calloc (TSi.number_of_TSs, sizeof (traffic_selector));
    TSi.traffic_selectors[0].TS_type = TS_IPV4_ADDR_RAN;
    TSi.traffic_selectors[0].IP_protocol_ID = ALL_PROT;
    uint8_t addr_len = get_addr_len (TSi.traffic_selectors[0].TS_type);
    TSi.traffic_selectors[0].selector_length =
        sizeof (generic_payload_header) + 4 + 2*addr_len;
    TSi.traffic_selectors[0].start_port = 0;
    TSi.traffic_selectors[0].end_port = 65535;
    // free (TSi.traffic_selectors[0].starting_address);
    TSi.traffic_selectors[0].starting_address =
        calloc (1, get_addr_len (TSi.traffic_selectors[0].TS_type));
    // free (TSi.traffic_selectors[0].ending_address);
    TSi.traffic_selectors[0].ending_address =
        calloc (1, get_addr_len (TSi.traffic_selectors[0].TS_type));
    TSi.traffic_selectors[0].starting_address[0] = 127;
    TSi.traffic_selectors[0].starting_address[1] = 0;
    TSi.traffic_selectors[0].starting_address[2] = 0;
    TSi.traffic_selectors[0].starting_address[3] = 1;
    TSi.traffic_selectors[0].ending_address[0] = 127;
    TSi.traffic_selectors[0].ending_address[1] = 0;
    TSi.traffic_selectors[0].ending_address[2] = 0;
    TSi.traffic_selectors[0].ending_address[3] = 2;
    TSi.header.next_payload = PL_TSr;
    TSi.header.critical = 0;
    TSi.header.payload_length = 8;
    for (int i = 0; i < TSi.number_of_TSs; i++)
        TSi.header.payload_length += TSi.traffic_selectors[i].selector_length;

    TSr.number_of_TSs = 1;
    TSr.reserved = 0;
    free (TSr.traffic_selectors);
    TSr.traffic_selectors =
        calloc (TSr.number_of_TSs, sizeof (traffic_selector));
    TSr.traffic_selectors[0].TS_type = TS_IPV4_ADDR_RAN;
    TSr.traffic_selectors[0].IP_protocol_ID = ALL_PROT;
    addr_len = get_addr_len (TSr.traffic_selectors[0].TS_type);
    TSr.traffic_selectors[0].selector_length =
        sizeof (generic_payload_header) + 4 + 2*addr_len;
    TSr.traffic_selectors[0].start_port = 0;
    TSr.traffic_selectors[0].end_port = 65535;
    free (TSr.traffic_selectors[0].starting_address);
    TSr.traffic_selectors[0].starting_address =
        calloc (1, get_addr_len (TSr.traffic_selectors[0].TS_type));
    free (TSr.traffic_selectors[0].ending_address);
    TSr.traffic_selectors[0].ending_address =
        calloc (1, get_addr_len (TSr.traffic_selectors[0].TS_type));
    TSr.traffic_selectors[0].starting_address[0] = 127;
    TSr.traffic_selectors[0].starting_address[1] = 0;
    TSr.traffic_selectors[0].starting_address[2] = 0;
    TSr.traffic_selectors[0].starting_address[3] = 1;
    TSr.traffic_selectors[0].ending_address[0] = 127;
    TSr.traffic_selectors[0].ending_address[1] = 0;
    TSr.traffic_selectors[0].ending_address[2] = 0;
    TSr.traffic_selectors[0].ending_address[3] = 2;
    TSr.header.next_payload = NO_NEXT_PL;
    TSr.header.critical = 0;
    TSr.header.payload_length = 8;
    for (int i = 0; i < TSr.number_of_TSs; i++)
        TSr.header.payload_length += TSr.traffic_selectors[i].selector_length;

    uint32_t data_len = 
        IDr.header.payload_length +
        AUTH.header.payload_length +
        SAr2.header.payload_length +
        TSi.header.payload_length +
        TSr.header.payload_length;
    uint8_t pad_len = (encr_block_len - (data_len+1 % encr_block_len)) % encr_block_len;

    SK.header.next_payload = PL_IDr;
    SK.header.critical = 0;
    SK.header.payload_length =
        sizeof (SK.header) +
        encr_block_len +
        data_len +
        pad_len+1 +
        integ_key_len;

    free (SK.iv);
    SK.iv = calloc (1, iv_len);
    for (int i = 0; i < iv_len; i++)
        SK.iv[i] = rand ();

    uint8_t *data = calloc (1, data_len + pad_len+1);
    uint32_t offset = 0;
    offset += id_pl2char   (&IDr,  data + offset);
    offset += auth_pl2char (&AUTH, data + offset);
    offset += sa_pl2char   (&SAi2, data + offset);
    offset += ts_pl2char   (&TSi,  data + offset);
    offset += ts_pl2char   (&TSr,  data + offset);
    data[data_len + pad_len] = pad_len;

    free (SK.enc_data);
    SK.enc_data = calloc (1, data_len + pad_len+1);
    encr_func (SK.enc_data,
               data,
               data_len + pad_len+1,
               SK_er,
               SK.iv);

    free (SK.icv);
    SK.icv = calloc (1, integ_key_len);

    ike_header HDR;
    memcpy (&HDR.init_SPI, SPIi, sizeof (uint64_t));
    memcpy (&HDR.resp_SPI, SPIr, sizeof (uint64_t));
    HDR.next_payload = PL_SK;
    HDR.versions = VERSIONS;
    HDR.exchange_type = IKE_AUTH;
    HDR.flags = XXI;
    HDR.message_ID = MID;
    HDR.length = 
        sizeof (ike_header) +
        SK.header.payload_length;

    // free (buff);
    buff = calloc (1, HDR.length);
    offset = 0;
    offset += ike_hdr2char (&HDR, buff + offset);
    offset += enc_pl2char  (&SK,  buff + offset,
                            iv_len, integ_key_len);
    offset -= integ_key_len;
    integ_func (SK_ai, integ_key_len,
                buff, offset,
                SK.icv);
    memcpy (buff + offset, SK.icv, integ_key_len);
    offset += integ_key_len;
    return offset;
}

int receive (void)
{
    parse_buff ();
    if (HDR_recv.exchange_type == IKE_SA_INIT)
        if (HDR_recv.flags == 8)
        {
            ike_init_resp ();

            mpz_powm_sec (dh_K, dh_A, dh_b, dh_p);
            size_t *count = (size_t*) calloc (1, sizeof (size_t));
            uint32_t size = mpz_sizeinbase (dh_K, 256);
            K = calloc (1, modp/8);
            mpz_export (K + modp/8 - size, count, 0, sizeof (char), 1, 0, dh_K);
            free (count);
            // dh_clear ();
            compute_keys ();
        }
        else
        {
            proposal *acc_proposal = SA_recv.proposals;

            mpz_import (dh_B, modp/8, 1, sizeof (char), 1, 0, KE_recv.key_exchange_data);
            mpz_powm_sec (dh_K, dh_B, dh_a, dh_p);

            size_t *count = (size_t*) calloc (1, sizeof (size_t));
            uint32_t size = mpz_sizeinbase (dh_K, 256);
            K = calloc (1, modp/8);
            mpz_export (K + modp/8 - size, count, 0, sizeof (char), 1, 0, dh_K);
            free (count);
            dh_clear ();
            compute_keys (acc_proposal);
        }
    if (HDR_recv.exchange_type == IKE_AUTH)
        if (HDR_recv.flags == 8)
        {
            ike_auth_resp ();
        }
    // mem_clr ();
}

int parse_buff (void)
{
    uint32_t offset = char2ike_hdr (buff, &HDR_recv);
    uint8_t next_payload = HDR_recv.next_payload;
    while (next_payload != NO_NEXT_PL)
    {
        if (next_payload == PL_SA)
        {
            offset += char2sa_pl (buff + offset, &SA_recv);
            next_payload = SA_recv.header.next_payload;
        }
        else if (next_payload == PL_KE)
        {
            offset += char2ke_pl (buff + offset, &KE_recv);
            next_payload = KE_recv.header.next_payload;
        }
        else if (next_payload == PL_IDi)
        {
            offset += char2id_pl (buff + offset, &IDi_recv);
            next_payload = IDi_recv.header.next_payload;
        }
        else if (next_payload == PL_IDr)
        {
            offset += char2id_pl (buff + offset, &IDr_recv);
            next_payload = IDr_recv.header.next_payload;
        }
        else if (next_payload == PL_CERT)
        {
        }
        else if (next_payload == PL_CERTREQ)
        {
        }
        else if (next_payload == PL_AUTH)
        {
            offset += char2auth_pl (buff + offset, &AUTH_recv);
            next_payload = AUTH_recv.header.next_payload;
        }
        else if (next_payload == PL_NONCE)
        {
            offset += char2nonce_pl (buff + offset, &NONCE_recv);
            next_payload = NONCE_recv.header.next_payload;
        }
        else if (next_payload == PL_NOTIFY)
        {
        }
        else if (next_payload == PL_DELETE)
        {
        }
        else if (next_payload == PL_VID)
        {
        }
        else if (next_payload == PL_TSi)
        {
            offset += char2ts_pl (buff + offset, &TSi_recv);
            next_payload = TSi_recv.header.next_payload;
        }
        else if (next_payload == PL_TSr)
        {
            offset += char2ts_pl (buff + offset, &TSr_recv);
            next_payload = TSr_recv.header.next_payload;
        }
        else if (next_payload == PL_SK)
        {
            offset += char2enc_pl (buff + offset, &SK_recv,
                                   iv_len, integ_key_len);
            if (check_icv () == INVALID)
                return -1;
            return parse_SK ();
        }
        else if (next_payload == PL_CP)
        {
        }
        else if (next_payload == PL_EAP)
        {
        }
        else
        {
            printf ("%d\n", next_payload);
            return -1;
        }
    }
    return 0;
}

int parse_SK (void)
{
    free (buff);
    buff = calloc (1, sizeof (ike_header) + SK_recv.header.payload_length);
    ike_header HDR = HDR_recv;
    HDR.next_payload = SK_recv.header.next_payload;
    HDR.length = sizeof (ike_header) + SK_recv.header.payload_length;
    uint32_t offset = ike_hdr2char (&HDR, buff);
    uint8_t *key_e = (HDR_recv.flags == XXI)?SK_ei:SK_er;
    decr_func (buff + offset,
               SK_recv.enc_data,
               SK_recv.header.payload_length - integ_key_len,
               key_e,
               SK_recv.iv);
    parse_buff ();
    return 0;
}

int check_icv (void)
{
    uint8_t *icv = calloc (1, integ_key_len);
    uint8_t *key = (HDR_recv.flags == XXI)?SK_ai:SK_ar;
    integ_func (key, integ_key_len,
                buff, HDR_recv.length - integ_key_len,
                icv);
    for (int i = 0; i < integ_key_len; i++)
        if (icv[i] != SK_recv.icv[i])
            return INVALID;
    return VALID;
}

int get_key_len (transform *trans)
{
    if (trans->transform_length > 8 &&
        trans->attribute_type == AT_KEY_LEN)
        return (trans->attribute_value[0] << 8) + trans->attribute_value[1];
    else if (trans->transform_type == ENCR)
        if (trans->transform_ID == ENCR_DES_IV64 ||
            trans->transform_ID == ENCR_DES_IV32 ||
            trans->transform_ID == ENCR_DES)
            return 64;
        else if (trans->transform_ID == ENCR_3DES)
            return 168;
        else if (trans->transform_ID == ENCR_RC5 ||
                 trans->transform_ID == ENCR_IDEA)
            return 128;
        else if (trans->transform_ID == ENCR_NULL)
            return 0;
}

int get_block_len (uint16_t encr, uint16_t encr_key_len)
{
    if (encr == ENCR_AES_CBC ||
        encr == ENCR_AES_CTR)
        return 128;
    else return 0;
}

int get_iv_len (uint16_t encr, uint16_t encr_key_len)
{
    if (encr == ENCR_AES_CBC ||
        encr == ENCR_AES_CTR)
        return 128;
    else return 0;
}

int get_id_len (uint32_t id_type)
{
    switch (id_type)
    {
        case ID_IPV4_ADDR:   return 4;
        case ID_FQDN:        return 0;
        case ID_RFC822_ADDR: return 0;
        case ID_IPV6_ADDR:   return 16;
        case ID_DER_ASN1_DN: return 0;
        case ID_DER_ASN1_GN: return 0;
        case ID_KEY_ID:      return 0;
        default:             return 0;
    }
}

int get_addr_len (uint8_t ts_type)
{
    if (ts_type == TS_IPV4_ADDR_RAN) return 4;
    if (ts_type == TS_IPV6_ADDR_RAN) return 16;
}

void compute_keys (void)
{
    encr_key_len = 0;
    prf_key_len = 0;
    integ_key_len = 0;
    acc_prf = 0;
    dh_group = 0;
    for (int i = 0; i < acc_proposal->num_transforms; i++)
    {
        if (acc_proposal->transforms[i].transform_type == ENCR)
        {
            acc_encr = acc_proposal->transforms[i].transform_ID;
            encr_key_len = get_key_len (&acc_proposal->transforms[i]) / 8;
            encr_block_len = get_block_len (acc_encr, encr_key_len) / 8;
            iv_len = get_iv_len (acc_encr, encr_key_len) / 8;
        }
        if (acc_proposal->transforms[i].transform_type == PRF)
        {
            acc_prf = acc_proposal->transforms[i].transform_ID;
            prf_key_len = get_key_len (&acc_proposal->transforms[i]) / 8;
        }
        if (acc_proposal->transforms[i].transform_type == INTEG)
        {
            acc_integ = acc_proposal->transforms[i].transform_ID;
            integ_key_len = get_key_len (&acc_proposal->transforms[i]) / 8;
        }
        if (acc_proposal->transforms[i].transform_type == DH_GR &&
            acc_proposal->transforms[i].transform_ID > dh_group)
            dh_group = acc_proposal->transforms[i].transform_ID;
            modp = get_modp (dh_group);
    }
    uint32_t offset = 0;
    uint32_t S_len = Ni_len + Nr_len;
    uint8_t *S = calloc (1, S_len);
    memcpy (S + offset, Ni.nonce_data, Ni_len);
    offset += Ni_len;
    memcpy (S + offset, Nr.nonce_data, Nr_len);
    offset += Nr_len;

    uint8_t *SKEYSEED = calloc (1, prf_key_len);
    prf_func (S, S_len, K, modp/8, SKEYSEED);

    free (K);

    uint16_t key_seq_len;
    key_seq_len = 2*encr_key_len + 
                  3*prf_key_len + 
                  2*integ_key_len;
    key_seq_len = key_seq_len/prf_key_len+1;
    uint8_t *key_seq = calloc (key_seq_len, prf_key_len);

    S_len = Ni_len + Nr_len + 2*sizeof (uint64_t)+1;
    S = realloc (S, S_len);
    memcpy (S + offset, SPIi, sizeof (uint64_t));
    offset += sizeof (uint64_t);
    memcpy (S + offset, SPIr, sizeof (uint64_t));

    offset = 0;
    S[S_len-1] = 1;
    prf_func (SKEYSEED, prf_key_len,
               S, S_len,
               key_seq + offset);
    S = realloc (S, S_len + prf_key_len);
    memcpy (S + prf_key_len, S, S_len-1);
    memcpy (S, key_seq + offset, prf_key_len);
    offset += prf_key_len;
    for (int i = 1; i < key_seq_len; i++)
    {
        S[prf_key_len + S_len-1] = (uint8_t) (i+1);
        prf_func (SKEYSEED, prf_key_len,
                   S, S_len + prf_key_len,
                   key_seq + offset);
        memcpy (S, key_seq + offset, prf_key_len);
        offset += prf_key_len;
    }

    SK_d =  calloc (1, prf_key_len);
    SK_ai = calloc (1, integ_key_len);
    SK_ar = calloc (1, integ_key_len);
    SK_ei = calloc (1, encr_key_len);
    SK_er = calloc (1, encr_key_len);
    SK_pi = calloc (1, prf_key_len);
    SK_pr = calloc (1, prf_key_len);

    offset = 0;
    memcpy (SK_d,  key_seq + offset, prf_key_len);
    offset += prf_key_len;
    memcpy (SK_ai, key_seq + offset, integ_key_len);
    offset += integ_key_len;
    memcpy (SK_ar, key_seq + offset, integ_key_len);
    offset += integ_key_len;
    memcpy (SK_ei, key_seq + offset, encr_key_len);
    offset += encr_key_len;
    memcpy (SK_er, key_seq + offset, encr_key_len);
    offset += encr_key_len;
    memcpy (SK_pi, key_seq + offset, prf_key_len);
    offset += prf_key_len;
    memcpy (SK_pr, key_seq + offset, prf_key_len);
    offset += prf_key_len;

    // dbg_print ();

    free (S);
    free (key_seq);
    free (SKEYSEED);
}

void encr_func (uint8_t *output,
                uint8_t *input,
                uint32_t length,
                uint8_t *key,
                uint8_t *iv)
{
    if (acc_encr == ENCR_AES_CBC &&
        encr_key_len*8 == 128);
        AES128_CBC_encrypt_buffer (output, input, length, key, iv);
}

void decr_func (uint8_t *output,
                uint8_t *input,
                uint32_t length,
                uint8_t *key,
                uint8_t *iv)
{
    if (acc_encr == ENCR_AES_CBC &&
        encr_key_len*8 == 128);
        AES128_CBC_decrypt_buffer (output, input, length, key, iv);
}

void prf_func (uint8_t *key, uint32_t keylen,
               uint8_t *data, uint32_t datalen,
               uint8_t *output)
{
    if (acc_prf == PRF_HMAC_SHA1)
        hmac_sha1 (key, keylen,
                   data, datalen,
                   output);
}

void integ_func (uint8_t *key, uint32_t keylen,
                 uint8_t *data, uint32_t datalen,
                 uint8_t *output)
{
    if (acc_prf == AUTH_HMAC_SHA1_96)
        hmac_sha1 (key, keylen,
                   data, datalen,
                   output);
}

void print_packet (void)
{
    const char size = 16;
    ike_header hdr;
    char2ike_hdr (buff, &hdr);

    for (int i = 0; i < hdr.length; i++)
    {
        if (i % size == 0) printf ("%03x-%03x  ", i, i+size-1);
        printf ("%02x:", buff[i]);
        if (i % size == size-1 && i != hdr.length-1) puts ("");
    }
    puts ("");

    // printf ("b'");
    // for (int i = 0; i < hdr.length; i++)
    // {
    //     printf ("\\x%02x", buff[i]);
    // }
    // puts ("'");
}

void dbg_print (void)
{
    // printf ("SPIi:\n");
    // dbg_print_buf (SPIi, sizeof (long long));

    // printf ("SPIr:\n");
    // dbg_print_buf (SPIr, sizeof (long long));

    // printf ("Ni:\n");
    // dbg_print_buf (Ni.nonce_data, Ni_len);

    // printf ("Nr:\n");
    // dbg_print_buf (Nr.nonce_data, Nr_len);

    // printf ("K:\n");
    // dbg_print_buf (K, modp/8);

    printf ("SK_d:\n");
    dbg_print_buf (SK_d, prf_key_len);

    printf ("SK_ai:\n");
    dbg_print_buf (SK_ai, integ_key_len);

    printf ("SK_ar:\n");
    dbg_print_buf (SK_ar, integ_key_len);

    printf ("SK_ei:\n");
    dbg_print_buf (SK_ei, encr_key_len);

    printf ("SK_er:\n");
    dbg_print_buf (SK_er, encr_key_len);

    printf ("SK_pi:\n");
    dbg_print_buf (SK_pi, prf_key_len);

    printf ("SK_pr:\n");
    dbg_print_buf (SK_pr, prf_key_len);
}

void dbg_print_buf (uint8_t *buf, uint32_t len)
{
     printf ("b'");
     for (int i = 0; i < len; i++)
         printf ("\\x%02x", buf[i]);
     puts ("'\n");

    // for (int i = 0; i < len; i++)
    //     printf ("%02x:", buf[i]);
    // puts ("");
}