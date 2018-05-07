/* IKE header */

#include "definitions.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

#pragma pack (1)

typedef struct ike_header
{
    uint64_t init_SPI;                /*IKE SA Initiator's SPI*/
    uint64_t resp_SPI;                /*IKE SA Responder's SPI*/
    uint8_t next_payload;             /*Type of PL in current message*/
    uint8_t versions;                 /*Major version. Must be 32*/
    uint8_t exchange_type;            /*Exchange Type*/
    uint8_t flags;                    /* XXRVIXXX */
    uint32_t message_ID;              /*Message ID*/
    uint32_t length;                  /*Length of the total message (HDR+PL) in octets*/
} ike_header;

typedef struct generic_payload_header
{
    uint8_t next_payload;             /*Type of next PL. Zero if last*/
    uint8_t critical;                 /*Must be 0*/
    uint16_t payload_length;          /*Length of current PL and PL_HDR in octets*/
} generic_payload_header;

typedef struct proposal
{
    uint8_t more;                     /*0 - last proposal; 2 - more*/
    uint8_t reserved;                 /*Must be 0*/
    uint16_t proposal_length;         /*Length of this proposal*/
    uint8_t proposal_num;             /*Number of proposal*/
    uint8_t protocol_ID;              /*IKE:1, AH:2, ESP:3*/
    uint8_t SPI_size;                 /*Init:0, IKE:8, ESP,AH:4*/
    uint8_t num_transforms;           /*The number of transforms in this proposal*/
    uint8_t *SPI;
    struct transform *transforms;
} proposal;

typedef struct SA_payload
{
    struct generic_payload_header header;
    struct proposal *proposals;
} SA_payload;

typedef struct transform
{
    uint8_t more;                     /*0 - last transform; 3 - more*/
    uint8_t reserved1;                /*Must be 0*/
    uint16_t transform_length;        /*Length 0f this transform in octets*/
    uint8_t transform_type;           /**/
    uint8_t reserved2;                /*Must be 0*/
    uint16_t transform_ID;            /**/
    uint8_t attribute_format;         /*Attribute format. 0:TLV, 128:TV*/
    uint8_t attribute_type;           /*14 for ENCR*/
    uint8_t *attribute_value;         /*Attribute value (variable)*/
} transform;

typedef struct key_exchange_payload
{
    struct generic_payload_header header;
    uint16_t dh_group_num;            /*Diffie-Hellman Group Num*/
    uint16_t reserved;                /*Must be 0*/
    uint8_t *key_exchange_data;       /*Key Exchange Data*/
} key_exchange_payload;

typedef struct identification_payload
{
    struct generic_payload_header header;
    uint8_t ID_type;                  /*Type of Identification being used*/
    unsigned reserved : 24;           /*Must be 0*/
    uint8_t *identification_data;     /*Identification Data*/
} identification_payload;

typedef struct certificate_payload
{
    struct generic_payload_header header;
    uint8_t cert_encoding;            /*Type of certificate or certificate-related information*/
    uint8_t *certificate_data;        /*Certificate Data*/
} certificate_payload;

typedef struct certificate_request_payload
{
    struct generic_payload_header header;
    uint8_t cert_encoding;            /*Type of certificate or certificate-related information*/
    uint8_t *certificate_authority;   /*Certificate Authority*/
} certificate_request_payload;

typedef struct authentication_payload
{
    struct generic_payload_header header;
    uint8_t auth_method;               /*Method of authentication used*/
    unsigned reserved : 24;            /*Must be 0*/
    uint8_t *authentication_data;      /*Authentication Data*/
} authentication_payload;

typedef struct nonce_payload
{
    struct generic_payload_header header;
    uint8_t *nonce_data;                /*Nonce Data*/
} nonce_payload;

typedef struct notify_payload
{
    struct generic_payload_header header;
    uint8_t protocol_ID;
    uint8_t SPI_size;
    uint16_t notify_message_type;
    uint8_t *SPI;
    uint8_t *notification_data;
} notify_payload;

typedef struct delete_payload
{
    struct generic_payload_header header;
    uint8_t protocol_ID;
    uint8_t SPI_size;
    uint16_t num_of_SPIs;
    uint8_t *SPIes;
} delete_payload;

typedef struct vendor_ID_payload
{
    struct generic_payload_header header;
    uint8_t *VID;
} vendor_ID_payload;

typedef struct traffic_selector
{
    uint8_t TS_type;
    uint8_t IP_protocol_ID;
    uint16_t selector_length;
    uint16_t start_port;
    uint16_t end_port;
    uint8_t *starting_address;
    uint8_t *ending_address;
} traffic_selector;

typedef struct traffic_selector_payload
{
    struct generic_payload_header header;
    uint8_t number_of_TSs;                  /**/
    unsigned reserved : 24;                 /*Must be 0*/
    traffic_selector *traffic_selectors;
} traffic_selector_payload;

typedef struct configuration_attribute
{
    uint16_t attribute_type;
    uint16_t length;
    uint8_t *value;
} configuration_attribute;

// typedef struct configuration_payload
// {
//     struct generic_payload_header header;
//     uint8_t CFG_type;                       /**/
//     unsigned reserved : 24;                 /*Must be 0*/
//     configuration_attribute *configuration_attributes;
// } configuration_payload;

typedef struct eap_payload
{
    struct generic_payload_header header;
    //EAP Message
} eap_payload;

typedef struct encrypted_payload
{
    struct generic_payload_header header;
    uint8_t *iv;
    uint8_t *enc_data;
    uint8_t *icv;
} encrypted_payload;

mpz_srcptr dh_nsize_random (uint32_t size);
void dh_initialize (void);
void dh_clear (void);
void dh_set_p (uint32_t modp);
uint32_t get_modp (uint32_t dh_group);

uint32_t ike_hdr2char (ike_header *hdr, uint8_t *buf);
uint32_t char2ike_hdr (uint8_t *buf, ike_header *hdr);
uint32_t gen_pl_hdr2char (generic_payload_header *hdr, uint8_t *buf);
uint32_t char2gen_pl_hdr (uint8_t *buf, generic_payload_header *hdr);
uint32_t transform2char (transform *trans, uint8_t *buf);
uint32_t char2transform (uint8_t *buf, transform *trans);
uint32_t proposal2char (proposal *prop, uint8_t *buf);
uint32_t char2proposal (uint8_t *buf, proposal *prop);
uint32_t sa_pl2char (SA_payload *pl, uint8_t *buf);
uint32_t char2sa_pl (uint8_t *buf, SA_payload *pl);
uint32_t ke_pl2char (key_exchange_payload *pl, uint8_t *buf);
uint32_t char2ke_pl (uint8_t *buf, key_exchange_payload *pl);
uint32_t id_pl2char (identification_payload *pl, uint8_t *buf);
uint32_t char2id_pl (uint8_t *buf, identification_payload *pl);
// uint32_t cert_pl2char (certificate_payload *pl, uint8_t *buf);
// uint32_t char2cert_pl (uint8_t *buf, certificate_payload *pl);
// uint32_t cert_req_pl2char (certificate_request_payload *pl, uint8_t *buf);
// uint32_t char2cert_req_pl (uint8_t *buf, certificate_request_payload *pl);
uint32_t auth_pl2char (authentication_payload *pl, uint8_t *buf);
uint32_t char2auth_pl (uint8_t *buf, authentication_payload *pl);
uint32_t nonce_pl2char (nonce_payload *pl, uint8_t *buf);
uint32_t char2nonce_pl (uint8_t *buf, nonce_payload *pl);
// uint32_t notify_pl2char (notify_payload *pl, uint8_t *buf);
// uint32_t char2notify_pl (uint8_t *buf, notify_payload *pl);
// uint32_t del_pl2char (delete_payload *pl, uint8_t *buf);
// uint32_t char2del_pl (uint8_t *buf, delete_payload *pl);
// uint32_t vid_pl2char (vendor_ID_payload *pl, uint8_t *buf);
// uint32_t char2vid_pl (uint8_t *buf, vendor_ID_payload *pl);
uint32_t ts2char (traffic_selector *ts, uint8_t *buf);
uint32_t char2ts (uint8_t *buf, traffic_selector *ts);
uint32_t ts_pl2char (traffic_selector_payload *pl, uint8_t *buf);
uint32_t char2ts_pl (uint8_t *buf, traffic_selector_payload *pl);
// uint32_t cfg_attr2char (configuration_attribute *ca, uint8_t *buf);
// uint32_t char2cfg_attr (uint8_t *buf, configuration_attribute *ca);
// uint32_t cfg_pl2char (configuration_payload *pl, uint8_t *buf);
// uint32_t char2cfg_pl (uint8_t *buf, configuration_payload *pl);
// uint32_t eap_pl2char (eap_payload *pl, uint8_t *buf);
// uint32_t char2eap_pl (uint8_t *buf, eap_payload *pl);
uint32_t enc_pl2char (encrypted_payload *pl, uint8_t *buf,
                 uint32_t block_len,
                 uint32_t integ_key_len);
uint32_t char2enc_pl (uint8_t *buf, encrypted_payload *pl,
                 uint32_t block_len,
                 uint32_t integ_key_len);

int get_block_len (uint16_t encr, uint16_t encr_key_len);
int get_id_len (uint32_t id_type);
int get_addr_len (uint8_t ts_type);
int get_key_len (transform *trans);

void init (void);
void reset (void);
void mem_clr (void);

int ike_init (void);
int ike_init_resp (void);

int ike_auth (void);
int ike_auth_resp (void);

int receive (void);
int parse_buff (void);
int check_icv (void);
int parse_SK (void);
void compute_keys ();

void encr_func (uint8_t *output,
                uint8_t *input,
                uint32_t length,
                uint8_t *key,
                uint8_t *iv);
void decr_func (uint8_t *output,
                uint8_t *input,
                uint32_t length,
                uint8_t *key,
                uint8_t *iv);
void prf_func (uint8_t *key, uint32_t keylen,
               uint8_t *data, uint32_t datalen,
               uint8_t *output);
void integ_func (uint8_t *key, uint32_t keylen,
                 uint8_t *data, uint32_t datalen,
                 uint8_t *output);

void dbg_print_buf (uint8_t *buf, uint32_t len);
void print_packet (void);
void dbg_print (void);