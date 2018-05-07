/* Maior&minor versions of IKE */
#define VERSIONS          32

/* Values ICV */
#define VALID             1
#define INVALID           0

/* FLAGS */
#define XXI               8
#define RXX               32

/* Exchange types */
#define IKE_SA_INIT       34
#define IKE_AUTH          35
#define CREATE_CHILD_SA   36
#define INFORMATIONAL     37

/* Next payload types */
#define NO_NEXT_PL        0
#define PL_SA             33
#define PL_KE             34
#define PL_IDi            35
#define PL_IDr            36
#define PL_CERT           37
#define PL_CERTREQ        38
#define PL_AUTH           39
#define PL_NONCE          40
#define PL_NOTIFY         41
#define PL_DELETE         42
#define PL_VID            43
#define PL_TSi            44
#define PL_TSr            45
#define PL_SK             46
#define PL_CP             47
#define PL_EAP            48

/* Protocol IDs */
#define IKE               1
#define AH                2
#define ESP               3

/* Transform types */
#define ENCR              1
#define PRF               2
#define INTEG             3
#define DH_GR             4
#define ESN               5

/* Transform IDs for ENCR */
#define ENCR_DES_IV64     1           /*(UNSPECIFIED)*/
#define ENCR_DES          2           /*(RFC2405), [DES]*/
#define ENCR_3DES         3           /*(RFC2451)*/
#define ENCR_RC5          4           /*(RFC2451)*/
#define ENCR_IDEA         5           /*(RFC2451), [IDEA]*/
#define ENCR_CAST         6           /*(RFC2451)*/
#define ENCR_BLOWFISH     7           /*(RFC2451)*/
#define ENCR_3IDEA        8           /*(UNSPECIFIED)*/
#define ENCR_DES_IV32     9           /*(UNSPECIFIED)*/
#define ENCR_NULL         11          /*(RFC2410)*/
#define ENCR_AES_CBC      12          /*(RFC3602)*/
#define ENCR_AES_CTR      13          /*(RFC3686)*/

/* Transform types for PRF */
#define PRF_HMAC_MD5      1           /*(RFC2104), [MD5]*/
#define PRF_HMAC_SHA1     2           /*(RFC2104), [SHA]*/
#define PRF_HMAC_TIGER    3           /*(UNSPECIFIED)*/

/* Transform types for INTEG */
#define AUTH_NONE         0
#define AUTH_HMAC_MD5_96  1           /*(RFC2403)*/
#define AUTH_HMAC_SHA1_96 2           /*(RFC2404)*/
#define AUTH_DES_MAC      3           /*(UNSPECIFIED)*/
#define AUTH_KPDK_MD5     4           /*(UNSPECIFIED)*/
#define AUTH_AES_XCBC_96  5           /*(RFC3566)*/

/* Transform types for DH_GR */
#define DH_GR_NONE        0
#define MODP_768          1
#define MODP_1024         2
#define MODP_1536         5
#define MODP_2048         14
#define MODP_3072         15
#define MODP_4096         16
#define MODP_6144         17
#define MODP_8192         18

/* Attribute formats */
#define AF_TLV            0
#define AF_TV             128

/* Attribute types */
#define AT_KEY_LEN        14

/* ID types (Identification PL) */
#define ID_IPV4_ADDR      1
#define ID_FQDN           2
#define ID_RFC822_ADDR    3
#define ID_IPV6_ADDR      4
#define ID_DER_ASN1_DN    9
#define ID_DER_ASN1_GN    10
#define ID_KEY_ID         11

/* Certificate encoding */
#define CE_PKCS7_WR_CERT  1
#define CE_PGP_CERT       2
#define CE_DNS_SIGN_KEY   3
#define CE_X509_SERT_SIGN 4
#define CE_KERB_TOKEN     6
#define CE_CRL            7
#define CE_ARL            8
#define CE_SPKI           9
#define CE_X509_ATTRIBUTE 10
#define CE_RAW_RSA_KEY    11
#define CE_H_URL_SER_X509 12
#define CE_H_URL_BUN_X509 13

/* Auth methods */
#define RSA_DS            1
#define S_KEY_M_I_CODE    2
#define DSS_DS            3

/* Error of NOTIFY */
#define U_C_P             1
#define INVALID_IKE_SPI   4
#define INVALID_M_V       5
#define INVALID_SYNTAX    7
#define INVALID_M_ID      9
#define INVALID_SPI       11
#define NO_PROP_CHOSEN    14
#define INVALID_KE_PL     17
#define AUTH_FAIL         24
#define SINGLE_P_REQ      34
#define NO_ADD_SAS        35
#define INT_ADD_FAIL      36
#define FAIL_CP_REQ       37
#define TS_UNACCEPTABLE   38
#define INVALID_SELECT    39
#define TEMP_FAIL         43
#define CHILD_SA_NOT_F    44
#define INITIAL_CONTACT   16384
#define SET_WIN_SIZE      16385
#define ADD_TS_POSS       16386
#define IPCOMP_SUPP       16387
#define NAT_DET_SOURCE_IP 16388
#define NAT_DET_DES_IP    16389
#define COOKIE            16390
#define USE_TRANS_MODE    16391
#define HTTP_CERT_L_S     16392
#define REKEY_SA          16393
#define ESP_TFC_P_NOT_SUP 16394
#define NON_FIRST_FRAG_A  16395

/* Traffic Selector Types */
#define TS_IPV4_ADDR_RAN  7
#define TS_IPV6_ADDR_RAN  8  

/* IP protocol IDs (TSs) */
#define ALL_PROT          0
// #define UDP               0
// #define TCP               0
// #define ICMP              0

/* Configuration Attributes */
#define CFG_REQUEST       1
#define CFG_REPLY         2
#define CFG_SET           3
#define CFG_ACK           4

/* Configuration Attribute Type */
#define INT_IP4_ADDRESS   1
#define INT_IP4_NETMASK   2
#define INT_IP4_DNS       3
#define INT_IP4_NBNS      4
#define INT_IP4_DHCP      6
#define APPLIC_VERSION    7
#define INT_IP6_ADDRESS   8
#define INT_IP6_DNS       10
#define INT_IP6_DHCP      12
#define INT_IP4_SUBNET    13
#define SUPP_ATTRIBUTES   14
#define INT_IP6_SUBNET    15

/* EAP Code */
#define REQUEST           1
#define RESPONSE          2
#define SUCCESS           3
#define FAILURE           4