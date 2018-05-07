/* transforms functions */

#define CPY(buf,offset,field) \
    reverse (buf+offset, sizeof (field)); \
    memcpy (&field, buf+offset, sizeof (field)); \
    reverse (buf+offset, sizeof (field)); \
    offset += sizeof (field);

#define MEMCHECK(ptr) \
    if (ptr == NULL) { \
        fprintf(stderr, "%s\n", "Memory allocating error"); \
        exit(-1); \
    }


uint32_t reverse (uint8_t *data, uint32_t l)
{
    uint8_t t;
    l--;
    for (uint32_t i=0; i <= l/2; i++)
    {
        t = data[i];
        data[i] = data[l - i];
        data[l - i] = t;
    }
    return 0;
}

uint32_t ike_hdr2char (ike_header *hdr, uint8_t *buf)
{
    uint32_t length = hdr->length;
    reverse ((uint8_t*)&hdr->init_SPI, sizeof (hdr->init_SPI));
    reverse ((uint8_t*)&hdr->resp_SPI, sizeof (hdr->resp_SPI));
    reverse ((uint8_t*)&hdr->message_ID, sizeof (hdr->message_ID));
    reverse ((uint8_t*)&hdr->length, sizeof (hdr->length));
    memcpy (buf, hdr, length);
    reverse ((uint8_t*)&hdr->init_SPI, sizeof (hdr->init_SPI));
    reverse ((uint8_t*)&hdr->resp_SPI, sizeof (hdr->resp_SPI));
    reverse ((uint8_t*)&hdr->message_ID, sizeof (hdr->message_ID));
    reverse ((uint8_t*)&hdr->length, sizeof (hdr->length));
    return sizeof (*hdr);
}

uint32_t char2ike_hdr (uint8_t *buf, ike_header *hdr)
{
    uint32_t offset = 0;
    CPY (buf, offset, hdr->init_SPI);
    CPY (buf, offset, hdr->resp_SPI);
    CPY (buf, offset, hdr->next_payload);
    CPY (buf, offset, hdr->versions);
    CPY (buf, offset, hdr->exchange_type);
    CPY (buf, offset, hdr->flags);
    CPY (buf, offset, hdr->message_ID);
    CPY (buf, offset, hdr->length);
    return offset;
}

uint32_t gen_pl_hdr2char (generic_payload_header *hdr, uint8_t *buf)
{
    uint32_t length = hdr->payload_length;
    reverse ((uint8_t*)&hdr->payload_length, sizeof (hdr->payload_length));
    memcpy (buf, hdr, length);
    reverse ((uint8_t*)&hdr->payload_length, sizeof (hdr->payload_length));
    return sizeof (*hdr);
}

uint32_t char2gen_pl_hdr (uint8_t *buf, generic_payload_header *hdr)
{
    uint32_t offset = 0;
    CPY (buf, offset, hdr->next_payload);
    CPY (buf, offset, hdr->critical);
    CPY (buf, offset, hdr->payload_length);
    return offset;
}

uint32_t transform2char (transform *trans, uint8_t *buf)
{
    uint32_t length = trans->transform_length;
    reverse ((uint8_t*) &trans->transform_length, sizeof (trans->transform_length));
    reverse ((uint8_t*) &trans->transform_ID, sizeof (trans->transform_ID));
    if (length == 8)
        memcpy (buf, trans, length);
    else
    {
        if (trans->attribute_format >> 7)
        {
            memcpy (buf, trans, 10);
            memcpy (buf+10, trans->attribute_value, 2);
        }
        else
        {   
            memcpy (buf, trans, 10);
            memcpy (buf+10, trans->attribute_value,
                2+((trans->attribute_value[0] << 8)+trans->attribute_value[1]));
        }
    }
    reverse ((uint8_t*) &trans->transform_length, sizeof (trans->transform_length));
    reverse ((uint8_t*) &trans->transform_ID, sizeof (trans->transform_ID));
    return length;
}

uint32_t char2transform (uint8_t *buf, transform *trans)
{
    uint32_t offset = 0;
    CPY (buf, offset, trans->more);
    CPY (buf, offset, trans->reserved1);
    CPY (buf, offset, trans->transform_length);
    CPY (buf, offset, trans->transform_type);
    CPY (buf, offset, trans->reserved2);
    CPY (buf, offset, trans->transform_ID);
    if (trans->transform_length > 8)
    {
        memcpy (&trans->attribute_format, buf+offset, sizeof (trans->attribute_format));
        offset += sizeof (trans->attribute_format);
        memcpy (&trans->attribute_type, buf+offset, sizeof (trans->attribute_type));
        offset += sizeof (trans->attribute_type);
        trans->attribute_value = calloc (1, 2);
        MEMCHECK (trans->attribute_value);
        memcpy (trans->attribute_value, buf+offset, 2);
        offset += 2;
        if (!(trans->attribute_format >> 7))
        {
            trans->attribute_value = realloc (trans->attribute_value,
                2+(trans->attribute_value[0] << 8) + trans->attribute_value[1]);
            MEMCHECK (trans->attribute_value);
            memcpy (trans->attribute_value+2, buf+offset,
                (trans->attribute_value[0] << 8) + trans->attribute_value[1]);
            offset += (trans->attribute_value[0] << 8)+trans->attribute_value[1];
        }
    }
    return offset;
}

uint32_t proposal2char (proposal *prop, uint8_t *buf)
{
    uint32_t offset = 0;
    uint32_t length = prop->proposal_length;
    reverse ((uint8_t*)&prop->proposal_length, sizeof (prop->proposal_length));
    if (prop->SPI_size > 0) reverse ((uint8_t*)prop->SPI, prop->SPI_size);
    memcpy (buf, prop, 8);
    offset += 8;
    memcpy (buf+8, prop->SPI, prop->SPI_size);
    offset += prop->SPI_size;
    for (uint32_t i = 0; i < prop->num_transforms; i++)
        offset += transform2char ((prop->transforms)+i, buf+offset);
    reverse ((uint8_t*)&prop->proposal_length, sizeof (prop->proposal_length));
    if (prop->SPI_size > 0) reverse ((uint8_t*)prop->SPI, prop->SPI_size);
    return length;
}

uint32_t char2proposal (uint8_t *buf, proposal *prop)
{
    uint32_t offset = 0;
    CPY (buf, offset, prop->more);
    CPY (buf, offset, prop->reserved);
    CPY (buf, offset, prop->proposal_length);
    CPY (buf, offset, prop->proposal_num);
    CPY (buf, offset, prop->protocol_ID);
    CPY (buf, offset, prop->SPI_size);
    CPY (buf, offset, prop->num_transforms);
    if (prop->SPI_size > 0)
    {
        reverse (buf+offset, prop->SPI_size);
        prop->SPI = calloc (prop->SPI_size, 1);
        memcpy (prop->SPI, buf+offset, prop->SPI_size);
        reverse (buf+offset, prop->SPI_size);
        offset += prop->SPI_size;
    }
    prop->transforms = calloc (prop->num_transforms, sizeof (transform));
    MEMCHECK (prop->transforms);
    for (uint32_t i = 0; i < prop->num_transforms; i++)
    {
        offset += char2transform (buf+offset, prop->transforms+i);
        if ((prop->transforms+i)->more == 0)
            break;
    }
    return offset;
}

uint32_t sa_pl2char (SA_payload *pl, uint8_t *buf)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint32_t length = pl->header.payload_length;
    uint32_t prop_num = 1;
    if (sizeof (pl->header) < length)
        do
        {
            offset += proposal2char (pl->proposals + prop_num-1, buf+offset);
            prop_num++;
        } while (pl->proposals[prop_num-2].more == 2);
    return length;
}

uint32_t char2sa_pl (uint8_t *buf, SA_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    pl->proposals = calloc (pl->header.payload_length - offset, 1);
    MEMCHECK (pl->proposals);
    uint32_t i = 0;
    do
    {
        offset += char2proposal (buf+offset, pl->proposals+i);
        i++;
    } while ((pl->proposals+i-1)->more != 0);
    return offset;
}

uint32_t ke_pl2char (key_exchange_payload *pl, uint8_t *buf)
{
    uint32_t length = pl->header.payload_length;
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint16_t tmp_l = sizeof (pl->dh_group_num) + sizeof (pl->reserved);
    reverse ((uint8_t*)&pl->dh_group_num, sizeof (pl->dh_group_num));
    memcpy (buf+offset, &pl->dh_group_num, tmp_l);
    offset += tmp_l;
    tmp_l = length - tmp_l - sizeof (pl->header);
    memcpy (buf+offset, pl->key_exchange_data, tmp_l);
    offset += tmp_l;
    reverse ((uint8_t*)&pl->dh_group_num, sizeof (pl->dh_group_num));
    return length;
}

uint32_t char2ke_pl (uint8_t *buf, key_exchange_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);   
    uint32_t length = pl->header.payload_length;
    CPY (buf, offset, pl->dh_group_num);
    CPY (buf, offset, pl->reserved);
    pl->key_exchange_data = calloc (length - offset, 1);
    MEMCHECK (pl->key_exchange_data);
    memcpy (pl->key_exchange_data, buf+offset, length - offset);
    return length;
}

uint32_t nonce_pl2char (nonce_payload *pl, uint8_t *buf)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);   
    uint32_t length = pl->header.payload_length;
    memcpy (buf+offset, pl->nonce_data, length - offset);
    return length;
}

uint32_t char2nonce_pl (uint8_t *buf, nonce_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    uint32_t length = pl->header.payload_length;
    pl->nonce_data = calloc (length - offset, 1);
    MEMCHECK (pl->nonce_data);
    memcpy (pl->nonce_data, buf+offset, length - offset);
    return length;
}

uint32_t auth_pl2char (authentication_payload *pl, uint8_t *buf)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint32_t length = pl->header.payload_length;
    memcpy (buf+offset, &pl->auth_method, 4);
    offset += 4;
    memcpy (buf+offset, pl->authentication_data, length - offset);
    return length;
}

uint32_t char2auth_pl (uint8_t *buf, authentication_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    uint32_t length = pl->header.payload_length;
    memcpy (&pl->auth_method, buf+offset, 4);
    offset += 4;
    pl->authentication_data = calloc (length - offset, 1);
    MEMCHECK (pl->authentication_data);
    memcpy (pl->authentication_data, buf+offset, length - offset);
    return length;
}

uint32_t id_pl2char (identification_payload *pl, uint8_t *buf)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint32_t length = pl->header.payload_length;
    memcpy (buf+offset, &pl->ID_type, 4);
    offset += 4;
    memcpy (buf+offset, pl->identification_data, length - offset);
    return length;
}

uint32_t char2id_pl (uint8_t *buf, identification_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    uint32_t length = pl->header.payload_length;
    memcpy (&pl->ID_type, buf+offset, 4);
    offset += 4;
    pl->identification_data = calloc (length - offset, 1);
    MEMCHECK (pl->identification_data);
    memcpy (pl->identification_data, buf+offset, length - offset);
    return length;
}

uint32_t ts2char (traffic_selector *ts, uint8_t *buf)
{
    uint16_t length = ts->selector_length;
    uint32_t offset = 0;
    reverse ((uint8_t*)&ts->selector_length, sizeof (ts->selector_length));
    reverse ((uint8_t*)&ts->start_port, sizeof (ts->start_port));
    reverse ((uint8_t*)&ts->end_port, sizeof (ts->end_port));
    uint16_t tmp_l = sizeof (ts->TS_type) + sizeof (ts->IP_protocol_ID) +
        sizeof (ts->selector_length) + sizeof (ts->start_port) + sizeof (ts->end_port);
    memcpy (buf+offset, ts, tmp_l);
    offset += tmp_l;
    tmp_l = (length - tmp_l)/2;
    memcpy (buf+offset, ts->starting_address, tmp_l);
    offset += tmp_l;
    memcpy (buf+offset, ts->ending_address, tmp_l);
    reverse ((uint8_t*)&ts->selector_length, sizeof (ts->selector_length));
    reverse ((uint8_t*)&ts->start_port, sizeof (ts->start_port));
    reverse ((uint8_t*)&ts->end_port, sizeof (ts->end_port));
    return length;
}

uint32_t char2ts (uint8_t *buf, traffic_selector *ts)
{
    uint32_t offset = 0;
    CPY (buf, offset, ts->TS_type);
    CPY (buf, offset, ts->IP_protocol_ID);
    CPY (buf, offset, ts->selector_length);
    CPY (buf, offset, ts->start_port);
    CPY (buf, offset, ts->end_port);
    uint16_t tmp_l = (ts->selector_length - offset)/2;
    ts->starting_address = calloc (tmp_l, 1);
    memcpy (ts->starting_address, buf+offset, tmp_l);
    offset += tmp_l;
    ts->ending_address = calloc (tmp_l, 1);
    memcpy (ts->ending_address, buf+offset, tmp_l);
    return ts->selector_length;
}

uint32_t ts_pl2char (traffic_selector_payload *pl, uint8_t *buf)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint32_t length = pl->header.payload_length;
    memcpy (buf+offset, &pl->number_of_TSs, sizeof (pl->number_of_TSs) + 3);
    offset += sizeof (pl->number_of_TSs) + 3;
    for (uint32_t i = 0; i < pl->number_of_TSs; i++) 
        offset += ts2char (pl->traffic_selectors+i, buf+offset);
    return length;
}

uint32_t char2ts_pl (uint8_t *buf, traffic_selector_payload *pl)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    uint32_t length = pl->header.payload_length;
    memcpy (&pl->number_of_TSs, buf+offset, sizeof (pl->number_of_TSs) + 3);
    offset += sizeof (pl->number_of_TSs) + 3;
    pl->traffic_selectors = calloc (pl->number_of_TSs, sizeof (traffic_selector));
    for (uint32_t i = 0; i < pl->number_of_TSs; i++) 
        offset += char2ts (buf+offset, pl->traffic_selectors+i);
    return length;
}

uint32_t enc_pl2char (encrypted_payload *pl, uint8_t *buf,
                 uint32_t iv_len,
                 uint32_t integ_key_len)
{
    uint32_t offset = gen_pl_hdr2char (&pl->header, buf);
    uint32_t length = pl->header.payload_length;
    memcpy (buf + offset, pl->iv, iv_len);
    offset += iv_len;
    memcpy (buf + offset, pl->enc_data, length - offset - integ_key_len);
    offset = length - integ_key_len;
    memcpy (buf + offset, pl->icv, integ_key_len);
    return length;
}

uint32_t char2enc_pl (uint8_t *buf, encrypted_payload *pl,
                 uint32_t iv_len,
                 uint32_t integ_key_len)
{
    uint32_t offset = char2gen_pl_hdr (buf, &pl->header);
    uint32_t length = pl->header.payload_length;
    pl->iv = calloc (1, iv_len);
    memcpy (pl->iv, buf + offset, iv_len);
    offset += iv_len;
    pl->enc_data = calloc (1, length - offset - integ_key_len);
    memcpy (pl->enc_data, buf + offset, length - offset - integ_key_len);
    offset = length - integ_key_len;
    pl->icv = calloc (1, integ_key_len);
    memcpy (pl->icv, buf + offset, integ_key_len);
    return length;
}