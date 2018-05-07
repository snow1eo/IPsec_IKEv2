/* Memory cleaning functions */

#define FREE_IF_SET(ptr) if (ptr != NULL) free (ptr); ptr = NULL

void transform_clr (transform *trans);
void proposal_clr (proposal *prop);
void sa_pl_clr (SA_payload *pl);
void ke_pl_clr (key_exchange_payload *pl);
void id_pl_clr (identification_payload *pl);
void cert_pl_clr (certificate_payload *pl);
void cert_req_pl_clr (certificate_request_payload *pl);
void auth_pl_clr (authentication_payload *pl);
void nonce_pl_clr (nonce_payload *pl);
void notify_pl_clr (notify_payload *pl);
void del_pl_clr (delete_payload *pl);
void vid_pl_clr (vendor_ID_payload *pl);
void ts_clr (traffic_selector *ts);
void ts_pl_clr (traffic_selector_payload *pl);
void cfg_attr_clr (configuration_attribute *attr);
// void cfg_pl_clr (eap_payload *pl);
// void eap_pl_clr ( *pl);
void enc_pl_clr (encrypted_payload *pl);

/*=========================================*/

void transform_clr (transform *trans)
{
	free (trans->attribute_value);
}

void proposal_clr (proposal *prop)
{
	free (prop->SPI);
	for (int i = 0; i < prop->num_transforms; i++)
		transform_clr (&prop->transforms[i]);
}

void sa_pl_clr (SA_payload *pl)
{
	if (pl->header.payload_length > sizeof (pl->header))
		for (int i = 0; pl->proposals[i].more != 0; i++)
			proposal_clr (&pl->proposals[i]);
}

void ke_pl_clr (key_exchange_payload *pl)
{
	free (pl->key_exchange_data);
}

void id_pl_clr (identification_payload *pl)
{
	free (pl->identification_data);
}

void cert_pl_clr (certificate_payload *pl)
{
	free (pl->certificate_data);
}

void cert_req_pl_clr (certificate_request_payload *pl)
{
	free (pl->certificate_authority);
}

void auth_pl_clr (authentication_payload *pl)
{
	free (pl->authentication_data);
}

void nonce_pl_clr (nonce_payload *pl)
{
	// free (pl->nonce_data);
}

void notify_pl_clr (notify_payload *pl)
{
	free (pl->SPI);
	free (pl->notification_data);
}

void del_pl_clr (delete_payload *pl)
{
	free (pl->SPIes);
}

void vid_pl_clr (vendor_ID_payload *pl)
{
	free (pl->VID);
}

void ts_clr (traffic_selector *ts)
{
	free (ts->starting_address);
	free (ts->ending_address);
}

void ts_pl_clr (traffic_selector_payload *pl)
{
	for (int i = 0; i < pl->number_of_TSs; i++)
		ts_clr (&pl->traffic_selectors[i]);
}

void cfg_attr_clr (configuration_attribute *attr)
{
	free (attr->value);
}

// void cfg_pl_clr (eap_payload *pl)
// {

// }

// void eap_pl_clr ( *pl)
// {
// }

void enc_pl_clr (encrypted_payload *pl)
{
	// free (pl->iv);
	// free (pl->enc_data);
	// free (pl->icv);
}