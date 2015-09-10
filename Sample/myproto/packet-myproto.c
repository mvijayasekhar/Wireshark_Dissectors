/*!< Adding myproto dissector to Wireshark */
/* packet-myproto.c
 * Copyright 2015
 *  
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/**
 *
 *       @file:       packet-myproto.c
 *       @brief:      Adding sample Dissector to Wireshark
 *       @version:    1.0
 *       @pre:        wireshark version 1.10 and above  
 *       @bug:        No Known bugs
 */

#include "config.h"
#include "moduleinfo.h"
#include <epan/packet.h>

#define MYPROTO_PORT  8088	/*for udp port */

/** function declaration */
static void dissect_myproto(tvbuff_t * tvb, packet_info * pinfo, 
		proto_tree * tree);
guint8 dissect_inner_pdu(proto_tree *, tvbuff_t *, guint, guint8, packet_info *, 
		proto_item *);

static int proto_myproto = -1;

/** sub trees */
static gint ett_myproto = -1;
static gint ett_myproto_TYPE1 = -1;
static gint ett_myproto_TYPE2 = -1;
static header_field_info *hf_myproto = NULL;

/** myproto variables */
static int hf_myproto_pdu_type = -1;
static int hf_myproto_pdu_len = -1;
static int hf_myproto_pdu_seqno = -1;
static int hf_myproto_padding[1] = { -1 };

/**   TYPE 1 PDU   */
static int hf_myproto_type1_pdu_len = -1;
static int hf_myproto_type1_pdu_val = -1;

/**   TYPE 2 PDU   */
static int hf_myproto_type2_pdu_len = -1;
static int hf_myproto_type2_pdu_val = -1;


/** value_string structure is a way to map values to strings. */
static const value_string pdutypes[] = {
	{1, "TYPE 1 PDU"},
	{2, "TYPE 2 PDU"},
	{0, NULL}
};


/**
 * @fn     proto_register_myproto 
 * @brief  register myproto with wireshark
 * @return void
 */
void proto_register_myproto(void)
{
	/** Field Registration */
	static hf_register_info hf[] = {
		/** For myproto */
		{&hf_myproto_pdu_type,
			{"PDU Type", "myproto.pdu_type",
				FT_UINT8, BASE_DEC,
				VALS(pdutypes), 0x0,
				NULL, HFILL}
		},
		{&hf_myproto_pdu_len,
			{"Length", "myproto.len",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		{&hf_myproto_pdu_seqno,
			{"Sequence Number", "myproto.seqno",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		{&hf_myproto_padding[0],
			{"Padding", "myproto.padding",
				FT_UINT8, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		/** For TYPE 1 PDU */
		{&hf_myproto_type1_pdu_len,
			{"TYPE 1 PDU Length", "myproto.type1_pdu_len",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		{&hf_myproto_type1_pdu_val,
			{"TYPE 1 PDU Value", "myproto.type1_pdu_val",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		/** For TYPE 2 PDU */
		{&hf_myproto_type2_pdu_len,
			{"TYPE 2 PDU Length", "myproto.type2_pdu_len",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		},
		{&hf_myproto_type2_pdu_val,
			{"TYPE 2 PDU Value", "myproto.type2_pdu_val",
				FT_UINT16, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL}
		}
	};

	/** Setup protocol subtree array */
	static gint *ett[] = {
		&ett_myproto,	/*for myproto */
		&ett_myproto_TYPE1,	/*for TYPE 1 PDU */
		&ett_myproto_TYPE2	/*for TYPE 2 PDU */
	};

	/** registering the myproto protocol with 3 names */
	proto_myproto = proto_register_protocol("MYPROTO",	/**  name */
			"myproto",	/**  short name */
			"myproto"	/**  abbrev  */
			);

	hf_myproto = proto_registrar_get_nth(proto_myproto);

	/** Register header fields and sub5trees. */
	proto_register_field_array(proto_myproto, hf, array_length(hf));

	/**  To register subtree types, pass an array of pointers */
	proto_register_subtree_array(ett, array_length(ett));

}

/**
 *   @fn     proto_reg_handoff_myproto 
 *   @brief  link dissector with wireshark
 *   @return void
 *
 */
void proto_reg_handoff_myproto(void)
{
	/** the handle for the dynamic dissector */
	dissector_handle_t myproto_handle;

	myproto_handle =
		create_dissector_handle(dissect_myproto, proto_myproto);
	dissector_add_uint("udp.port", MYPROTO_PORT, myproto_handle);
}

/**
 *
 * 	@fn     dissect_myproto 
 * 	@brief  dissecting the packets in myproto
 * 	@return void
 *
 */
static void
dissect_myproto(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

	/*col_set_str() function is used to set the column string */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MYPROTO");

	/*To clear corresponding column info */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item *ti = NULL;
		proto_tree *myproto_tree = NULL;
		guint8 offset = 0;
		guint8 pdu_type = 0;

		/** Adding Items and Values to the Protocol Tree */
		ti = proto_tree_add_item(tree, proto_myproto, tvb, 0, -1,
				FALSE);
		myproto_tree = proto_item_add_subtree(ti, ett_myproto);

		/** adding each item to myproto */
		pdu_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(myproto_tree, hf_myproto_pdu_type, tvb,
				offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(myproto_tree, hf_myproto_padding[0], tvb,
				offset, 1, FALSE);
		offset += 1;
		
		proto_tree_add_item(myproto_tree, hf_myproto_pdu_len, tvb, offset,
				2, FALSE);
		offset += 2;

		proto_tree_add_item(myproto_tree, hf_myproto_pdu_seqno, tvb,
				offset, 2, FALSE);
		offset += 2;

		col_append_fstr(pinfo->cinfo, COL_INFO, "PDU Type(s):");
		offset = dissect_inner_pdu(myproto_tree, tvb, offset, pdu_type, pinfo, ti);

	}

}

/**
 *
 * 	@fn     dissect_inner_pdu
 * 	@brief  dissecting and adding each pdu to tree
 * 	@return offset
 *
 */
guint8 dissect_inner_pdu(proto_tree * myproto_tree, tvbuff_t * tvb, guint offset,
		guint8 pdu_type, packet_info * pinfo, proto_item * ti)
{
	proto_item *ti_TYPE1 = NULL;
	proto_item *ti_TYPE2 = NULL;
	proto_tree *myproto_tree_TYPE1 = NULL;
	proto_tree *myproto_tree_TYPE2 = NULL;

	switch (pdu_type) {

		case 1:
			/*for TYPE 1 PDU */
			ti_TYPE1 =
				proto_tree_add_text(myproto_tree, tvb, offset, 0,
						"TYPE 1 PDU");
			myproto_tree_TYPE1 =
				proto_item_add_subtree(ti_TYPE1, ett_myproto_TYPE1);

			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",                         
					val_to_str(pdu_type, pdutypes,                                  
						"Unknown (0x%02x)"));                                    

			proto_item_append_text(ti, " Type: %s",                                 
					val_to_str(pdu_type, pdutypes,                           
						"Unknown (0x%02x)")); 

			proto_tree_add_item(myproto_tree_TYPE1, hf_myproto_type1_pdu_len,
					tvb, offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(myproto_tree_TYPE1,
					hf_myproto_type1_pdu_val, tvb, offset, 2,
					FALSE);
			offset += 2;

			break;

		case 2:
			/*for TYPE 2 PDU */
			ti_TYPE2 =
				proto_tree_add_text(myproto_tree, tvb, offset, 0,
						"TYPE 2 PDU");
			myproto_tree_TYPE2 =
				proto_item_add_subtree(ti_TYPE2, ett_myproto_TYPE2);

			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",                         
					val_to_str(pdu_type, pdutypes,                                  
						"Unknown (0x%02x)"));                                    

			proto_item_append_text(ti, " Type: %s",                                 
					val_to_str(pdu_type, pdutypes,                           
						"Unknown (0x%02x)")); 
			proto_tree_add_item(myproto_tree_TYPE2, hf_myproto_type2_pdu_len,
					tvb, offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(myproto_tree_TYPE2,
					hf_myproto_type2_pdu_val, tvb, offset, 2,
					FALSE);
			offset += 2;

			break;

		default:
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", "Unknown (0x%02x)");
			proto_item_append_text(ti, ", Type: %s", "Unknown (0x%02x)");
			break;
	}

	return offset;
}

/* END of program  */
