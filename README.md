In the blog post [Windows Filtering Platform: Persistent state under the hood](https://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html),
the quarkslab folks describe how to decode the Base Filtering Engine (BFE) persistent state,
i.e. the boot-time filters stored in the registry hive *HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\BootTime*
and the persistent callouts / filters / providers / sub-layers stored in the registry hive *HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent*.

At the end of the blog post, they provide samples of decoded objects, but they did not release any tool to do the decoding process.

The following script, **decode_bfe_filters.py**, decode the BFE boot-time filters and persistent filters located respectively in the registry keys 
*HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\BootTime\Filter* and *HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter*,
and generate an HTML report.<br/>
The script can be extended to decode the BFE persistent callouts, providers and sub-layers.

This script is useful for studying WFP callout drivers, e.g. firewall, IDS, IPS, etc.

The file **bfe_filters.html** is an example report generated for a clean install of Windows 10 Education version 1511 x86.

-----------------------------------

The following method was used to develop the script.

The persistent filters stored in the *HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter* registry key 
are decoded in the FWPM_FILTER_MARSHAL_Decode function of BFE.DLL by the API NdrMesTypeDecode2 :

	NdrMesTypeDecode2 (
		handle_t Handle, 
		const MIDL_TYPE_PICKLING_INFO *pPicklingInfo,
		const MIDL_STUB_DESC *pStubDesc,
		PFORMAT_STRING pFormatString,
		void *pObject
	)
	
pFormatString is the type format string table<br/>
pStubDesc.pFormatTypes is the type format description describing the structure to decode

First, compute the offset of the type format description (.text:10001D54) in the type format string table (.text:10001BCA): 10001D54 - 10001BCA = 18A (394)

Then, decompile the type format string table using a homemade NDR decompiler and look at offset 394 to get the definition of the decoded structure :

	[394] FC_UP
		pointer_attributes 0
		pointer_type FC_UP
		offset_to_complex_description 542 -> 938 (FC_BOGUS_STRUCT)
		
	[938] FC_BOGUS_STRUCT
	[946] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -770 -> 178 (FC_STRUCT)
	[950] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -762 -> 190 (FC_PSTRUCT)
	[954] FC_LONG
	[955] FC_POINTER
	[956] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -548 -> 410 (FC_PSTRUCT)
	[960] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -784 -> 178 (FC_STRUCT)
	[964] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -788 -> 178 (FC_STRUCT)
	[968] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -366 -> 604 (FC_BOGUS_STRUCT)
	[972] FC_LONG
	[973] FC_POINTER
	[974] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -330 -> 646 (FC_BOGUS_STRUCT)
	[978] FC_STRUCTPAD4
	[979] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -321 -> 660 (FC_NON_ENCAPSULATED_UNION)
	[983] FC_POINTER
	[984] FC_STRUCTPAD4
	[985] FC_HYPER
	[986] FC_EMBEDDED_COMPLEX
	FC_EMBEDDED_COMPLEX
		memory_pad 0
		offset_to_description -384 -> 604 (FC_BOGUS_STRUCT)
	FC_BOGUS_STRUCT
		alignment 7
		memory_size 152
		offset_to_conformant_array_description 0 -> 0
		offset_to_pointer_layout 48
		member_layout
			FC_EMBEDDED_COMPLEX
			FC_EMBEDDED_COMPLEX
			FC_LONG
			FC_POINTER
			FC_EMBEDDED_COMPLEX
			FC_EMBEDDED_COMPLEX
			FC_EMBEDDED_COMPLEX
			FC_EMBEDDED_COMPLEX
			FC_LONG
			FC_POINTER
			FC_EMBEDDED_COMPLEX
			FC_STRUCTPAD4
			FC_EMBEDDED_COMPLEX
			FC_POINTER
			FC_STRUCTPAD4
			FC_HYPER
			FC_EMBEDDED_COMPLEX
		pointer_layout
				pointer_attributes 0
				pointer_type FC_UP
				offset_to_complex_description -816 -> 178 (FC_STRUCT)
				pointer_attributes 32
				pointer_type FC_UP
				offset_to_complex_description -82 -> 916 (FC_BOGUS_ARRAY)
				pointer_attributes 0
				pointer_type FC_UP
				offset_to_complex_description -824 -> 178 (FC_STRUCT)
				
The corresponding structure definition is the following :			
				
	typedef struct struct_24 {
		struct struct_5 elem_1;
		struct struct_6 elem_2;
		long elem_3;
		struct struct_5 * elem_4;
		struct struct_11 elem_5;
		struct struct_5 elem_6;
		struct struct_5 elem_7;
		struct struct_14 elem_8;
		long elem_9;
		[size_is(elem_9)] struct struct_23 * elem_10;
		struct struct_16 elem_11;
		[switch_is(elem_3 & 0x4)] union union_17 elem_12;
		struct struct_5 * elem_13;
		hyper elem_14;
		struct struct_14 elem_15;
	} struct_24;
	
Finally, search for a structure matching the struct_24 structure in the WDK header files; the FWPM_FILTER0 structure is a match (fwpmtypes.h / fwpmtypes.idl) :

	typedef struct FWPM_FILTER0_
    {
		GUID filterKey;
		FWPM_DISPLAY_DATA0 displayData;
		UINT32 flags;
		[unique] GUID* providerKey;
		FWP_BYTE_BLOB providerData;
		GUID layerKey;
		GUID subLayerKey;
		FWP_VALUE0 weight;
		UINT32 numFilterConditions;
		[size_is(numFilterConditions), unique] FWPM_FILTER_CONDITION0* filterCondition;
		FWPM_ACTION0 action;
		[switch_is(flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT)]
		union
		{
			[case(0)]
				UINT64 rawContext;
			[case(FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT)]
				GUID providerContextKey;
		};
		[unique] GUID* reserved;
		UINT64 filterId;
		FWP_VALUE0 effectiveWeight;
    } FWPM_FILTER0;
	
Now it is just a matter of decoding the registry binary blobs.
	
The boot-time filters stored in the *HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\BootTime\Filter* registry key 
are decoded in the PWFP_BOOTTIME_FILTER_Decode function of netio.sys by the API NdrMesTypeDecode2.<br/>
The same method was used to get the definition of the decoded structure (FWPS_FILTER2 / fwpstypes.h / fwpstypes.idl).
