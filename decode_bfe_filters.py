
import globals
from utils import *

import sys
from cStringIO import StringIO
import uuid
import operator
import os
# import pefile

#
#   HTML export
#

def export_bfe_filters_to_html():

    '''
    #
    #   BFE Filters to XXX binaries
    #

    filterIds = set([])

    for boottime_filter in globals.g_boottime_filters:
        filterIds.add(boottime_filter.filterGuid)

    for persistent_filter in globals.g_persistent_filters:
        filterIds.add(persistent_filter.filterGuid)

    filterId_to_binaries = {}

    rootdir = XXX

    for root, dirs, files in os.walk(rootdir):
        for filename in files:
            filepath = os.path.join(root, filename)

            try:
                pe = pefile.PE(filepath, fast_load=False)
            except Exception:
                continue

            f = open(filepath, 'rb')
            filecontent = f.read()
            f.close()

            for filterId in filterIds:
                filterId_bytes_le = uuid.UUID(filterId).bytes_le
                if filterId_bytes_le in filecontent:
                    if filterId not in filterId_to_binaries:
                        filterId_to_binaries[filterId] = []
                    filterId_to_binaries[filterId].append(filename)
    '''

    #
    #
    #

    with open('bfe_filters.html', 'w') as f:

        f.write('<html>')
        f.write('<body>')

        f.write('<h1>BFE Filters</h1>')

        #
        #   Persistent Filters
        #

        f.write('<h2>Persistent Filters - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE\Parameters\Policy\Persistent\Filter</h2>')

        f.write('<font size="1" face="Courier New">')
        f.write('<table style="border-collapse: collapse;">')

        f.write('<tr>')

        f.write('<th style="border: 1px solid black;">N</th>')
        f.write('<th style="border: 1px solid black;">Id</th>')
        # f.write('<th style="border: 1px solid black;">GUID</th>')
        f.write('<th style="border: 1px solid black;">Name</th>')
        f.write('<th style="border: 1px solid black;">Layer</th>')
        f.write('<th style="border: 1px solid black;">Action</th>')
        f.write('<th style="border: 1px solid black;">Conditions</th>')
        # f.write('<th style="border: 1px solid black;">Binaries</th>')

        f.write('</tr>')

        persistent_filters = globals.g_persistent_filters
        persistent_filters.sort(key = operator.attrgetter('filterId'))

        for i in range(0, len(persistent_filters)):
            f.write('<tr>')

            f.write('<td style="border: 1px solid black;">%d</td>' % (i+1))
            f.write('<td style="border: 1px solid black;">%d</td>' % persistent_filters[i].filterId)
            # f.write('<td style="border: 1px solid black;">%s</td>' % persistent_filters[i].filterGuid)
            f.write('<td style="border: 1px solid black;">%s</td>' % persistent_filters[i].filterName)
            f.write('<td style="border: 1px solid black;">%s</td>' % persistent_filters[i].layerId[11:])        # FWPM_LAYER_*
            f.write('<td style="border: 1px solid black;">%s</td>' % persistent_filters[i].actionType[11:])     # FWP_ACTION_*

            f.write('<td style="border: 1px solid black;">')
            for fieldId, matchType, value in persistent_filters[i].conditions:
                if str(value).isdigit():
                    f.write('%s %s %s (%s)<br />' % (fieldId[15:], matchType[10:], value, hex(value)))          # FWPM_CONDITION_* / FWP_MATCH_*
                else:
                    f.write('%s %s %s<br />' % (fieldId[15:], matchType[10:], value))                           # FWPM_CONDITION_* / FWP_MATCH_*
            f.write('</td>')

            '''
            f.write('<td style="border: 1px solid black;">')
            if persistent_filters[i].filterGuid in filterId_to_binaries:
                for binary in filterId_to_binaries[persistent_filters[i].filterGuid]:
                    f.write('%s<br />' % binary)
            f.write('</td>')
            '''

            f.write('</tr>')

        f.write('</table>')
        f.write('</font>')

        #
        #   BootTime Filters
        #

        f.write('<h2>BootTime Filters - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE\Parameters\Policy\BootTime\Filter</h2>')

        f.write('<font size="1" face="Courier New">')
        f.write('<table style="border-collapse: collapse;">')

        f.write('<tr>')

        f.write('<th style="border: 1px solid black;">N</th>')
        f.write('<th style="border: 1px solid black;">Id</th>')
        # f.write('<th style="border: 1px solid black;">GUID</th>')
        # f.write('<th style="border: 1px solid black;">Name</th>')
        f.write('<th style="border: 1px solid black;">Layer</th>')
        f.write('<th style="border: 1px solid black;">Action</th>')
        f.write('<th style="border: 1px solid black;">Conditions</th>')
        # f.write('<th style="border: 1px solid black;">Binaries</th>')

        f.write('</tr>')

        boottime_filters = globals.g_boottime_filters
        boottime_filters.sort(key = operator.attrgetter('filterId'))

        for i in range(0, len(boottime_filters)):
            f.write('<tr>')

            f.write('<td style="border: 1px solid black;">%d</td>' % (i+1))
            f.write('<td style="border: 1px solid black;">%d</td>' % boottime_filters[i].filterId)
            # f.write('<td style="border: 1px solid black;">%s</td>' % boottime_filters[i].filterGuid)
            # f.write('<td style="border: 1px solid black;">%s</td>' % boottime_filters[i].filterName)
            f.write('<td style="border: 1px solid black;">%s</td>' % FWPS_layerId_to_str[boottime_filters[i].layerId][11:])     # FWPS_LAYER_*
            f.write('<td style="border: 1px solid black;">%s</td>' % boottime_filters[i].actionType[11:])                       # FWP_ACTION_*

            f.write('<td style="border: 1px solid black;">')
            for fieldId, matchType, value in boottime_filters[i].conditions:
                layerId = FWPS_layerId_to_str[boottime_filters[i].layerId][11:]
                fieldId = fieldId[11:]
                assert(fieldId.startswith(layerId+'_'))
                fieldId = fieldId[len(layerId)+1:]
                if str(value).isdigit():
                    f.write('%s %s %s (%s)<br />' % (fieldId, matchType[10:], value, hex(value)))                       # FWPS_FIELD_* / FWP_MATCH_*
                else:
                    f.write('%s %s %s<br />' % (fieldId, matchType[10:], value))                                        # FWPS_FIELD_* / FWP_MATCH_*
            f.write('</td>')

            '''
            f.write('<td style="border: 1px solid black;">')
            if boottime_filters[i].filterGuid in filterId_to_binaries:
                for binary in filterId_to_binaries[boottime_filters[i].filterGuid]:
                    f.write('%s<br />' % binary)
            f.write('</td>')
            '''

            f.write('</tr>')

        f.write('</table>')
        f.write('</font>')

        f.write('</body>')
        f.write('</html>')

#
#   class
#

class BootTimeFilter:
    def __init__(self):
        self.filterId = 0
        self.filterGuid = ''
        self.filterWeight = 0
        self.layerId = 0
        self.actionCalloutId = 0
        self.calloutGuid = ''
        self.actionType = ''
        self.conditions = []

    def pprint(self):
        print 'Filter'
        print '\t', 'Id:', hex(self.filterId)
        print '\t', 'GUID:', self.filterGuid
        print '\t', 'Weight:', hex(self.filterWeight)
        print '\t', 'Layer Id:', FWPS_layerId_to_str[self.layerId]
        print '\t', 'Callout Id:', hex(self.actionCalloutId)
        print '\t', 'Callout GUID:', self.calloutGuid
        print '\t', 'Action:', self.actionType
        print '\t', 'Conditions:'
        for fieldId, matchType, value in self.conditions:
            print '\t\t', fieldId
            print '\t\t', matchType
            if str(value).isdigit():
                print '\t\t', '%s (%s)' % (value, hex(value)) 
            else:
                print '\t\t', '%s' % value
            print

class PersistentFilter:
    def __init__(self):
        self.filterId = 0
        self.filterGuid = ''
        self.filterName = ''
        self.filterDescription = ''
        self.filterWeight = 0
        self.layerId = ''
        self.layerGuid = ''
        self.sublayerGuid = ''
        self.actioncalloutGuid = ''
        self.actionType = ''
        self.conditions = []

    def pprint(self):
        print 'Filter'
        print '\t', 'Id:', hex(self.filterId)
        print '\t', 'GUID:', self.filterGuid
        print '\t', 'Name: "%s"' % self.filterName
        print '\t', 'Description: "%s"' % self.filterDescription
        print '\t', 'Weight:', hex(self.filterWeight)
        print '\t', 'Layer Id:', self.layerId
        print '\t', 'Layer GUID:', self.layerGuid
        print '\t', 'SubLayer GUID:', self.sublayerGuid
        print '\t', 'Callout GUID:', self.actioncalloutGuid
        print '\t', 'Action:', self.actionType
        print '\t', 'Conditions:'
        for fieldId, matchType, value in self.conditions:
            print '\t\t', fieldId
            print '\t\t', matchType
            if str(value).isdigit():
                print '\t\t', '%s (%s)' % (value, hex(value)) 
            else:
                print '\t\t', '%s' % value
            print

#
#   BFE BootTime Filters
#

'''
    // Values that conditions can use when testing for matches. The
    // FWP_CONDITION_VALUE's data type must be compatible with the type of the
    // FWP_VALUE to which it's being compared. However, this doesn't mean they
    // necessarily need to be the same. For example, an FWP_V4_ADDR_MASK can be
    // compared to an FWP_UINT32 containing an IPv4 address.
    typedef struct FWP_CONDITION_VALUE0_
    {
       FWP_DATA_TYPE type;
       [switch_type(FWP_DATA_TYPE), switch_is(type)]
       union
       {
          [case(FWP_EMPTY)]
             ;
          [case(FWP_UINT8, FWP_BITMAP_INDEX_TYPE)]
             UINT8 uint8;
          [case(FWP_UINT16)]
             UINT16 uint16;
          [case(FWP_UINT32)]
             UINT32 uint32;
          [case(FWP_UINT64)]
             [unique] UINT64* uint64;
          [case(FWP_INT8)]
             INT8 int8;
          [case(FWP_INT16)]
             INT16 int16;
          [case(FWP_INT32)]
             INT32 int32;
          [case(FWP_INT64)]
             [unique] INT64* int64;
          [case(FWP_FLOAT)]
             float float32;
          [case(FWP_DOUBLE)]
             [unique] double* double64;
          [case(FWP_BYTE_ARRAY16_TYPE)]
             [unique] FWP_BYTE_ARRAY16* byteArray16;
          [case(FWP_BYTE_BLOB_TYPE)]
             [unique] FWP_BYTE_BLOB* byteBlob;
          [case(FWP_SID)]
             [unique] SID* sid;
          [case(FWP_SECURITY_DESCRIPTOR_TYPE)]
             [unique] FWP_BYTE_BLOB* sd;
          [case(FWP_TOKEN_INFORMATION_TYPE)]
             [unique] FWP_TOKEN_INFORMATION* tokenInformation;
          [case(FWP_TOKEN_ACCESS_INFORMATION_TYPE)]
             [unique] FWP_BYTE_BLOB* tokenAccessInformation;
          [case(FWP_UNICODE_STRING_TYPE)]
             [string] LPWSTR unicodeString;
          [case(FWP_BYTE_ARRAY6_TYPE)]
             [unique] FWP_BYTE_ARRAY6* byteArray6;
          [case(FWP_BITMAP_ARRAY64_TYPE)]
             [unique] FWP_BITMAP_ARRAY64* bitmapArray64;
          [case(FWP_V4_ADDR_MASK)]
             [unique] FWP_V4_ADDR_AND_MASK* v4AddrMask;
          [case(FWP_V6_ADDR_MASK)]
             [unique] FWP_V6_ADDR_AND_MASK* v6AddrMask;
          [case(FWP_RANGE_TYPE)]
             [unique] FWP_RANGE0* rangeValue;
       };
    } FWP_CONDITION_VALUE0;
'''
def decode_FWP_CONDITION_VALUE0(f):
    _type = signed_long_at(f)                                       # FWP_CONDITION_VALUE0.type

    union_discriminant = signed_long_at(f)
    assert(union_discriminant == _type)

    if _type == FWP_UINT8:
        value = unsigned_char_at(f)                                 # FWP_CONDITION_VALUE0.uint8

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_UINT8'
        print '\t\t', 'FWP_CONDITION_VALUE0.uint8:', hex(value)

        padding = f.read(3)                                         # padding
        print '\t\t', 'padding:', format_hex(padding)

    elif _type == FWP_UINT16:
        value = unsigned_short_at(f)                                # FWP_CONDITION_VALUE0.uint16

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_UINT16'
        print '\t\t', 'FWP_CONDITION_VALUE0.uint16:', hex(value)

        padding = f.read(2)                                         # padding
        print '\t\t', 'padding:', format_hex(padding)

    elif _type == FWP_UINT32:
        value = unsigned_long_at(f)                                 # FWP_CONDITION_VALUE0.uint32

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_UINT32'
        print '\t\t', 'FWP_CONDITION_VALUE0.uint32:', hex(value)

    elif _type == FWP_BYTE_BLOB_TYPE:
        value = unsigned_long_at(f)                                 # FWP_CONDITION_VALUE0.byteBlob / FWP_BYTE_BLOB *

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_BYTE_BLOB_TYPE'
        print '\t\t', 'FWP_CONDITION_VALUE0.byteBlob: /* FC_UP */ %s (FWP_BYTE_BLOB *)' % hex(value)

    elif _type == FWP_SID:
        value = unsigned_long_at(f)                                 # FWP_CONDITION_VALUE0.sid / SID *

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_SID'
        print '\t\t', 'FWP_CONDITION_VALUE0.sid: /* FC_UP */ %s (SID *)' % hex(value)

    elif _type == FWP_RANGE_TYPE:
        value = unsigned_long_at(f)                                 # FWP_CONDITION_VALUE0.rangeValue / FWP_RANGE0 *

        print '\t\t', 'FWP_CONDITION_VALUE0.type:', 'FWP_RANGE_TYPE'
        print '\t\t', 'FWP_CONDITION_VALUE0.rangeValue: /* FC_UP */ %s (FWP_RANGE0 *)' % hex(value)

    else:
        print '[+] decode_FWP_CONDITION_VALUE0(): unsupported FWP_DATA_TYPE', _type
        sys.exit(1)

    return (_type, value)

'''
    // Expresses a filter condition that must be true for the action to be invoked.
    typedef struct FWPS_FILTER_CONDITION0_
    {
       // LUID of the field to be tested.
       UINT16 fieldId;
       // Reserved for system type.
       UINT16 reserved;
       // Type of match to be performed.
       FWP_MATCH_TYPE matchType;
       // Value to match the field against.
       FWP_CONDITION_VALUE0 conditionValue;
    } FWPS_FILTER_CONDITION0;
'''
def decode_FWPS_FILTER_CONDITION0(f):    
    fieldId = unsigned_short_at(f)                                          # FWPS_FILTER_CONDITION0.fieldId
    assert(fieldId < len(FWPS_layerId_to_fieldIdsStr[globals.g_filter.layerId]))
    print '\t', 'FWPS_FILTER_CONDITION0.fieldId:', FWPS_layerId_to_fieldIdsStr[globals.g_filter.layerId][fieldId]

    reserved = unsigned_short_at(f)                                         # FWPS_FILTER_CONDITION0.reserved
    print '\t', 'FWPS_FILTER_CONDITION0.reserved:', hex(reserved)

    matchType = signed_long_at(f)                                           # FWPS_FILTER_CONDITION0.matchType
    assert(matchType < FWP_MATCH_TYPE_MAX)
    print '\t', 'FWPS_FILTER_CONDITION0.matchType:', matchType_to_str[matchType]

    print '\t', 'FWPS_FILTER_CONDITION0.conditionValue:'
    conditionValue_type, conditionValue = decode_FWP_CONDITION_VALUE0(f)    # FWPS_FILTER_CONDITION0.conditionValue / FWP_UINT8 / FWP_UINT16 / FWP_UINT32 / FWP_BYTE_BLOB_TYPE (FWP_BYTE_BLOB *) / FWP_SID (SID *) / FWP_RANGE_TYPE (FWP_RANGE0 *)

    assert(conditionValue_type == FWP_UINT8
           or conditionValue_type == FWP_UINT16
           or conditionValue_type == FWP_UINT32
           or conditionValue_type == FWP_SID)               # SID *
           # or conditionValue_type == FWP_BYTE_BLOB_TYPE     # FWP_BYTE_BLOB *
           # or conditionValue_type == FWP_RANGE_TYPE)        # FWP_RANGE0 *

    if (conditionValue_type == FWP_SID) and (conditionValue != 0):          # FWPS_FILTER_CONDITION0.conditionValue / SID *
        sid = f.read(16)
        sid = str(uuid.UUID(bytes_le=sid))
        print '\t', 'sid:', sid
        print

        conditionValue = sid

    globals.g_filter.conditions.append( (FWPS_layerId_to_fieldIdsStr[globals.g_filter.layerId][fieldId], matchType_to_str[matchType], conditionValue) )

    print

'''
    // Action invoked if all the filter conditions are true.
    typedef struct FWPS_ACTION0_
    {
       // Type of action.
       FWP_ACTION_TYPE type;
       // LUID of the callout if FWP_ACTION_FLAG_CALLOUT is set in the action type.
       // Otherwise, it's ignored.
       // This calloutId field can be used for bitmapIndex, in which case, type is set to FWP_ACTION_BITMAP_INDEX_SET
       UINT32 calloutId;
    } FWPS_ACTION0;
'''
def decode_FWPS_ACTION0(f):
    _type = unsigned_long_at(f)                                 # FWPS_ACTION0.type
    assert(_type in actionType_to_str)
    print '\t\t', 'FWPS_ACTION0.type:', actionType_to_str[_type]

    globals.g_filter.actionType = actionType_to_str[_type]

    calloutId = unsigned_long_at(f)                             # FWPS_ACTION0.calloutId
    print '\t\t', 'FWPS_ACTION0.calloutId:', hex(calloutId)

    globals.g_filter.actionCalloutId = calloutId

'''
    // Generic data value. This is primarily used to supply incoming values to the
    // filter engine.
    typedef struct FWP_VALUE0_
    {
       FWP_DATA_TYPE type;
       [switch_type(FWP_DATA_TYPE), switch_is(type)]
       union
       {
              [case(FWP_EMPTY)]
                     ;
              [case(FWP_UINT8, FWP_BITMAP_INDEX_TYPE)]
                     UINT8 uint8;
              [case(FWP_UINT16)]
                     UINT16 uint16;
              [case(FWP_UINT32)]
                     UINT32 uint32;
              [case(FWP_UINT64)]
                     [unique] UINT64* uint64;
              [case(FWP_INT8)]
                     INT8 int8;
              [case(FWP_INT16)]
                     INT16 int16;
              [case(FWP_INT32)]
                     INT32 int32;
              [case(FWP_INT64)]
                     [unique] INT64* int64;
              [case(FWP_FLOAT)]
                     float float32;
              [case(FWP_DOUBLE)]
                     [unique] double* double64;
              [case(FWP_BYTE_ARRAY16_TYPE)]
                     [unique] FWP_BYTE_ARRAY16* byteArray16;
              [case(FWP_BYTE_BLOB_TYPE)]
                     [unique] FWP_BYTE_BLOB* byteBlob;
              [case(FWP_SID)]
                     [unique] SID* sid;
              [case(FWP_SECURITY_DESCRIPTOR_TYPE)]
                     [unique] FWP_BYTE_BLOB* sd;
              [case(FWP_TOKEN_INFORMATION_TYPE)]
                     [unique] FWP_TOKEN_INFORMATION* tokenInformation;
              [case(FWP_TOKEN_ACCESS_INFORMATION_TYPE)]
                     [unique] FWP_BYTE_BLOB* tokenAccessInformation;
              [case(FWP_UNICODE_STRING_TYPE)]
                     [string] LPWSTR unicodeString;
              [case(FWP_BYTE_ARRAY6_TYPE)]
                     [unique] FWP_BYTE_ARRAY6* byteArray6;
              [case(FWP_BITMAP_ARRAY64_TYPE)]
                     [unique] FWP_BITMAP_ARRAY64* bitmapArray64;
       };
    } FWP_VALUE0;
'''
def decode_FWP_VALUE0(f):
    _type = signed_long_at(f)                                       # FWP_VALUE0.type

    union_discriminant = signed_long_at(f)
    assert(union_discriminant == _type)

    if _type == FWP_EMPTY:
        print '\t\t', 'FWP_VALUE0.type:', 'FWP_EMPTY'

        return (FWP_EMPTY, 0)

    elif _type == FWP_UINT8:
        uint8 = unsigned_char_at(f)                                 # FWP_VALUE0.uint8

        print '\t\t', 'FWP_VALUE0.type:', 'FWP_UINT8'
        print '\t\t', 'FWP_VALUE0.uint8:', hex(uint8)

        padding = f.read(3)                                         # padding
        print '\t\t', 'padding:', format_hex(padding)

        return (FWP_UINT8, uint8)

    elif _type == FWP_UINT64:
        uint64 = unsigned_long_at(f)                                # FWP_VALUE0.uint64 / UINT64 *

        print '\t\t', 'FWP_VALUE0.type:', 'FWP_UINT64'
        print '\t\t', 'FWP_VALUE0.uint64: /* FC_UP */ %s (UINT64 *)' % hex(uint64)

        return (FWP_UINT64, uint64)

    elif _type == FWP_BYTE_ARRAY16_TYPE:
        byteArray16 = unsigned_long_at(f)                           # FWP_VALUE0.byteArray16 / FWP_BYTE_ARRAY16 *

        print '\t\t', 'FWP_VALUE0.type:', 'FWP_BYTE_ARRAY16_TYPE'
        print '\t\t', 'FWP_VALUE0.byteArray16: /* FC_UP */ %s (FWP_BYTE_ARRAY16 *)' % hex(byteArray16)

        return (FWP_BYTE_ARRAY16_TYPE, byteArray16)

    else:
        print '[+] decode_FWP_VALUE0(): unsupported FWP_DATA_TYPE', _type
        sys.exit(1)

'''
    typedef struct struct_56 {
            hyper elem_1;
            struct struct_8 elem_2;
            short elem_3;
            short elem_4;
            long elem_5;
            [size_is(elem_5)] struct struct_14 * elem_6;
            struct struct_9 elem_7;
            hyper elem_8;
            struct struct_55 * elem_9;
    } struct_56;

    // Version-2 of system filter used for run-time classification.
    typedef struct FWPS_FILTER2_
    {
       // LUID uniquely identifying the filter in the filter engine.
       UINT64 filterId;

       // Weight of the filter -- higher filters are invoked first.
       FWP_VALUE0 weight;
       // Weight of the filter's sub-layer -- higher weights are invoked first.
       UINT16 subLayerWeight;
       UINT16 flags;
       // Array of filter conditions. All must be true for the action to be
       // performed. In other words, the conditions are AND'ed together. If no
       // conditions are specified, the action is always performed.
       UINT32 numFilterConditions;
       [size_is(numFilterConditions), unique]
              FWPS_FILTER_CONDITION0* filterCondition;
       // Action performed if the conditions are true.
       FWPS_ACTION0 action;
       // Opaque context that may be interpreted by callouts. The context of the
       // terminating filter is also returned from classify. In many cases, this
       // context will be the LUID of a provider context, but it need not be.
       UINT64 context;
       // If this is a callout filter and the callout has the
       // FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT flag set, this contains the
       // provider context from the corresponding FWPM_FILTER1 struct. Otherwise,
       // it is null.
       [unique] FWPM_PROVIDER_CONTEXT2* providerContext;
    } FWPS_FILTER2;
'''
def decode_FWPS_FILTER2(f):
    filterId = unsigned_long_long_at(f)                                 # FWPS_FILTER2.filterId
    print '\t', 'FWPS_FILTER2.filterId:', hex(filterId)

    globals.g_filter.filterId = filterId

    print '\t', 'FWPS_FILTER2.weight:'
    weight_type, weight = decode_FWP_VALUE0(f)                          # FWPS_FILTER2.weight / FWP_EMPTY / FWP_UINT8 / FWP_UINT64 (UINT64 *) / FWP_BYTE_ARRAY16_TYPE (FWP_BYTE_ARRAY16 *)

    globals.g_filter.filterWeight = weight

    subLayerWeight = unsigned_short_at(f)                               # FWPS_FILTER2.subLayerWeight
    print '\t', 'FWPS_FILTER2.subLayerWeight:', hex(subLayerWeight)

    flags = unsigned_short_at(f)                                        # FWPS_FILTER2.flags
    print '\t', 'FWPS_FILTER2.flags:', hex(flags)

    numFilterConditions = unsigned_long_at(f)                           # FWPS_FILTER2.numFilterConditions
    print '\t', 'FWPS_FILTER2.numFilterConditions:', hex(numFilterConditions)

    filterCondition = unsigned_long_at(f)                               # FWPS_FILTER2.filterCondition / FWPS_FILTER_CONDITION0 *
    print '\t', 'FWPS_FILTER2.filterCondition: /* FC_UP */ %s (FWPS_FILTER_CONDITION0 *)' % hex(filterCondition)

    print '\t', 'FWPS_FILTER2.action:'
    decode_FWPS_ACTION0(f)                                              # FWPS_FILTER2.action

    context = unsigned_long_long_at(f)                                  # FWPS_FILTER2.context
    print '\t', 'FWPS_FILTER2.context:', hex(context)

    providerContext = unsigned_long_at(f)                               # FWPS_FILTER2.providerContext / FWPM_PROVIDER_CONTEXT2 *
    print '\t', 'FWPS_FILTER2.providerContext: /* FC_UP */ %s (FWPM_PROVIDER_CONTEXT2 *)' % hex(providerContext)
    print

    #
    #   FC_UP
    #

    assert(weight_type == FWP_EMPTY or weight_type == FWP_UINT8 or weight_type == FWP_UINT64) # or weight_type == FWP_BYTE_ARRAY16_TYPE)
    if (weight_type == FWP_UINT64) and (weight != 0):
        padding = f.read(4)                                             # padding
        print '\t', 'padding:', format_hex(padding)
        print
        
        weight = unsigned_long_long_at(f)                               # FWPS_FILTER2.weight
        print '\t', 'FWPS_FILTER2.weight:', hex(weight)
        print

        globals.g_filter.filterWeight = weight

    if filterCondition != 0:
        sized_pointer_size = unsigned_long_at(f)
        assert(sized_pointer_size == numFilterConditions)

        for i in range(0, numFilterConditions):
            decode_FWPS_FILTER_CONDITION0(f)                            # FWPS_FILTER2.filterCondition

    assert(providerContext == 0)                                        # FWPS_FILTER2.providerContext

'''
    typedef [switch_type( unsigned long )] union union_61 {
            [case(0)] struct struct_56 * elem_1;
    } union_61;
'''
def decode_union_61(f, union_discriminant):
    assert(union_discriminant == 0)

    elem_1 = unsigned_long_at(f)                    # union_61.elem_1 / struct_56 * / FWPS_FILTER2 *
    print '\t\t', 'union_61.elem_1: /* FC_UP */ %s (FWPS_FILTER2 *)' % hex(elem_1)
    print

    if elem_1 != 0:
        padding = f.read(4)                         # padding
        print '\t', 'padding:', format_hex(padding)
        print

        decode_FWPS_FILTER2(f)                      # FWPS_FILTER2

'''
    typedef struct struct_15 {
            long elem_1;
            short elem_2;
            short elem_3;
            byte elem_4[8];
    } struct_15;

    struct_15 == GUID
'''
def decode_struct_15(f):
    pass

'''
    typedef struct struct_62 {
            long elem_1;
            long elem_2;                                // UINT32 layerId
            struct struct_15 elem_3;                    // GUID calloutGuid, cf. decode_struct_15()
            [switch_is(elem_1)] union union_61 elem_4;
    } struct_62;
'''
def decode_struct_62(f):
    elem_1 = signed_long_at(f)                          # struct_62.elem_1
    print '\t', 'struct_62.elem_1:', hex(elem_1)

    layerId = unsigned_long_at(f)                       # struct_62.layerId
    assert(layerId < FWPS_BUILTIN_LAYER_MAX)
    print '\t', 'struct_62.layerId:', FWPS_layerId_to_str[layerId]

    globals.g_filter.layerId = layerId

    calloutGuid = f.read(16)                            # struct_62.calloutGuid / HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE\Parameters\Policy\Persistent\Callout
    calloutGuid = str(uuid.UUID(bytes_le=calloutGuid))
    print '\t', 'struct_62.calloutGuid:', calloutGuid

    globals.g_filter.calloutGuid = calloutGuid

    union_discriminant = signed_long_at(f)
    assert(union_discriminant == elem_1)

    print '\t', 'struct_62.elem_4:'
    decode_union_61(f, union_discriminant)              # struct_62.elem_4

def decode_boottime_filter(filterGuid, f):
    globals.g_filter = BootTimeFilter()
    
    print '[+] filterGuid:', filterGuid
    print

    globals.g_filter.filterGuid = filterGuid

    header = f.read(16)                                 # header
    print '\t', 'header:', format_hex(header)
    print

    struct_62_pointer_identifier = unsigned_long_at(f)  # struct_62 *
    print '\t', '/* FC_UP */ %s (struct_62 *)' % hex(struct_62_pointer_identifier)
    print

    if struct_62_pointer_identifier != 0:
        decode_struct_62(f)                             # struct_62
    print

    globals.g_boottime_filters.append(globals.g_filter)

def decode_boottime_filters(filters):
    for k, v in filters.iteritems():
        filterGuid = k[1:-1]
        f = StringIO(v)
        decode_boottime_filter(filterGuid, f)

#
#   BFE Persistent Filters
#

'''
    // Expresses a filter condition that must be true for the action to be taken.
    typedef struct FWPM_FILTER_CONDITION0_
    {
       // GUID of the field to be tested.
       GUID fieldKey;
       // Type of match to be performed.
       FWP_MATCH_TYPE matchType;
       // Value to match the field against.
       FWP_CONDITION_VALUE0 conditionValue;
    } FWPM_FILTER_CONDITION0;
'''
def decode_FWPM_FILTER_CONDITION0(f):
    fieldKey = f.read(16)                                                   # FWPM_FILTER_CONDITION0.fieldKey
    fieldKey = str(uuid.UUID(bytes_le=fieldKey))
    assert(fieldKey in FWPM_fieldGuid_to_fieldIdStr)
    print '\t', 'FWPM_FILTER_CONDITION0.fieldKey:', FWPM_fieldGuid_to_fieldIdStr[fieldKey]

    matchType = signed_long_at(f)                                           # FWPM_FILTER_CONDITION0.matchType
    assert(matchType < FWP_MATCH_TYPE_MAX)
    print '\t', 'FWPM_FILTER_CONDITION0.matchType:', matchType_to_str[matchType]

    print '\t', 'FWPM_FILTER_CONDITION0.conditionValue:'
    conditionValue_type, conditionValue = decode_FWP_CONDITION_VALUE0(f)    # FWPM_FILTER_CONDITION0.conditionValue / FWP_UINT8 / FWP_UINT16 / FWP_UINT32 / FWP_BYTE_BLOB_TYPE (FWP_BYTE_BLOB *) / FWP_SID (SID *) / FWP_RANGE_TYPE (FWP_RANGE0 *)

    print

    return (fieldKey, matchType, conditionValue_type, conditionValue)

def decode_string(f):
    x = unsigned_long_at(f)
    y = unsigned_long_at(f)
    z = unsigned_long_at(f)
    assert(x == z)
    assert(y == 0)

    '''
    # ..
    if x == 0x1b0000:
        x = 0x1b
    elif x == 0x10000:
        x = 0
    elif x == 0x230000:
        x = 0x23
    elif x == 0x150000:
        x = 0x15
    elif x == 0x2d0000:
        x = 0x2d
    elif x == 0x2f0000:
        x = 0x2f
    elif x == 0x350000:
        x = 0x35
    elif x == 0x250000:
        x = 0x25
    elif x == 0x310000:
        x = 0x31
    '''
    # dirty fix
    if x > 0xff:
        x = x >> 16

    string = f.read(x * 2)
    string = ''.join([c if ord(c) != 0 else '' for c in string]) # remove null bytes

    return str(string)

'''
    typedef UINT32 FWP_ACTION_TYPE;

    // Action taken if all the filter conditions are true.
    typedef struct FWPM_ACTION0_
    {
       // Action type.
       FWP_ACTION_TYPE type;
       // If the action invokes a callout, calloutKey must contain the GUID for a
       // valid callout in the layer. Otherwise, the filterType may contain an
       // arbitrary GUID chosen by the policy provider.
       [switch_is(type & FWP_ACTION_FLAG_CALLOUT)]
       union
       {
           [case(0)]
           GUID filterType;
           [case(FWP_ACTION_FLAG_CALLOUT)]
           GUID calloutKey;
           [case(FWP_ACTION_BITMAP_INDEX_SET)]
           UINT8 bitmapIndex;
       };

    } FWPM_ACTION0;
'''
def decode_FWPM_ACTION0(f):
    _type = unsigned_long_at(f)                                 # FWPM_ACTION0.type
    assert(_type in actionType_to_str)
    print '\t\t', 'FWPM_ACTION0.type:', actionType_to_str[_type]

    globals.g_filter.actionType = actionType_to_str[_type]

    union_discriminant = unsigned_long_at(f)
    assert(union_discriminant == (_type & FWP_ACTION_FLAG_CALLOUT))
    assert((union_discriminant == 0) or (union_discriminant == FWP_ACTION_FLAG_CALLOUT) or (union_discriminant == FWP_ACTION_BITMAP_INDEX_SET))

    if union_discriminant == 0:
        filterType = f.read(16)                                 # FWPM_ACTION0.filterType
        filterType = str(uuid.UUID(bytes_le=filterType))
        print '\t\t', 'FWPM_ACTION0.filterType:', filterType

    elif union_discriminant == FWP_ACTION_FLAG_CALLOUT:
        calloutKey = f.read(16)                                 # FWPM_ACTION0.calloutKey
        calloutKey = str(uuid.UUID(bytes_le=calloutKey))
        print '\t\t', 'FWPM_ACTION0.calloutKey:', calloutKey

        globals.g_filter.actioncalloutGuid = calloutKey

    elif union_discriminant == FWP_ACTION_BITMAP_INDEX_SET:
        bitmapIndex = unsigned_char_at(f)                       # FWPM_ACTION0.bitmapIndex
        print '\t\t', 'FWPM_ACTION0.bitmapIndex:', hex(bitmapIndex)

        padding = f.read(3)                                     # padding
        print '\t\t', 'padding:', format_hex(padding)

'''
    // Stores an array containing a variable number of bytes.
    typedef struct FWP_BYTE_BLOB_
    {
       UINT32 size;
       [size_is(size), unique] UINT8* data;
    } FWP_BYTE_BLOB;
'''
def decode_FWP_BYTE_BLOB(f):
    size = unsigned_long_at(f)      # FWP_BYTE_BLOB.size
    print '\t\t', 'FWP_BYTE_BLOB.size:', hex(size)

    data = unsigned_long_at(f)      # FWP_BYTE_BLOB.data / UINT8 *
    print '\t\t', 'FWP_BYTE_BLOB.data: /* FC_UP */ %s (UINT8 *)' % hex(data)

    return (size, data)

'''
    // Stores an optional friendly name and description for an object. In order to
    // support MUI, both strings may contain indirect strings (see
    // SHLoadIndirectString for details).

    typedef struct FWPM_DISPLAY_DATA0_
    {
       [string, unique] wchar_t* name;
       [string, unique] wchar_t* description;
    } FWPM_DISPLAY_DATA0;
'''
def decode_FWPM_DISPLAY_DATA0(f):
    name = unsigned_long_at(f)          # FWPM_DISPLAY_DATA0.name / wchar_t *
    print '\t\t', 'FWPM_DISPLAY_DATA0.name: /* FC_UP */ %s (wchar_t *)' % hex(name)

    description = unsigned_long_at(f)   # FWPM_DISPLAY_DATA0.description / wchar_t *
    print '\t\t', 'FWPM_DISPLAY_DATA0.description: /* FC_UP */ %s (wchar_t *)' % hex(description)

    return (name, description)

'''
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

    // Stores the state associated with a filter.
    typedef struct FWPM_FILTER0_
    {
       // Information supplied when adding objects.

       // Uniquely identifies the filter. If the GUID is zero-initialized in the
       // call to Add, BFE will generate one.
       GUID filterKey;
       // Allows filters to be annotated in a human-readable form.
       FWPM_DISPLAY_DATA0 displayData;
       // Flags
       UINT32 flags;
       // Optional GUID of the policy provider that manages this object.
       [unique] GUID* providerKey;
       // Optional provider-specific data; allows providers to store additional
       // context info with the object.
       FWP_BYTE_BLOB providerData;
       // GUID of the layer where the filter resides.
       GUID layerKey;
       // GUID of the sublayer where the filter resides. If this is set to
       // IID_NULL, the filter is added to the default sublayer.
       GUID subLayerKey;
       // Weight of the filter. This must be either of type FWP_UINT64 or
       // FWP_EMPTY. If empty, BFE will automatically assign a weight based on the
       // filter conditions.
       FWP_VALUE0 weight;
       // Array of filter conditions. All must be true for the action to be
       // performed. In other words, the conditions are AND'ed together. If no
       // conditions are specified, the action is always performed.
       UINT32 numFilterConditions;
       [size_is(numFilterConditions), unique]
          FWPM_FILTER_CONDITION0* filterCondition;
       // Action performed if all the filter conditions are true.
       FWPM_ACTION0 action;
       // If FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT is not set, the rawContext is
       // placed 'as is' in the context field of the corresonding FWPS_FILTER.
       // Otherwise, the LUID of the provider context specified by the
       // providerContextKey is used.
       [switch_is(flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT)]
       union
       {
          [case(0)]
             UINT64 rawContext;
          [case(FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT)]
             GUID providerContextKey;
       };
       // Reserved for system use.
       [unique] GUID* reserved;

       // Additional information returned when getting/enumerating objects.

       // LUID identifying the filter. This is also the LUID of the corresponding
       // FWPS_FILTER.
       UINT64 filterId;
       // Weight assigned to the FWPS_FILTER filter.
       FWP_VALUE0 effectiveWeight;
    } FWPM_FILTER0;

    typedef struct FWP_RANGE0_
    {
        FWP_VALUE0 valueLow;
        FWP_VALUE0 valueHigh;
    } FWP_RANGE0;

    typedef struct FWP_BYTE_ARRAY16_
    {
        UINT8 byteArray16[ 16 ];
    } FWP_BYTE_ARRAY16;
'''
def decode_FWPM_FILTER0(f, struct_173_elem_4):
    filterKey = f.read(16)                                          # FWPM_FILTER0.filterKey / HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter
    filterKey = str(uuid.UUID(bytes_le=filterKey))
    print '\t', 'FWPM_FILTER0.filterKey:', filterKey

    globals.g_filter.filterGuid = filterKey

    print '\t', 'FWPM_FILTER0.displayData:'
    name, description = decode_FWPM_DISPLAY_DATA0(f)                # FWPM_FILTER0.displayData / wchar_t * / wchar_t *

    flags = unsigned_long_at(f)                                     # FWPM_FILTER0.flags
    print '\t', 'FWPM_FILTER0.flags:', hex(flags)

    providerKey = unsigned_long_at(f)                               # FWPM_FILTER0.providerKey / GUID *
    print '\t', 'FWPM_FILTER0.providerKey: /* FC_UP */ %s (GUID *)' % hex(providerKey)

    print '\t', 'FWPM_FILTER0.providerData:'
    size, data = decode_FWP_BYTE_BLOB(f)                            # FWPM_FILTER0.providerData / UINT8 *

    layerKey = f.read(16)                                           # FWPM_FILTER0.layerKey
    layerKey = str(uuid.UUID(bytes_le=layerKey))
    print '\t', 'FWPM_FILTER0.layerKey:', layerKey

    globals.g_filter.layerGuid = layerKey

    assert(layerKey in FWPM_layerGuid_to_layerIdStr)
    globals.g_filter.layerId = FWPM_layerGuid_to_layerIdStr[layerKey]

    subLayerKey = f.read(16)                                        # FWPM_FILTER0.subLayerKey / HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\SubLayer
    subLayerKey = str(uuid.UUID(bytes_le=subLayerKey))
    print '\t', 'FWPM_FILTER0.subLayerKey:', subLayerKey

    globals.g_filter.sublayerGuid = subLayerKey

    print '\t', 'FWPM_FILTER0.weight:'
    weight_type, weight = decode_FWP_VALUE0(f)                      # FWPM_FILTER0.weight / FWP_EMPTY / FWP_UINT8 / FWP_UINT64 (UINT64 *) / FWP_BYTE_ARRAY16_TYPE (FWP_BYTE_ARRAY16 *)

    globals.g_filter.filterWeight = weight

    numFilterConditions = unsigned_long_at(f)                       # FWPM_FILTER0.numFilterConditions
    print '\t', 'FWPM_FILTER0.numFilterConditions:', hex(numFilterConditions)

    filterCondition = unsigned_long_at(f)                           # FWPM_FILTER0.filterCondition / FWPM_FILTER_CONDITION0 *
    print '\t', 'FWPM_FILTER0.filterCondition: /* FC_UP */ %s (FWPM_FILTER_CONDITION0 *)' % hex(filterCondition)

    print '\t', 'FWPM_FILTER0.action:'
    decode_FWPM_ACTION0(f)                                          # FWPM_FILTER0.action

    union_discriminant = unsigned_long_at(f)
    assert(union_discriminant == (flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT))
    assert((union_discriminant == 0) or (union_discriminant == FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT))

    if union_discriminant == 0:
        rawContext = unsigned_long_long_at(f)                       # FWPM_FILTER0.rawContext
        print '\t', 'FWPM_FILTER0.rawContext:', hex(rawContext)

    elif union_discriminant == FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT:
        providerContextKey = f.read(16)                             # FWPM_FILTER0.providerContextKey
        providerContextKey = str(uuid.UUID(bytes_le=providerContextKey))
        print '\t', 'FWPM_FILTER0.providerContextKey:', providerContextKey

    reserved = unsigned_long_at(f)                                  # FWPM_FILTER0.reserved / GUID *
    print '\t', 'FWPM_FILTER0.reserved: /* FC_UP */ %s (GUID *)' % hex(reserved)

    while test_unsigned_long_at(f) == 0:
        padding = f.read(4)                                         # padding
        print '\t', 'padding:', format_hex(padding)

    filterId = unsigned_long_long_at(f)                             # FWPM_FILTER0.filterId
    print '\t', 'FWPM_FILTER0.filterId:', hex(filterId)

    globals.g_filter.filterId = filterId

    print '\t', 'FWPM_FILTER0.effectiveWeight:'
    effectiveWeight_type, effectiveWeight = decode_FWP_VALUE0(f)    # FWPM_FILTER0.effectiveWeight / FWP_EMPTY / FWP_UINT8 / FWP_UINT64 (UINT64 *) / FWP_BYTE_ARRAY16_TYPE (FWP_BYTE_ARRAY16 *)

    print

    #
    #   FC_UP
    #

    if name != 0:
        name = decode_string(f)                                     # FWPM_FILTER0.displayData name
        print '\t', 'FWPM_FILTER0.displayData name: "%s"' % name
        print

        globals.g_filter.filterName = name

    if description != 0:
        description = decode_string(f)                              # FWPM_FILTER0.displayData description
        print '\t', 'FWPM_FILTER0.displayData description: "%s"' % description
        print

        globals.g_filter.filterDescription = description

    if test_unsigned_short_at(f) == 0:
        while test_unsigned_short_at(f) == 0:
            padding = f.read(2)                                     # padding
            print '\t', 'padding:', format_hex(padding)
        print

    if providerKey != 0:        
        providerKey = f.read(16)                                    # FWPM_FILTER0.providerKey
        providerKey = str(uuid.UUID(bytes_le=providerKey))
        print '\t', 'FWPM_FILTER0.providerKey:', providerKey
        print

    if data != 0:
        sized_pointer_size = unsigned_long_at(f)
        assert(sized_pointer_size == size)
        
        data = f.read(size)                                         # FWPM_FILTER0.providerData
        print '\t', 'FWPM_FILTER0.providerData:', format_hex(data)
        print

    assert(weight_type == FWP_EMPTY or weight_type == FWP_UINT8 or weight_type == FWP_UINT64) # or weight_type == FWP_BYTE_ARRAY16_TYPE)
    if (weight_type == FWP_UINT64) and (weight != 0):

        if test_unsigned_short_at(f) == 0:
            while test_unsigned_short_at(f) == 0:
                padding = f.read(2)                                 # padding
                print '\t', 'padding:', format_hex(padding)
            print
        
        weight = unsigned_long_long_at(f)                           # FWPM_FILTER0.weight
        print '\t', 'FWPM_FILTER0.weight:', hex(weight)
        print

        globals.g_filter.filterWeight = weight

    if filterCondition != 0:
        sized_pointer_size = unsigned_long_at(f)
        assert(sized_pointer_size == numFilterConditions)

        conditions = []

        for i in range(0, numFilterConditions):
            fieldKey, matchType, conditionValue_type, conditionValue = decode_FWPM_FILTER_CONDITION0(f) # FWPM_FILTER0.filterCondition

            conditions.append((fieldKey, matchType, conditionValue_type, conditionValue))

        for fieldKey, matchType, conditionValue_type, conditionValue in conditions:

            assert(conditionValue_type == FWP_UINT8
                   or conditionValue_type == FWP_UINT16
                   or conditionValue_type == FWP_UINT32
                   or conditionValue_type == FWP_BYTE_BLOB_TYPE     # FWP_BYTE_BLOB *
                   or conditionValue_type == FWP_SID                # SID *
                   or conditionValue_type == FWP_RANGE_TYPE)        # FWP_RANGE0 *

            if (conditionValue_type == FWP_BYTE_BLOB_TYPE) and (conditionValue != 0):                   # FWPM_FILTER_CONDITION0.conditionValue / FWP_BYTE_BLOB *
                size = unsigned_long_at(f)                                                              # FWP_BYTE_BLOB.size
                print '\t', 'FWP_BYTE_BLOB.size:', hex(size)

                data = unsigned_long_at(f)                                                              # FWP_BYTE_BLOB.data / UINT8 *
                print '\t', 'FWP_BYTE_BLOB.data: /* FC_UP */ %s (UINT8 *)' % hex(data)

                sized_pointer_size = unsigned_long_at(f)
                assert(sized_pointer_size == size)

                data = f.read(size)
                print '\t', 'data:', format_hex(data)

                padding = f.read(4 - size % 4)                                                          # padding
                print '\t', 'padding:', format_hex(padding)
                print

                conditionValue = ''.join([c if ord(c) != 0 else '' for c in data]) # remove null bytes

            elif (conditionValue_type == FWP_SID) and (conditionValue != 0):                            # FWPM_FILTER_CONDITION0.conditionValue / SID *
                sid = f.read(16)
                sid = str(uuid.UUID(bytes_le=sid))
                print '\t', 'sid:', sid
                print

                conditionValue = sid

            elif (conditionValue_type == FWP_RANGE_TYPE) and (conditionValue != 0):                     # FWPM_FILTER_CONDITION0.conditionValue / FWP_RANGE0 *
                print '\t', 'FWP_RANGE0.valueLow:'
                valueLow_type, valueLow = decode_FWP_VALUE0(f)                                          # FWP_RANGE0.valueLow / FWP_EMPTY / FWP_UINT8 / FWP_UINT64 (UINT64 *) / FWP_BYTE_ARRAY16_TYPE (FWP_BYTE_ARRAY16 *)

                print '\t', 'FWP_RANGE0.valueHigh:'
                valueHigh_type, valueHigh = decode_FWP_VALUE0(f)                                        # FWP_RANGE0.valueHigh / FWP_EMPTY / FWP_UINT8 / FWP_UINT64 (UINT64 *) / FWP_BYTE_ARRAY16_TYPE (FWP_BYTE_ARRAY16 *)

                assert(valueLow_type == FWP_BYTE_ARRAY16_TYPE) # or valueLow_type == FWP_EMPTY or valueLow_type == FWP_UINT8 or valueLow_type == FWP_UINT64)
                if (valueLow_type == FWP_BYTE_ARRAY16_TYPE) and (valueLow != 0):
                    valueLow = f.read(16)
                    print '\t', 'valueLow:', format_hex(valueLow)

                assert(valueHigh_type == FWP_BYTE_ARRAY16_TYPE) # or valueHigh_type == FWP_EMPTY or valueHigh_type == FWP_UINT8 or valueHigh_type == FWP_UINT64)
                if (valueHigh_type == FWP_BYTE_ARRAY16_TYPE) and (valueHigh != 0):
                    valueHigh = f.read(16)
                    print '\t', 'valueHigh:', format_hex(valueHigh)

                print

                conditionValue = format_hex(valueLow) + '-' + format_hex(valueHigh)

            assert(fieldKey in FWPM_fieldGuid_to_fieldIdStr)
            globals.g_filter.conditions.append( (FWPM_fieldGuid_to_fieldIdStr[fieldKey], matchType_to_str[matchType], conditionValue) )

    assert(reserved == 0)                                           # FWPM_FILTER0.reserved

    assert(effectiveWeight_type == FWP_EMPTY or effectiveWeight_type == FWP_UINT8 or effectiveWeight_type == FWP_UINT64) # or effectiveWeight_type == FWP_BYTE_ARRAY16_TYPE)
    if (effectiveWeight_type == FWP_UINT64) and (effectiveWeight != 0):

        current_position = f.tell()
        padding_size = 0
        done = False

        while not done:
            try:
                padding = f.read(padding_size)                      # padding
        
                effectiveWeight = unsigned_long_long_at(f)          # FWPM_FILTER0.effectiveWeight

                #
                #   struct_173.elem_5
                #

                sized_pointer_size = unsigned_long_at(f)
                assert(sized_pointer_size == struct_173_elem_4)

                done = True

            except AssertionError:
                f.seek(current_position)
                padding_size = padding_size + 2

        if padding:
            print '\t', 'padding:', format_hex(padding)
            print

        print '\t', 'FWPM_FILTER0.effectiveWeight:', hex(effectiveWeight)
        print

    else:
        #
        #   struct_173.elem_5
        #

        sized_pointer_size = unsigned_long_at(f)
        assert(sized_pointer_size == struct_173_elem_4)

elem_1_to_str = [
    'Provider',         # FWPM_PROVIDER_MARSHAL_Decode(x, x)
    'Provider Context', # FWPM_PROVIDER_CONTEXT_MARSHAL_Decode(x, x)
    'SubLayer',         # FWPM_SUBLAYER_MARSHAL_Decode(x, x)
    'Layer',            # FWPM_LAYER_MARSHAL_Decode(x, x)
    'Callout',          # FWPM_CALLOUT_MARSHAL_Decode(x, x)
    'Filter',           # FWPM_FILTER_MARSHAL_Decode(x, x)              # pFormatString 10001D54  # 10001D54 - 10001BCA = 0x18A = 394 # struct_24 *
    'Container'         # FWPM_CONTAINER0_MARSHAL_Decode(x, x)
]

'''
    typedef struct struct_173 {
            long elem_1;
            long elem_2;
            [size_is(elem_2)] char * elem_3;
            long elem_4;
            [size_is(elem_4)] char * elem_5;
    } struct_173;
'''
def decode_struct_173(f):
    elem_1 = unsigned_long_at(f)                                # struct_173.elem_1
    assert(elem_1 < len(elem_1_to_str))
    print '\t', 'struct_173.elem_1:', elem_1_to_str[elem_1]

    elem_2 = unsigned_long_at(f)                                # struct_173.elem_2
    print '\t', 'struct_173.elem_2:', hex(elem_2)

    elem_3 = unsigned_long_at(f)                                # struct_173.elem_3 / struct_24 ** / FWPM_FILTER0 **
    print '\t', 'struct_173.elem_3: /* FC_UP */ %s (FWPM_FILTER0 **)' % hex(elem_3)

    elem_4 = unsigned_long_at(f)                                # struct_173.elem_4
    print '\t', 'struct_173.elem_4:', hex(elem_4)

    elem_5 = unsigned_long_at(f)                                # struct_173.elem_5 / char *
    print '\t', 'struct_173.elem_5: /* FC_UP */ %s (char *)' % hex(elem_5)

    print

    #
    #   FC_UP
    #

    if elem_3 != 0:
        sized_pointer_size = unsigned_long_at(f)
        assert(sized_pointer_size == elem_2)

        header = f.read(16)                                     # header
        print '\t', 'header:', format_hex(header)
        print

        FWPM_FILTER0_pointer_identifier = unsigned_long_at(f)   # struct_24 * / FWPM_FILTER0 *
        print '\t', '/* FC_UP */ %s (FWPM_FILTER0 *)' % hex(FWPM_FILTER0_pointer_identifier)
        print

        padding = f.read(4)                                     # padding
        print '\t', 'padding:', format_hex(padding)
        print

        decode_FWPM_FILTER0(f, elem_4)                          # struct_24 / FWPM_FILTER0

    # TODO
    if elem_5 != 0:
        pass

def decode_persistent_filter(filterGuid, f):
    globals.g_filter = PersistentFilter()
    
    print '[+] filterGuid:', filterGuid
    print

    header = f.read(16)                                 # header
    print '\t', 'header:', format_hex(header)
    print

    struct_173_pointer_identifier = unsigned_long_at(f) # struct_173 *
    print '\t', '/* FC_UP */ %s (struct_173 *)' % hex(struct_173_pointer_identifier)
    print

    if struct_173_pointer_identifier != 0:
        decode_struct_173(f)                            # struct_173
    print

    globals.g_persistent_filters.append(globals.g_filter)

def decode_persistent_filters(filters):
    for k, v in filters.iteritems():
        filterGuid = k
        f = StringIO(v)
        decode_persistent_filter(filterGuid, f)

#
#   MAIN
#

def main():
    globals.init()

    #
    #   BFE BootTime Filters
    #   "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE\Parameters\Policy\BootTime\Filter"
    #

    decode_boottime_filters(globals.g_BFE_BootTime_Filters)

    print '%d BootTime Filters\n' % len(globals.g_boottime_filters)

    for i in range(0, len(globals.g_boottime_filters)):
        print i
        globals.g_boottime_filters[i].pprint()
    print

    #
    #   BFE Persistent Filters
    #   "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BFE\Parameters\Policy\Persistent\Filter"
    #

    decode_persistent_filters(globals.g_BFE_Persistent_Filters)

    print '%d Persistent Filters\n' % len(globals.g_persistent_filters)

    for i in range(0, len(globals.g_persistent_filters)):
        print i
        globals.g_persistent_filters[i].pprint()
    print

    #
    #   HTML export
    #

    export_bfe_filters_to_html()

if __name__ == "__main__":
    main()
