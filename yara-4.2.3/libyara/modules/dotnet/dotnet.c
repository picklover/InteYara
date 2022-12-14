/*
Copyright (c) 2015. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <yara/dotnet.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/pe.h>
#include <yara/pe_utils.h>
#include <yara/strutils.h>

#define MODULE_NAME dotnet

char* pe_get_dotnet_string(
    PE* pe,
    const uint8_t* string_offset,
    DWORD string_index)
{
  size_t remaining;

  char* start;
  char* eos;

  // Start of string must be within boundary
  if (!(string_offset + string_index >= pe->data &&
        string_offset + string_index < pe->data + pe->data_size))
    return NULL;

  // Calculate how much until end of boundary, don't scan past that.
  remaining = (pe->data + pe->data_size) - (string_offset + string_index);

  // Search for a NULL terminator from start of string, up to remaining.
  start = (char*) (string_offset + string_index);
  eos = (char*) memmem((void*) start, remaining, "\0", 1);

  // If no NULL terminator was found or the string is too large, return NULL.
  if (eos == NULL || eos - start > 1024)
    return NULL;

  return start;
}

uint32_t max_rows(int count, ...)
{
  va_list ap;
  int i;
  uint32_t biggest;
  uint32_t x;

  if (count == 0)
    return 0;

  va_start(ap, count);
  biggest = va_arg(ap, uint32_t);

  for (i = 1; i < count; i++)
  {
    x = va_arg(ap, uint32_t);
    biggest = (x > biggest) ? x : biggest;
  }

  va_end(ap);
  return biggest;
}

void dotnet_parse_guid(
    PE* pe,
    int64_t metadata_root,
    PSTREAM_HEADER guid_header)
{
  // GUIDs are 16 bytes each, converted to hex format plus separators and NULL.
  char guid[37];
  int i = 0;

  const uint8_t* guid_offset = pe->data + metadata_root +
                               yr_le32toh(guid_header->Offset);

  DWORD guid_size = yr_le32toh(guid_header->Size);

  // Limit the number of GUIDs to 16.
  guid_size = yr_min(guid_size, 256);

  // Parse GUIDs if we have them. GUIDs are 16 bytes each.
  while (guid_size >= 16 && fits_in_pe(pe, guid_offset, 16))
  {
    sprintf(
        guid,
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        yr_le32toh(*(uint32_t*) guid_offset),
        yr_le16toh(*(uint16_t*) (guid_offset + 4)),
        yr_le16toh(*(uint16_t*) (guid_offset + 6)),
        *(guid_offset + 8),
        *(guid_offset + 9),
        *(guid_offset + 10),
        *(guid_offset + 11),
        *(guid_offset + 12),
        *(guid_offset + 13),
        *(guid_offset + 14),
        *(guid_offset + 15));

    guid[(16 * 2) + 4] = '\0';

    set_string(guid, pe->object, "guids[%i]", i);

    i++;
    guid_size -= 16;
    guid_offset += 16;
  }

  set_integer(i, pe->object, "number_of_guids");
}

// Given an offset into a #US or #Blob stream, parse the entry at that position.
// The offset is relative to the start of the PE file.
BLOB_PARSE_RESULT dotnet_parse_blob_entry(PE* pe, const uint8_t* offset)
{
  BLOB_PARSE_RESULT result;

  // Blob size is encoded in the first 1, 2 or 4 bytes of the blob.
  //
  // If the high bit is not set the length is encoded in one byte.
  //
  // If the high 2 bits are 10 (base 2) then the length is encoded in
  // the rest of the bits and the next byte.
  //
  // If the high 3 bits are 110 (base 2) then the length is encoded
  // in the rest of the bits and the next 3 bytes.
  //
  // See ECMA-335 II.24.2.4 for details.

  // Make sure we have at least one byte.

  if (!fits_in_pe(pe, offset, 1))
  {
    result.size = 0;
    return result;
  }

  if ((*offset & 0x80) == 0x00)
  {
    result.length = (DWORD) *offset;
    result.size = 1;
  }
  else if ((*offset & 0xC0) == 0x80)
  {
    // Make sure we have one more byte.
    if (!fits_in_pe(pe, offset, 2))
    {
      result.size = 0;
      return result;
    }

    // Shift remaining 6 bits left by 8 and OR in the remaining byte.
    result.length = ((*offset & 0x3F) << 8) | *(offset + 1);
    result.size = 2;
  }
  else if (offset + 4 < pe->data + pe->data_size && (*offset & 0xE0) == 0xC0)
  {
    // Make sure we have 3 more bytes.
    if (!fits_in_pe(pe, offset, 4))
    {
      result.size = 0;
      return result;
    }

    result.length = ((*offset & 0x1F) << 24) | (*(offset + 1) << 16) |
                    (*(offset + 2) << 8) | *(offset + 3);
    result.size = 4;
  }
  else
  {
    // Return a 0 size as an error.
    result.size = 0;
    return result;
  }

  // There is an additional terminal byte which is 0x01 under certain
  // conditions. The exact conditions are not relevant to our parsing but are
  // documented in ECMA-335 II.24.2.4.
  if (result.length > 0)
    result.length--;

  return result;
}

void dotnet_parse_us(PE* pe, int64_t metadata_root, PSTREAM_HEADER us_header)
{
  BLOB_PARSE_RESULT blob_result;
  int i = 0;

  const uint32_t ush_sz = yr_le32toh(us_header->Size);

  const uint8_t* offset = pe->data + metadata_root +
                          yr_le32toh(us_header->Offset);
  const uint8_t* end_of_header = offset + ush_sz;

  // Make sure the header size is larger than 0 and its end is not past the
  // end of PE.
  if (ush_sz == 0 || !fits_in_pe(pe, offset, ush_sz))
    return;

  // The first entry MUST be single NULL byte.
  if (*offset != 0x00)
    return;

  offset++;

  while (offset < end_of_header)
  {
    blob_result = dotnet_parse_blob_entry(pe, offset);

    if (blob_result.size == 0)
      break;

    offset += blob_result.size;
    // Avoid empty strings, which usually happen as padding at the end of the
    // stream.

    if (blob_result.length > 0 && fits_in_pe(pe, offset, blob_result.length))
    {
      set_sized_string(
          (char*) offset,
          blob_result.length,
          pe->object,
          "user_strings[%i]",
          i);

      offset += blob_result.length;
      i++;
    }
  }

  set_integer(i, pe->object, "number_of_user_strings");
}

STREAMS dotnet_parse_stream_headers(
    PE* pe,
    int64_t offset,
    int64_t metadata_root,
    DWORD num_streams)
{
  PSTREAM_HEADER stream_header;
  STREAMS headers;

  char* start;
  char* eos;
  char stream_name[DOTNET_STREAM_NAME_SIZE + 1];
  unsigned int i;

  memset(&headers, '\0', sizeof(STREAMS));

  stream_header = (PSTREAM_HEADER) (pe->data + offset);

  for (i = 0; i < num_streams; i++)
  {
    if (!struct_fits_in_pe(pe, stream_header, STREAM_HEADER))
      break;

    start = (char*) stream_header->Name;

    if (!fits_in_pe(pe, start, DOTNET_STREAM_NAME_SIZE))
      break;

    eos = (char*) memmem((void*) start, DOTNET_STREAM_NAME_SIZE, "\0", 1);

    if (eos == NULL)
      break;

    strncpy(stream_name, stream_header->Name, DOTNET_STREAM_NAME_SIZE);
    stream_name[DOTNET_STREAM_NAME_SIZE] = '\0';

    set_string(stream_name, pe->object, "streams[%i].name", i);

    // Offset is relative to metadata_root.
    set_integer(
        metadata_root + yr_le32toh(stream_header->Offset),
        pe->object,
        "streams[%i].offset",
        i);

    set_integer(
        yr_le32toh(stream_header->Size), pe->object, "streams[%i].size", i);

    // Store necessary bits to parse these later. Not all tables will be
    // parsed, but are referenced from others. For example, the #Strings
    // stream is referenced from various tables in the #~ heap.
    //
    // #- is not documented but it represents unoptimized metadata stream. It
    // may contain additional tables such as FieldPtr, ParamPtr, MethodPtr or
    // PropertyPtr for indirect referencing. We already take into account these
    // tables and they do not interfere with anything we parse in this module.

    if ((strncmp(stream_name, "#~", 2) == 0 ||
         strncmp(stream_name, "#-", 2) == 0) &&
        headers.tilde == NULL)
      headers.tilde = stream_header;
    else if (strncmp(stream_name, "#GUID", 5) == 0)
      headers.guid = stream_header;
    else if (strncmp(stream_name, "#Strings", 8) == 0 && headers.string == NULL)
      headers.string = stream_header;
    else if (strncmp(stream_name, "#Blob", 5) == 0)
      headers.blob = stream_header;
    else if (strncmp(stream_name, "#US", 3) == 0 && headers.us == NULL)
      headers.us = stream_header;

    // Stream name is padded to a multiple of 4.
    stream_header =
        (PSTREAM_HEADER) ((uint8_t*) stream_header + sizeof(STREAM_HEADER) + strlen(stream_name) + 4 - (strlen(stream_name) % 4));
  }

  set_integer(i, pe->object, "number_of_streams");

  return headers;
}

// This is the second pass through the data for #~. The first pass collects
// information on the number of rows for tables which have coded indexes.
// This pass uses that information and the index_sizes to parse the tables
// of interest.
//
// Because the indexes can vary in size depending upon the number of rows in
// other tables it is impossible to use static sized structures. To deal with
// this hardcode the sizes of each table based upon the documentation (for the
// static sized portions) and use the variable sizes accordingly.

void dotnet_parse_tilde_2(
    PE* pe,
    PTILDE_HEADER tilde_header,
    int64_t resource_base,
    int64_t metadata_root,
    ROWS rows,
    INDEX_SIZES index_sizes,
    PSTREAMS streams)
{
  PMODULE_TABLE module_table;
  PASSEMBLY_TABLE assembly_table;
  PASSEMBLYREF_TABLE assemblyref_table;
  PFIELDRVA_TABLE fieldrva_table;
  PMANIFESTRESOURCE_TABLE manifestresource_table;
  PMODULEREF_TABLE moduleref_table;
  PCUSTOMATTRIBUTE_TABLE customattribute_table;
  PCONSTANT_TABLE constant_table;
  DWORD resource_size, implementation;

  char* name;
  char typelib[MAX_TYPELIB_SIZE + 1];
  unsigned int i;
  int bit_check;
  int matched_bits = 0;

  int64_t resource_offset, field_offset;
  uint32_t row_size, row_count, counter;

  const uint8_t* string_offset;
  const uint8_t* blob_offset;

  uint32_t num_rows = 0;
  uint32_t valid_rows = 0;
  uint32_t* row_offset = NULL;
  uint8_t* table_offset = NULL;
  uint8_t* row_ptr = NULL;

  // These are pointers and row sizes for tables of interest to us for special
  // parsing. For example, we are interested in pulling out any CustomAttributes
  // that are GUIDs so we need to be able to walk these tables. To find GUID
  // CustomAttributes you need to walk the CustomAttribute table and look for
  // any row with a Parent that indexes into the Assembly table and Type indexes
  // into the MemberRef table. Then you follow the index into the MemberRef
  // table and check the Class to make sure it indexes into TypeRef table. If it
  // does you follow that index and make sure the Name is "GuidAttribute". If
  // all that is valid then you can take the Value from the CustomAttribute
  // table to find out the index into the Blob stream and parse that.
  //
  // Luckily we can abuse the fact that the order of the tables is guaranteed
  // consistent (though some may not exist, but if they do exist they must exist
  // in a certain order). The order is defined by their position in the Valid
  // member of the tilde_header structure. By the time we are parsing the
  // CustomAttribute table we have already recorded the location of the TypeRef
  // and MemberRef tables, so we can follow the chain back up from
  // CustomAttribute through MemberRef to TypeRef.

  uint8_t* typeref_ptr = NULL;
  uint8_t* memberref_ptr = NULL;
  uint32_t typeref_row_size = 0;
  uint32_t memberref_row_size = 0;
  uint8_t* typeref_row = NULL;
  uint8_t* memberref_row = NULL;

  DWORD type_index;
  DWORD class_index;
  BLOB_PARSE_RESULT blob_result;
  DWORD blob_index;
  DWORD blob_length;

  // These are used to determine the size of coded indexes, which are the
  // dynamically sized columns for some tables. The coded indexes are
  // documented in ECMA-335 Section II.24.2.6.
  uint8_t index_size, index_size2;

  // Number of rows is the number of bits set to 1 in Valid.
  // Should use this technique:
  // http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
  for (i = 0; i < 64; i++)
    valid_rows += ((yr_le64toh(tilde_header->Valid) >> i) & 0x01);

  row_offset = (uint32_t*) (tilde_header + 1);
  table_offset = (uint8_t*) row_offset;
  table_offset += sizeof(uint32_t) * valid_rows;

#define DOTNET_STRING_INDEX(Name)                       \
  index_sizes.string == 2 ? yr_le16toh(Name.Name_Short) \
                          : yr_le32toh(Name.Name_Long)

  string_offset = pe->data + metadata_root +
                  yr_le32toh(streams->string->Offset);

  // Now walk again this time parsing out what we care about.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    // If the Valid bit is not set for this table, skip it...
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

    if (!fits_in_pe(pe, row_offset + matched_bits, sizeof(uint32_t)))
      return;

    num_rows = yr_le32toh(*(row_offset + matched_bits));

    // Make sure that num_rows has a reasonable value. For example
    // edc05e49dd3810be67942b983455fd43 sets a large value for number of
    // rows for the BIT_MODULE section.
    if (num_rows > 10000)
      return;

    // Those tables which exist, but that we don't care about must be
    // skipped.
    //
    // Sadly, given the dynamic sizes of some columns we can not have well
    // defined structures for all tables and use them accordingly. To deal
    // with this manually move the table_offset pointer by the appropriate
    // number of bytes as described in the documentation for each table.
    //
    // The table structures are documented in ECMA-335 Section II.22.

    switch (bit_check)
    {
    case BIT_MODULE:
      module_table = (PMODULE_TABLE) table_offset;

      if (!struct_fits_in_pe(pe, module_table, MODULE_TABLE))
        break;

      name = pe_get_dotnet_string(
          pe, string_offset, DOTNET_STRING_INDEX(module_table->Name));

      if (name != NULL)
        set_string(name, pe->object, "module_name");

      table_offset += (2 + index_sizes.string + (index_sizes.guid * 3)) *
                      num_rows;
      break;

    case BIT_TYPEREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.module),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.typeref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + (index_sizes.string * 2));
      typeref_row_size = row_size;
      typeref_ptr = table_offset;
      table_offset += row_size * num_rows;
      break;

    case BIT_TYPEDEF:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (4 + (index_sizes.string * 2) + index_size +
                       index_sizes.field + index_sizes.methoddef) *
                      num_rows;
      break;

    case BIT_FIELDPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.field) * num_rows;
      break;

    case BIT_FIELD:
      table_offset += (2 + (index_sizes.string) + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODDEFPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.methoddef) * num_rows;
      break;

    case BIT_METHODDEF:
      table_offset += (4 + 2 + 2 + index_sizes.string + index_sizes.blob +
                       index_sizes.param) *
                      num_rows;
      break;

    case BIT_PARAM:
      table_offset += (2 + 2 + index_sizes.string) * num_rows;
      break;

    case BIT_INTERFACEIMPL:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.typedef_ + index_size) * num_rows;
      break;

    case BIT_MEMBERREF:
      row_count = max_rows(
          4,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x03))
        index_size = 4;
      else
        index_size = 2;

      row_size = (index_size + index_sizes.string + index_sizes.blob);
      memberref_row_size = row_size;
      memberref_ptr = table_offset;
      table_offset += row_size * num_rows;
      break;

    case BIT_CONSTANT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.param),
          yr_le32toh(rows.field),
          yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      // Using 'i' is insufficent since we may skip certain constants and
      // it would give an inaccurate count in that case.
      counter = 0;
      row_size = (1 + 1 + index_size + index_sizes.blob);
      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        constant_table = (PCONSTANT_TABLE) row_ptr;

        // Only look for constants of type string.
        if (yr_le32toh(constant_table->Type) != ELEMENT_TYPE_STRING)
        {
          row_ptr += row_size;
          continue;
        }

        // Get the blob offset and pull it out of the blob table.
        blob_offset = ((uint8_t*) constant_table) + 2 + index_size;

        if (index_sizes.blob == 4)
          blob_index = *(DWORD*) blob_offset;
        else
          // Cast the value (index into blob table) to a 32bit value.
          blob_index = (DWORD) (*(WORD*) blob_offset);

        // Everything checks out. Make sure the index into the blob field
        // is valid (non-null and within range).
        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset) + blob_index;

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);

        if (blob_result.size == 0)
        {
          row_ptr += row_size;
          continue;
        }

        blob_length = blob_result.length;
        blob_offset += blob_result.size;

        // Quick sanity check to make sure the blob entry is within bounds.
        if (blob_offset + blob_length >= pe->data + pe->data_size)
        {
          row_ptr += row_size;
          continue;
        }

        set_sized_string(
            (char*) blob_offset,
            blob_result.length,
            pe->object,
            "constants[%i]",
            counter);

        counter++;
        row_ptr += row_size;
      }

      set_integer(counter, pe->object, "number_of_constants");
      table_offset += row_size * num_rows;
      break;

    case BIT_CUSTOMATTRIBUTE:
      // index_size is size of the parent column.
      row_count = max_rows(
          21,
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.field),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.param),
          yr_le32toh(rows.interfaceimpl),
          yr_le32toh(rows.memberref),
          yr_le32toh(rows.module),
          yr_le32toh(rows.property),
          yr_le32toh(rows.event),
          yr_le32toh(rows.standalonesig),
          yr_le32toh(rows.moduleref),
          yr_le32toh(rows.typespec),
          yr_le32toh(rows.assembly),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.file),
          yr_le32toh(rows.exportedtype),
          yr_le32toh(rows.manifestresource),
          yr_le32toh(rows.genericparam),
          yr_le32toh(rows.genericparamconstraint),
          yr_le32toh(rows.methodspec));

      if (row_count > (0xFFFF >> 0x05))
        index_size = 4;
      else
        index_size = 2;

      // index_size2 is size of the type column.
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x03))
        index_size2 = 4;
      else
        index_size2 = 2;

      row_size = (index_size + index_size2 + index_sizes.blob);

      if (typeref_ptr != NULL && memberref_ptr != NULL)
      {
        row_ptr = table_offset;

        for (i = 0; i < num_rows; i++)
        {
          if (!fits_in_pe(pe, row_ptr, row_size))
            break;

          // Check the Parent field.
          customattribute_table = (PCUSTOMATTRIBUTE_TABLE) row_ptr;

          if (index_size == 4)
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((*(DWORD*) customattribute_table & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }
          else
          {
            // Low 5 bits tell us what this is an index into. Remaining bits
            // tell us the index value.
            // Parent must be an index into the Assembly (0x0E) table.
            if ((*(WORD*) customattribute_table & 0x1F) != 0x0E)
            {
              row_ptr += row_size;
              continue;
            }
          }

          // Check the Type field.
          customattribute_table =
              (PCUSTOMATTRIBUTE_TABLE) (row_ptr + index_size);

          if (index_size2 == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((*(DWORD*) customattribute_table & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            type_index = *(DWORD*) customattribute_table >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Only values 2 and 3 are defined.
            // Type must be an index into the MemberRef table.
            if ((*(WORD*) customattribute_table & 0x07) != 0x03)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            type_index = (DWORD) ((*(WORD*) customattribute_table >> 3));
          }

          if (type_index > 0)
            type_index--;

          // Now follow the Type index into the MemberRef table.
          memberref_row = memberref_ptr + (memberref_row_size * type_index);

          if (!fits_in_pe(pe, memberref_row, memberref_row_size))
            break;

          if (index_sizes.memberref == 4)
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((*(DWORD*) memberref_row & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            class_index = *(DWORD*) memberref_row >> 3;
          }
          else
          {
            // Low 3 bits tell us what this is an index into. Remaining bits
            // tell us the index value. Class must be an index into the
            // TypeRef table.
            if ((*(WORD*) memberref_row & 0x07) != 0x01)
            {
              row_ptr += row_size;
              continue;
            }

            // Cast the index to a 32bit value.
            class_index = (DWORD) (*(WORD*) memberref_row >> 3);
          }

          if (class_index > 0)
            class_index--;

          // Now follow the Class index into the TypeRef table.
          typeref_row = typeref_ptr + (typeref_row_size * class_index);

          if (!fits_in_pe(pe, typeref_row, typeref_row_size))
            break;

          // Skip over the ResolutionScope and check the Name field,
          // which is an index into the Strings heap.
          row_count = max_rows(
              4,
              yr_le32toh(rows.module),
              yr_le32toh(rows.moduleref),
              yr_le32toh(rows.assemblyref),
              yr_le32toh(rows.typeref));

          if (row_count > (0xFFFF >> 0x02))
            typeref_row += 4;
          else
            typeref_row += 2;

          if (index_sizes.string == 4)
          {
            name = pe_get_dotnet_string(
                pe, string_offset, *(DWORD*) typeref_row);
          }
          else
          {
            name = pe_get_dotnet_string(
                pe, string_offset, *(WORD*) typeref_row);
          }

          if (name != NULL && strncmp(name, "GuidAttribute", 13) != 0)
          {
            row_ptr += row_size;
            continue;
          }

          // Get the Value field.
          customattribute_table =
              (PCUSTOMATTRIBUTE_TABLE) (row_ptr + index_size + index_size2);

          if (index_sizes.blob == 4)
            blob_index = *(DWORD*) customattribute_table;
          else
            // Cast the value (index into blob table) to a 32bit value.
            blob_index = (DWORD) (*(WORD*) customattribute_table);

          // Everything checks out. Make sure the index into the blob field
          // is valid (non-null and within range).
          blob_offset = pe->data + metadata_root +
                        yr_le32toh(streams->blob->Offset) + blob_index;

          // If index into blob is 0 or past the end of the blob stream, skip
          // it. We don't know the size of the blob entry yet because that is
          // encoded in the start.
          if (blob_index == 0x00 || blob_offset >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          blob_result = dotnet_parse_blob_entry(pe, blob_offset);

          if (blob_result.size == 0)
          {
            row_ptr += row_size;
            continue;
          }

          blob_length = blob_result.length;
          blob_offset += blob_result.size;

          // Quick sanity check to make sure the blob entry is within bounds
          // and its length is at least 3 (2 bytes for the 16 bits prolog and
          // 1 byte for the string length)
          if (blob_length < 3 ||
              blob_offset + blob_length >= pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          // Custom attributes MUST have a 16 bit prolog of 0x0001
          if (*(WORD*) blob_offset != 0x0001)
          {
            row_ptr += row_size;
            continue;
          }

          // The next byte after the 16 bit prolog is the length of the string.
          blob_offset += 2;
          uint8_t str_len = *blob_offset;

          // Increment blob_offset so that it points to the first byte of the
          // string.
          blob_offset += 1;

          if (blob_offset + str_len > pe->data + pe->data_size)
          {
            row_ptr += row_size;
            continue;
          }

          if (*blob_offset == 0xFF || *blob_offset == 0x00)
          {
            typelib[0] = '\0';
          }
          else
          {
            strncpy(typelib, (char*) blob_offset, str_len);
            typelib[str_len] = '\0';
          }

          set_string(typelib, pe->object, "typelib");

          row_ptr += row_size;
        }
      }

      table_offset += row_size * num_rows;
      break;

    case BIT_FIELDMARSHAL:
      row_count = max_rows(2, yr_le32toh(rows.field), yr_le32toh(rows.param));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_DECLSECURITY:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.methoddef),
          yr_le32toh(rows.assembly));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_CLASSLAYOUT:
      table_offset += (2 + 4 + index_sizes.typedef_) * num_rows;
      break;

    case BIT_FIELDLAYOUT:
      table_offset += (4 + index_sizes.field) * num_rows;
      break;

    case BIT_STANDALONESIG:
      table_offset += (index_sizes.blob) * num_rows;
      break;

    case BIT_EVENTMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.event) * num_rows;
      break;

    case BIT_EVENTPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.event) * num_rows;
      break;

    case BIT_EVENT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.string + index_size) * num_rows;
      break;

    case BIT_PROPERTYMAP:
      table_offset += (index_sizes.typedef_ + index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTYPTR:
      // This one is not documented in ECMA-335.
      table_offset += (index_sizes.property) * num_rows;
      break;

    case BIT_PROPERTY:
      table_offset += (2 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_METHODSEMANTICS:
      row_count = max_rows(
          2, yr_le32toh(rows.event), yr_le32toh(rows.property));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_sizes.methoddef + index_size) * num_rows;
      break;

    case BIT_METHODIMPL:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.typedef_ + (index_size * 2)) * num_rows;
      break;

    case BIT_MODULEREF:
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the string if it is not
      // NULL. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        moduleref_table = (PMODULEREF_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, moduleref_table, MODULEREF_TABLE))
          break;

        name = pe_get_dotnet_string(
            pe, string_offset, DOTNET_STRING_INDEX(moduleref_table->Name));

        if (name != NULL)
        {
          set_string(name, pe->object, "modulerefs[%i]", counter);
          counter++;
        }

        row_ptr += index_sizes.string;
      }

      set_integer(counter, pe->object, "number_of_modulerefs");

      table_offset += (index_sizes.string) * num_rows;
      break;

    case BIT_TYPESPEC:
      table_offset += (index_sizes.blob) * num_rows;
      break;

    case BIT_IMPLMAP:
      row_count = max_rows(
          2, yr_le32toh(rows.field), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + index_size + index_sizes.string +
                       index_sizes.moduleref) *
                      num_rows;
      break;

    case BIT_FIELDRVA:
      row_size = 4 + index_sizes.field;
      row_ptr = table_offset;

      // Can't use 'i' here because we only set the field offset if it is
      // valid. Instead use 'counter'.
      counter = 0;

      for (i = 0; i < num_rows; i++)
      {
        fieldrva_table = (PFIELDRVA_TABLE) row_ptr;

        if (!struct_fits_in_pe(pe, fieldrva_table, FIELDRVA_TABLE))
          break;

        field_offset = pe_rva_to_offset(pe, fieldrva_table->RVA);

        if (field_offset >= 0)
        {
          set_integer(field_offset, pe->object, "field_offsets[%i]", counter);
          counter++;
        }

        row_ptr += row_size;
      }

      set_integer(counter, pe->object, "number_of_field_offsets");

      table_offset += row_size * num_rows;
      break;

    case BIT_ENCLOG:
      table_offset += (4 + 4) * num_rows;
      break;

    case BIT_ENCMAP:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLY:
      row_size =
          (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob + (index_sizes.string * 2));

      if (!fits_in_pe(pe, table_offset, row_size))
        break;

      row_ptr = table_offset;
      assembly_table = (PASSEMBLY_TABLE) table_offset;

      set_integer(
          yr_le16toh(assembly_table->MajorVersion),
          pe->object,
          "assembly.version.major");
      set_integer(
          yr_le16toh(assembly_table->MinorVersion),
          pe->object,
          "assembly.version.minor");
      set_integer(
          yr_le16toh(assembly_table->BuildNumber),
          pe->object,
          "assembly.version.build_number");
      set_integer(
          yr_le16toh(assembly_table->RevisionNumber),
          pe->object,
          "assembly.version.revision_number");

      // Can't use assembly_table here because the PublicKey comes before
      // Name and is a variable length field.

      if (index_sizes.string == 4)
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            yr_le32toh(*(
                DWORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));
      else
        name = pe_get_dotnet_string(
            pe,
            string_offset,
            yr_le16toh(
                *(WORD*) (row_ptr + 4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

      if (name != NULL)
        set_string(name, pe->object, "assembly.name");

      // Culture comes after Name.
      if (index_sizes.string == 4)
      {
        name = pe_get_dotnet_string(
              pe,
              string_offset,
              yr_le32toh(*(DWORD*) (
                  row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
                  index_sizes.blob +
                  index_sizes.string)));
      }
      else
      {
        name = pe_get_dotnet_string(
              pe,
              string_offset,
              yr_le16toh(*(WORD*) (
                  row_ptr + 4 + 2 + 2 + 2 + 2 + 4 +
                  index_sizes.blob +
                  index_sizes.string)));
      }

      // Sometimes it will be a zero length string. This is technically
      // against the specification but happens from time to time.
      if (name != NULL && strlen(name) > 0)
        set_string(name, pe->object, "assembly.culture");

      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYPROCESSOR:
      table_offset += (4) * num_rows;
      break;

    case BIT_ASSEMBLYOS:
      table_offset += (4 + 4 + 4) * num_rows;
      break;

    case BIT_ASSEMBLYREF:
      row_size =
          (2 + 2 + 2 + 2 + 4 + (index_sizes.blob * 2) +
           (index_sizes.string * 2));

      row_ptr = table_offset;

      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        assemblyref_table = (PASSEMBLYREF_TABLE) row_ptr;

        set_integer(
            yr_le16toh(assemblyref_table->MajorVersion),
            pe->object,
            "assembly_refs[%i].version.major",
            i);
        set_integer(
            yr_le16toh(assemblyref_table->MinorVersion),
            pe->object,
            "assembly_refs[%i].version.minor",
            i);
        set_integer(
            yr_le16toh(assemblyref_table->BuildNumber),
            pe->object,
            "assembly_refs[%i].version.build_number",
            i);
        set_integer(
            yr_le16toh(assemblyref_table->RevisionNumber),
            pe->object,
            "assembly_refs[%i].version.revision_number",
            i);

        blob_offset = pe->data + metadata_root +
                      yr_le32toh(streams->blob->Offset);

        if (index_sizes.blob == 4)
          blob_offset += yr_le32toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Long);
        else
          blob_offset += yr_le16toh(
              assemblyref_table->PublicKeyOrToken.PublicKeyOrToken_Short);

        blob_result = dotnet_parse_blob_entry(pe, blob_offset);
        blob_offset += blob_result.size;

        if (blob_result.size == 0 ||
            !fits_in_pe(pe, blob_offset, blob_result.length))
        {
          row_ptr += row_size;
          continue;
        }

        // Avoid empty strings.
        if (blob_result.length > 0)
        {
          set_sized_string(
              (char*) blob_offset,
              blob_result.length,
              pe->object,
              "assembly_refs[%i].public_key_or_token",
              i);
        }

        // Can't use assemblyref_table here because the PublicKey comes before
        // Name and is a variable length field.

        if (index_sizes.string == 4)
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              yr_le32toh(
                  *(DWORD*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));
        else
          name = pe_get_dotnet_string(
              pe,
              string_offset,
              yr_le16toh(
                  *(WORD*) (row_ptr + 2 + 2 + 2 + 2 + 4 + index_sizes.blob)));

        if (name != NULL)
          set_string(name, pe->object, "assembly_refs[%i].name", i);

        row_ptr += row_size;
      }

      set_integer(i, pe->object, "number_of_assembly_refs");
      table_offset += row_size * num_rows;
      break;

    case BIT_ASSEMBLYREFPROCESSOR:
      table_offset += (4 + index_sizes.assemblyrefprocessor) * num_rows;
      break;

    case BIT_ASSEMBLYREFOS:
      table_offset += (4 + 4 + 4 + index_sizes.assemblyref) * num_rows;
      break;

    case BIT_FILE:
      table_offset += (4 + index_sizes.string + index_sizes.blob) * num_rows;
      break;

    case BIT_EXPORTEDTYPE:
      row_count = max_rows(
          3,
          yr_le32toh(rows.file),
          yr_le32toh(rows.assemblyref),
          yr_le32toh(rows.exportedtype));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (4 + 4 + (index_sizes.string * 2) + index_size) *
                      num_rows;
      break;

    case BIT_MANIFESTRESOURCE:
      // This is an Implementation coded index with no 3rd bit specified.
      row_count = max_rows(
          2, yr_le32toh(rows.file), yr_le32toh(rows.assemblyref));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      row_size = (4 + 4 + index_sizes.string + index_size);

      // Using 'i' is insufficent since we may skip certain resources and
      // it would give an inaccurate count in that case.
      counter = 0;
      row_ptr = table_offset;

      // First DWORD is the offset.
      for (i = 0; i < num_rows; i++)
      {
        if (!fits_in_pe(pe, row_ptr, row_size))
          break;

        manifestresource_table = (PMANIFESTRESOURCE_TABLE) row_ptr;
        resource_offset = yr_le32toh(manifestresource_table->Offset);

        // Only set offset if it is in this file (implementation != 0).
        // Can't use manifestresource_table here because the Name and
        // Implementation fields are variable size.
        if (index_size == 4)
          implementation = yr_le32toh(
              *(DWORD*) (row_ptr + 4 + 4 + index_sizes.string));
        else
          implementation = yr_le16toh(
              *(WORD*) (row_ptr + 4 + 4 + index_sizes.string));

        if (implementation != 0)
        {
          row_ptr += row_size;
          continue;
        }

        if (!fits_in_pe(
                pe, pe->data + resource_base + resource_offset, sizeof(DWORD)))
        {
          row_ptr += row_size;
          continue;
        }

        resource_size = yr_le32toh(
            *(DWORD*) (pe->data + resource_base + resource_offset));

        if (!fits_in_pe(
                pe, pe->data + resource_base + resource_offset, resource_size))
        {
          row_ptr += row_size;
          continue;
        }

        // Add 4 to skip the size.
        set_integer(
            resource_base + resource_offset + 4,
            pe->object,
            "resources[%i].offset",
            counter);

        set_integer(resource_size, pe->object, "resources[%i].length", counter);

        name = pe_get_dotnet_string(
            pe,
            string_offset,
            DOTNET_STRING_INDEX(manifestresource_table->Name));

        if (name != NULL)
          set_string(name, pe->object, "resources[%i].name", counter);

        row_ptr += row_size;
        counter++;
      }

      set_integer(counter, pe->object, "number_of_resources");

      table_offset += row_size * num_rows;
      break;

    case BIT_NESTEDCLASS:
      table_offset += (index_sizes.typedef_ * 2) * num_rows;
      break;

    case BIT_GENERICPARAM:
      row_count = max_rows(
          2, yr_le32toh(rows.typedef_), yr_le32toh(rows.methoddef));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (2 + 2 + index_size + index_sizes.string) * num_rows;
      break;

    case BIT_METHODSPEC:
      row_count = max_rows(
          2, yr_le32toh(rows.methoddef), yr_le32toh(rows.memberref));

      if (row_count > (0xFFFF >> 0x01))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_size + index_sizes.blob) * num_rows;
      break;

    case BIT_GENERICPARAMCONSTRAINT:
      row_count = max_rows(
          3,
          yr_le32toh(rows.typedef_),
          yr_le32toh(rows.typeref),
          yr_le32toh(rows.typespec));

      if (row_count > (0xFFFF >> 0x02))
        index_size = 4;
      else
        index_size = 2;

      table_offset += (index_sizes.genericparam + index_size) * num_rows;
      break;

    default:
      // printf("Unknown bit: %i\n", bit_check);
      return;
    }

    matched_bits++;
  }
}

// Parsing the #~ stream is done in two parts. The first part (this function)
// parses enough of the Stream to provide context for the second pass. In
// particular it is collecting the number of rows for each of the tables. The
// second part parses the actual tables of interest.

void dotnet_parse_tilde(
    PE* pe,
    int64_t metadata_root,
    PCLI_HEADER cli_header,
    PSTREAMS streams)
{
  PTILDE_HEADER tilde_header;
  int64_t resource_base;
  uint32_t* row_offset = NULL;

  int bit_check;

  // This is used as an offset into the rows and tables. For every bit set in
  // Valid this will be incremented. This is because the bit position doesn't
  // matter, just the number of bits that are set, when determining how many
  // rows and what the table structure is.
  int matched_bits = 0;

  // We need to know the number of rows for some tables, because they are
  // indexed into. The index will be either 2 or 4 bytes, depending upon the
  // number of rows being indexed into.
  ROWS rows;
  INDEX_SIZES index_sizes;
  uint32_t heap_sizes;

  // Default all rows to 0. They will be set to actual values later on, if
  // they exist in the file.
  memset(&rows, '\0', sizeof(ROWS));

  // Default index sizes are 2. Will be bumped to 4 if necessary.
  memset(&index_sizes, 2, sizeof(index_sizes));

  tilde_header =
      (PTILDE_HEADER) (pe->data + metadata_root + yr_le32toh(streams->tilde->Offset));

  if (!struct_fits_in_pe(pe, tilde_header, TILDE_HEADER))
    return;

  heap_sizes = yr_le32toh(tilde_header->HeapSizes);

  // Set index sizes for various heaps.
  if (heap_sizes & 0x01)
    index_sizes.string = 4;

  if (heap_sizes & 0x02)
    index_sizes.guid = 4;

  if (heap_sizes & 0x04)
    index_sizes.blob = 4;

  // Immediately after the tilde header is an array of 32bit values which
  // indicate how many rows are in each table. The tables are immediately
  // after the rows array.
  //
  // Save the row offset.
  row_offset = (uint32_t*) (tilde_header + 1);

  // Walk all the bits first because we need to know the number of rows for
  // some tables in order to parse others. In particular this applies to
  // coded indexes, which are documented in ECMA-335 II.24.2.6.
  for (bit_check = 0; bit_check < 64; bit_check++)
  {
    if (!((yr_le64toh(tilde_header->Valid) >> bit_check) & 0x01))
      continue;

#define ROW_CHECK(name)                                                  \
  if (fits_in_pe(pe, row_offset, (matched_bits + 1) * sizeof(uint32_t))) \
    rows.name = *(row_offset + matched_bits);

#define ROW_CHECK_WITH_INDEX(name)    \
  ROW_CHECK(name);                    \
  if (yr_le32toh(rows.name) > 0xFFFF) \
    index_sizes.name = 4;

    switch (bit_check)
    {
    case BIT_MODULE:
      ROW_CHECK(module);
      break;
    case BIT_MODULEREF:
      ROW_CHECK_WITH_INDEX(moduleref);
      break;
    case BIT_ASSEMBLYREF:
      ROW_CHECK_WITH_INDEX(assemblyref);
      break;
    case BIT_ASSEMBLYREFPROCESSOR:
      ROW_CHECK_WITH_INDEX(assemblyrefprocessor);
      break;
    case BIT_TYPEREF:
      ROW_CHECK(typeref);
      break;
    case BIT_METHODDEF:
      ROW_CHECK_WITH_INDEX(methoddef);
      break;
    case BIT_MEMBERREF:
      ROW_CHECK_WITH_INDEX(memberref);
      break;
    case BIT_TYPEDEF:
      ROW_CHECK_WITH_INDEX(typedef_);
      break;
    case BIT_TYPESPEC:
      ROW_CHECK(typespec);
      break;
    case BIT_FIELD:
      ROW_CHECK_WITH_INDEX(field);
      break;
    case BIT_PARAM:
      ROW_CHECK_WITH_INDEX(param);
      break;
    case BIT_PROPERTY:
      ROW_CHECK_WITH_INDEX(property);
      break;
    case BIT_INTERFACEIMPL:
      ROW_CHECK(interfaceimpl);
      break;
    case BIT_EVENT:
      ROW_CHECK_WITH_INDEX(event);
      break;
    case BIT_STANDALONESIG:
      ROW_CHECK(standalonesig);
      break;
    case BIT_ASSEMBLY:
      ROW_CHECK(assembly);
      break;
    case BIT_FILE:
      ROW_CHECK(file);
      break;
    case BIT_EXPORTEDTYPE:
      ROW_CHECK(exportedtype);
      break;
    case BIT_MANIFESTRESOURCE:
      ROW_CHECK(manifestresource);
      break;
    case BIT_GENERICPARAM:
      ROW_CHECK_WITH_INDEX(genericparam);
      break;
    case BIT_GENERICPARAMCONSTRAINT:
      ROW_CHECK(genericparamconstraint);
      break;
    case BIT_METHODSPEC:
      ROW_CHECK(methodspec);
      break;
    default:
      break;
    }

    matched_bits++;
  }

  // This is used when parsing the MANIFEST RESOURCE table.
  resource_base = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->Resources.VirtualAddress));

  dotnet_parse_tilde_2(
      pe,
      tilde_header,
      resource_base,
      metadata_root,
      rows,
      index_sizes,
      streams);
}

static bool dotnet_is_dotnet(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory = pe_get_directory_entry(
      pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

  if (!directory)
    return false;

  int64_t offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return false;

  CLI_HEADER* cli_header = (CLI_HEADER*) (pe->data + offset);

  if (yr_le32toh(cli_header->Size) != sizeof(CLI_HEADER))
    return false;

  int64_t metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));
  offset = metadata_root;

  if (!struct_fits_in_pe(pe, pe->data + metadata_root, NET_METADATA))
    return false;

  NET_METADATA* metadata = (NET_METADATA*) (pe->data + metadata_root);

  if (yr_le32toh(metadata->Magic) != NET_METADATA_MAGIC)
    return false;

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  uint32_t md_len = yr_le32toh(metadata->Length);
  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return false;
  }

  if (IS_64BITS_PE(pe))
  {
    if (yr_le16toh(OptionalHeader(pe, NumberOfRvaAndSizes)) <
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
      return false;
  }
  else if (!(pe->header->FileHeader.Characteristics & IMAGE_FILE_DLL))  // 32bit
  {
    // Check first 2 bytes of the Entry point are equal to 0xFF 0x25
    int64_t entry_offset = pe_rva_to_offset(
        pe, yr_le32toh(pe->header->OptionalHeader.AddressOfEntryPoint));

    if (entry_offset < 0 || !fits_in_pe(pe, pe->data + entry_offset, 2))
      return false;

    const uint8_t* entry_data = pe->data + entry_offset;
    if (!(entry_data[0] == 0xFF && entry_data[1] == 0x25))
      return false;
  }

  return true;
}

void dotnet_parse_com(PE* pe)
{
  PIMAGE_DATA_DIRECTORY directory;
  PCLI_HEADER cli_header;
  PNET_METADATA metadata;
  int64_t metadata_root, offset;
  char* end;
  STREAMS headers;
  WORD num_streams;
  uint32_t md_len;

  if (!dotnet_is_dotnet(pe))
  {
    set_integer(0, pe->object, "is_dotnet");
    return;
  }

  set_integer(1, pe->object, "is_dotnet");

  directory = pe_get_directory_entry(pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
  if (directory == NULL)
    return;

  offset = pe_rva_to_offset(pe, yr_le32toh(directory->VirtualAddress));

  if (offset < 0 || !struct_fits_in_pe(pe, pe->data + offset, CLI_HEADER))
    return;

  cli_header = (PCLI_HEADER) (pe->data + offset);

  offset = metadata_root = pe_rva_to_offset(
      pe, yr_le32toh(cli_header->MetaData.VirtualAddress));

  if (!struct_fits_in_pe(pe, pe->data + offset, NET_METADATA))
    return;

  metadata = (PNET_METADATA) (pe->data + offset);

  // Version length must be between 1 and 255, and be a multiple of 4.
  // Also make sure it fits in pe.
  md_len = yr_le32toh(metadata->Length);

  if (md_len == 0 || md_len > 255 || md_len % 4 != 0 ||
      !fits_in_pe(pe, pe->data + offset + sizeof(NET_METADATA), md_len))
  {
    return;
  }

  // The length includes the NULL terminator and is rounded up to a multiple of
  // 4. We need to exclude the terminator and the padding, so search for the
  // first NULL byte.
  end = (char*) memmem((void*) metadata->Version, md_len, "\0", 1);

  if (end != NULL)
    set_sized_string(
        metadata->Version, (end - metadata->Version), pe->object, "version");

  // The metadata structure has some variable length records after the version.
  // We must manually parse things from here on out.
  //
  // Flags are 2 bytes (always 0).
  offset += sizeof(NET_METADATA) + md_len + 2;

  // 2 bytes for Streams.
  if (!fits_in_pe(pe, pe->data + offset, 2))
    return;

  num_streams = (WORD) * (pe->data + offset);
  offset += 2;

  headers = dotnet_parse_stream_headers(pe, offset, metadata_root, num_streams);

  if (headers.guid != NULL)
    dotnet_parse_guid(pe, metadata_root, headers.guid);

  // Parse the #~ stream, which includes various tables of interest.
  // These tables reference the blob and string streams, so we need to ensure
  // those are not NULL also.
  if (headers.tilde != NULL && headers.string != NULL && headers.blob != NULL)
    dotnet_parse_tilde(pe, metadata_root, cli_header, &headers);

  if (headers.us != NULL)
    dotnet_parse_us(pe, metadata_root, headers.us);
}

begin_declarations
  declare_integer("is_dotnet");
  declare_string("version");
  declare_string("module_name");

  begin_struct_array("streams")
    declare_string("name");
    declare_integer("offset");
    declare_integer("size");
  end_struct_array("streams")

  declare_integer("number_of_streams");

  declare_string_array("guids");
  declare_integer("number_of_guids");

  begin_struct_array("resources")
    declare_integer("offset");
    declare_integer("length");
    declare_string("name");
  end_struct_array("resources")

  declare_integer("number_of_resources");

  begin_struct_array("assembly_refs")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("public_key_or_token");
    declare_string("name");
  end_struct_array("assembly_refs")

  declare_integer("number_of_assembly_refs");

  begin_struct("assembly")
    begin_struct("version")
      declare_integer("major");
      declare_integer("minor");
      declare_integer("build_number");
      declare_integer("revision_number");
    end_struct("version")
    declare_string("name");
    declare_string("culture");
  end_struct("assembly")

  declare_string_array("modulerefs");
  declare_integer("number_of_modulerefs");
  declare_string_array("user_strings");
  declare_integer("number_of_user_strings");
  declare_string("typelib");
  declare_string_array("constants");
  declare_integer("number_of_constants");

  declare_integer_array("field_offsets");
  declare_integer("number_of_field_offsets");
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  const uint8_t* block_data = NULL;

  foreach_memory_block(iterator, block)
  {
    PIMAGE_NT_HEADERS32 pe_header;

    block_data = block->fetch_data(block);

    if (block_data == NULL)
      continue;

    pe_header = pe_get_header(block_data, block->size);

    if (pe_header != NULL)
    {
      // Ignore DLLs while scanning a process

      if (!(context->flags & SCAN_FLAGS_PROCESS_MEMORY) ||
          !(pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL))
      {
        PE* pe = (PE*) yr_malloc(sizeof(PE));

        if (pe == NULL)
          return ERROR_INSUFFICIENT_MEMORY;

        pe->data = block_data;
        pe->data_size = block->size;
        pe->object = module_object;
        pe->header = pe_header;

        module_object->data = pe;

        dotnet_parse_com(pe);

        break;
      }
    }
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  PE* pe = (PE*) module_object->data;

  if (pe == NULL)
    return ERROR_SUCCESS;

  yr_free(pe);

  return ERROR_SUCCESS;
}
