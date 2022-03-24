import struct
import string
import xlrd
import pandas as pd
from printy import *
from helpers import *
from helpers import Helpers
from beautifultable import BeautifulTable


class XLSParser:
    """
    The XLSParser() class is a helper class for the OLEParser class.
    It specifically handles OLE Excel files, as those have additional parsing and logic that needs to be applicaed
    to fully parse/analyze the file.

    The class will:
    - Parse BOF records (Beginning of File headers)
    - Parse BOUNDSHEET records (sheets)
    - Detect hidden sheets via BOUNDSHEET records
    - Detect if a sheet has XLM macros via BOUNDSHEET records
    - Extract strings from sheets.
    - Extract Shared Strings Table strings.

    """
    def __init__(self, data):
        self.data = data

    # Used later for XLM macro methods.
    xlm_flag = None
    # Used later for hidden sheet detection.
    hidden_sheet_flag = None

    # Initiate the Helpers() class
    helpers = Helpers()

    # Assign bas BoF record offset with temporary integer value.
    base_bof_record = 0

    def strings(self, filename, min=7):
        """
        UNIX strings implementation in python
        https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
        """
        with open(filename, errors="ignore") as f:  # Python 3.x
            # with open(filename, "rb") as f:       # Python 2.x
            result = ""
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                    yield result
                result = ""
            if len(result) >= min:  # catch result at EOF
                    yield result

    def parse_base_bof_offset(self, data):

        # Save the offset of the base BoF record.
        base_bof_record = re.search(self.helpers.BOF_RECORD_RE, data)
        # Return BoF record offset (start offset)
        return base_bof_record.start()

    def parse_base_bof_record(self, data, bof_table):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          -  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          -  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """
        # Parse base BoF record as the start offset of all other BoF records (aligned one after the other).
        self.base_bof_record = self.parse_base_bof_offset(data)

        # Add base BoF offset to BoF table
        bof_table.rows.append(["Offset in file", str(hex(self.base_bof_record))])

        # Parse BoF chunk size (of the entire file)
        bof_chunk_size = len(data[self.base_bof_record:re.search(self.helpers.EOF_BOF,
                                                            data[self.base_bof_record:]).start() + 4])
        # Add base BoF block size to BoF table.
        print_string = "%d bytes" % bof_chunk_size
        bof_table.rows.append(["BOF file chunk size", print_string])

        # Parse BoF record length
        biff_header_length = struct.unpack("<H", data[self.base_bof_record + 2:self.base_bof_record + 4])[0]

        # Add BoF record length to BoF table.
        bof_table.rows.append(["BOF record length", str(biff_header_length)])

        # Parse BIFF version of the file.
        biff_version = data[self.base_bof_record + 5:self.base_bof_record + 6]

        # The carved bytes from the BoF record will be parsed in the check_biff_version method.
        self.check_biff_version(biff_version, bof_table)

        # Parse the XLM flag.
        xlm = data[self.base_bof_record + 6]

        # Parse and check the XLM flag.
        self.check_xlm_flag_in_bof(xlm, bof_table)

        # Extract all following BoF records using regex.
        # The regex scans the data starting from the end of the base BoF (end of first file).
        bof_headers = re.findall(self.helpers.BOF_RECORD_RE, data[self.base_bof_record:])

        # Return a list of BoF records and the offset of the base BoF record.
        return bof_headers, self.base_bof_record

    def parse_rest_of_bofs(self, data, bof_table, bof_headers, position):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          -  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          -  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """

        for i in range(1, len(bof_headers)):

            # Get offset of bof record in relation to the base BoF record offset
            loc = re.search(bof_headers[i], data[position:])

            if loc:

                # Calculate base BoF's end offset to determine the start of the second record.
                bof_offset_record_end = position + loc.start() + 12

                # Calculate the end offset of the current BoF record.
                end_of_bof = re.search(self.helpers.EOF_BOF, data[bof_offset_record_end:])

                if not end_of_bof:
                    # if BoF end of file record was not found, it is the last record.
                    end_offset = len(data)
                else:
                    # Else, calculate the end offset for the current BoF file (end of file / EOF).
                    end_offset = end_of_bof.end() + bof_offset_record_end

                # After BoF chunk start and end offsets are calculated, the BoF record is parsed
                printy("\n[y]BOF (Beginning of File) record:@")

                # Add record offset as new row to final summary table.
                bof_table.rows.append(["Offset in file", str(hex(bof_offset_record_end - 12))])

                # Calculate BoF chunk size (entire file)
                bof_chunk_size = end_offset - bof_offset_record_end
                # Add chunk size as new row to final summary table.
                bof_table.rows.append(["BOF file block size", str(bof_chunk_size)])

                # Parse BIFF header length.
                biff_header_length = struct.unpack("<H", data[bof_offset_record_end + 2:bof_offset_record_end + 4])[0]
                bof_table.rows.append(["BOF record length", str(biff_header_length)])

                # Parse BIFF version bytes.
                biff_version = data[data.find(bof_headers[i]) + 5:data.find(bof_headers[i]) + 6]
                # Determine BIFF version by cheking byte values.
                self.check_biff_version(biff_version, bof_table)

                # Parse XLM byte from record.
                xlm = data[bof_offset_record_end - 6]

                # Determine XLM 4 macros existence by checking byte values.
                self.check_xlm_flag_in_bof(xlm, bof_table)

                # Used to calculate the next BoF's end offset in the nex iteration.
                position = bof_offset_record_end + 12

                # Prepare and print BoF table.
                bof_table.columns.alignment = BeautifulTable.ALIGN_LEFT
                print(bof_table)

                # Clear table for next record.
                bof_table.clear()

                #print(hexdump.hexdump(data[bof_offset_record_end -12: (bof_offset_record_end -12) + 100]))

            else:
                print("failed getting BOF header location, fix regex...")

    def parse_bof_records(self, data):
        """
        Wraps all functions related to BoF records parsing.
        First parses the base BoF record offset.
        then proceeds to the rest of the records.
        For each record it will print a table showing the record fields/values.

        """
        printy("\n[bw]BOF (Beginging of File) Records@\n" + "=" * 30)
        print("\nBase BOF (Begginging of File) record:")

        # create BoF table
        bof_table = BeautifulTable(maxwidth=100)

        # Parse base BoF record, return list of all other records.
        # position = base BoF record offset.
        # bof_headers = Bof records list (without base record).
        bof_headers, position = self.parse_base_bof_record(data, bof_table)

        # Prepare BoF table and print it.
        bof_table.columns.alignment = BeautifulTable.ALIGN_LEFT

        # Print BoF table for current record.
        print(bof_table)

        # Clear the table for next BoF record.
        bof_table.clear()

        # After parsing the base BoF record, proceed to parsing all the rest.
        # The base BoF record offset is used to calculate offsets of following records.
        # position = base BoF record offset.
        # bof_headers = Bof records list (without base record).
        self.parse_rest_of_bofs(data, bof_table, bof_headers, position)

    def check_biff_version(self, biff_version_bytes, bof_table):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        BoF (beginning of file) record for the mandatory Workbook Globals Substream, which must be the first substream
        in a BIFF8 XLS file:
          -  2-byte BoF record number field. Hex value 0908. 09 indicates a BoF record. 08 indicates the BIFF version.
          -  2 bytes unspecified
          *  BoF record data, starting with 2-byte Hex value 0006, indicating BIFF8
          *  2-byte Hex value 0500, indicating that the substream stream for which this is the record data is the
          mandatory Workbook Globals Substream
        """

        # Hex value 0006, indicating BIFF 5/7
        if biff_version_bytes is b'\x05':
            bof_table.rows.append(["BIFF version", "5/7"])

        # Hex value 0006, indicating BIFF8
        elif biff_version_bytes is b'\x06':
            bof_table.rows.append(["BIFF version", "8"])

    def check_xlm_flag_in_bof(self, xlm_bytes, bof_table):
        """
        Checks for XLM 4 macros presence by checking the value in the parsed XLM flag from the BoF record.
        - 0x10 - BOF record is a WorkSheet
        - 0x05 - BOF record for mandatory Workbook Globals Substream
        - 0x40 - BOF of a substream that contains XLM Macros

        """
        # Hex value 0x40, indicating the sheet contains XLM 4 macros.
        if xlm_bytes is 0x40:
            self.xlm_flag = True

            # Prepare to add row to bof table.
            print_string = raw_format("[r>]XLM Macros")
            print_desc = raw_format("[r>](XLM byte: 0x40) BOF of a substream that contains XLM Macros@")
            bof_table.rows.append([print_string, print_desc])

            # Add row to final summary table.
            self.helpers.add_summary_if_no_duplicates(print_string, "XLM 4.0 macros found in sheets")

        # Add to table just for full parsing.
        elif xlm_bytes is 0x05:
            bof_table.rows.append(["XLM Macros", "(0x05) BOF record for mandatory Workbook Globals Substream"])

        # Add to table just for full parsing.
        elif xlm_bytes is 0x10:
            bof_table.rows.append(["XLM Macros", "(0x10) BOF record is a WorkSheet"])

    def carve_sheet_name(self, data, raw_record):
        """
        Carve sheet names when iterating over BOUNDSHEET records.
        Returns the sheet name.

        """
        if raw_record in data:
            loc = data.find(raw_record)
            sheet_chunk = data[loc:loc + 42]

            try:
                try:
                    sheet_name = re.findall(self.helpers.SHEET_NAME_1, sheet_chunk)[0]
                    clean_sheet_name = []

                    for byte in sheet_name:

                        if 31 < byte < 128:

                            clean_sheet_name += chr(byte)

                    name = "".join(clean_sheet_name)
                    return name

                except IndexError:
                    sheet_name = re.findall(self.helpers.SHEET_NAME_2,
                                            sheet_chunk)[0]
                    clean_sheet_name = []

                    for byte in sheet_name:
                        if byte > 12 and byte < 128:
                            clean_sheet_name += chr(byte)
                    name = "".join(clean_sheet_name)
                    return name

            except IndexError:
                return 0

    def parse_boundsheet_record(self, data):
        """
        Parse BOUNDSHEET records.
        https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf

        """
        printy("\n[bw]Excel Sheets (BoundSheet records):@\n" + "=" * 40)

        # Parse base BoF record offset.
        base_bof_offset = self.parse_base_bof_offset(data)

        # Create sheets table.
        sheets_table = BeautifulTable(maxwidth=100)
        #sheets_table.column_headers = ([])

        # Extract all BOUNDSHEET records.
        regex = re.compile(self.helpers.BOUNDHSEET_RECORD)
        boundsheet_records = re.findall(regex, data)
        i = 0

        for record in boundsheet_records:
            if record[3] is b"\x00" or (record[9] is b"\x00" or record[9] is b"\x01"):
                continue
            else:
                # get sheet name
                sheet_name = self.carve_sheet_name(data, record)

                # Loop exit flag.
                # If the BoF is the last record, it is set to True.
                # The function will also parse the record and extract findings.
                flag = self.handle_sheet_parsing(i, sheet_name, record, base_bof_offset, data, boundsheet_records,
                                                 sheets_table)
                if flag:
                    break
                i += 1
                if i > len(boundsheet_records):
                    break
                else:
                    break

        # If hidden flag is True, add to summary table.
        if self.hidden_sheet_flag:
            print_string = raw_format("[r>]Hidden sheets detected in workbook@")
            self.helpers.add_summary_if_no_duplicates(print_string,
                                                      "Hidden sheets usually hide malicious strings/XLM macros")

    def handle_sheet_parsing(self, i, sheet_name, record, base_bof_offset, data, boundsheet_records, sheets_table):
        """
        Parses a sheet, using a provided sheet name, base BoF offset, data and carved BOUNDSHEET records.
        For each sheet it will create a table with the parsed record fields/values.

        """
        # exit flag
        flag = False

        # Check if sheet name os not None and validate input.
        if sheet_name and not re.search('[\\\/\?\*\[\]]', sheet_name):

            # flag that states whether current sheet is the last sheet.
            last_sheet = False

            # Parse sheet's BoF record offset.
            sheet_bof_offset = struct.unpack('<I', record[4:8])[0] + base_bof_offset

            # Check if the BoF record is not out of range and not to small.
            if sheet_bof_offset > len(data) or sheet_bof_offset < 512:
                flag = True
                return True

            try:
                # Calculate next BOUNDSHEET record offset.
                next_record = re.search(boundsheet_records[i + 1], data)

                # Check if next record offset is not None
                if next_record:
                    # Assign next BOUNDSHEET record offset to final variable
                    final_next_record = next_record.start()
                else:
                    # If next record offset could not be calculated, its the last sheet.
                    last_sheet = True
                    # Calculate end offset for sheet.
                    end_offset = re.search(self.helpers.EOF_BOF, data)
                    final_end_offset = end_offset.start() + 4

            except IndexError:
                # If boundsheet_records[i + 1] does not exist, its the last sheet.
                last_sheet = True
                # Calculate end offset for sheet.
                end_offset = re.search(self.helpers.EOF_BOF, data)
                final_end_offset = end_offset.start() + 4

            if last_sheet:
                # If this is the last sheet, the start of next sheet is actually the end of the file.
                next_sheet_offset = final_end_offset
            else:
                # Next sheet start offset is the end of the current sheet
                next_sheet_offset = final_next_record

            # print boundsheet_record table:
            printy("\n[y]Sheet Name: \'%s\'@" % str(sheet_name))

             # Parse base BoF record offset
            base_bof_record = self.parse_base_bof_offset(data)

            # Add sheet's associated BoF record start offset to sheets table.
            sheets_table.rows.append(["Sheet associated BOF record start offset", str(hex(sheet_bof_offset))])

            # Carve sheet chunk from data.
            sheet_chunk = data[sheet_bof_offset:sheet_bof_offset + next_sheet_offset]

            # Calculate sheet size (start of next sheet - start of current sheet).
            sheet_size = hex(next_sheet_offset - sheet_bof_offset)
            sheets_table.rows.append(["Sheet size", str(sheet_size)])

            # Check if sheet is hidden.
            print_string = self.get_visible_flag(i, sheet_name, boundsheet_records)
            sheets_table.rows.append(["Sheet visibility", print_string])

            # Set hidden flag if sheet is HIDDEN or VERY HIDDEN.
            if "Sheet is hidden" in print_string or "Sheet is VERY hidden" in print_string:
                self.hidden_sheet_flag = True

            # Append an XLM 4 macros indication to the sheets table.
            print_string = self.detect_xlm_macros(i, boundsheet_records, sheet_name)
            sheets_table.rows.append(["Excel 4.0 Macros", print_string])

            # print(hexdump.hexdump(sheet_chunk[:100]))

            # Prepare sheets table before printing.
            sheets_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            print(sheets_table)

            # Clear sheets table for next record (each record is printed in a separate table).
            sheets_table.clear()

    def detect_xlm_macros(self, sheet_index, boundsheet_records, sheet_name):
        """
        Receives a sheet index number, BOUNDHSEET records and a sheet name.
        Pasrses the relevant XLM flag byte from the BOUNDSHEET record and compares it to known constants.
        Returns a string indicating whether XLM 4 macros is present.

        Constants:
        - 0x00 - no macros
        - 0x01 - Has XLM 4 macros

        """
        # Carve XLM flag byte from the boundsheet record.
        xlm_macros = boundsheet_records[sheet_index][9:10]

        # Check for Excel 4.0 XLM Macros.
        if xlm_macros == b"\x00":
            return "Sheet does not contain Excel 4.0 Macros\n"

        elif xlm_macros == b"\x01":
            return "Sheet contains Excel 4.0 Macros"

    def extract_sheets(self, fname):

        try:
            book = xlrd.open_workbook(fname)

            printy("\n[bw]Strings from sheets:@" + "\n" + "=" * 20)

            for i in range(0, len(book.sheets())):
                printy("\n[y]Sheet name: \"%s\"@" % str(book.sheet_by_index(i).name))
                print("-" * 20)
                printy("[y][+] Searching Excel 4.0 Macros (XLM) in sheet cells@\n")

                # Print non-empty cells.
                for row in range(book.sheet_by_index(i).nrows):
                    for col in range(book.sheet_by_index(i).ncols):
                        cell_obj = book.sheet_by_index(i).cell(row, col)

                        if cell_obj.value is '':
                            continue
                        else:
                            print(cell_obj.value)

                printy("\n[y][+] Extracting generic strings from sheet: %s@\n" % str(book.sheet_by_index(i).name))

                # strings implementation in python
                # https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
                sl = list(self.strings(fname))

                # Print each string and scan it against known keywords/indicators.
                for s in sl:
                    if len(s) > 15:
                        print(s)
                        self.helpers.search_indicators_in_string(fname, s)

        except IndexError as e:
            printy("\n[r>][-] For some reason, failed to read data from the Excel sheets (\"xlrd.open_workbook(fname)\")....@\n")
            pass

    def get_visible_flag(self, sheet_index, sheet_name, boundsheet_records):

        # Get sheet hidden flag.
        sheet_hidden = boundsheet_records[sheet_index][8:9]

        # Check if sheet is hidden.
        if int.from_bytes(sheet_hidden, "little") & 0x03 == 0x00:
            return "Sheet is visible"

        elif int.from_bytes(sheet_hidden, "little") & 0x03 == 0x01:
            return "Sheet is hidden"

        elif int.from_bytes(sheet_hidden, "little") & 0x03 == 0x02:
            return "Sheet is VERY hidden"

    def unhide_sheets(self, xls_file):

        print("\nUnhiding hidden sheets...")
        data = xls_file.read()

        boundsheet_records = re.findall(self.helpers.BOUNDHSEET_RECORD, data)

        patched_name = ".\\clean\\patched_unhidden.xls"

        try:
            patched_file = open("patched_unhidden.xls", "xb")
        except FileExistsError:
            patched_file = open("patched_unhidden.xls", "r+b")

        patched_file.write(data)

        for record in boundsheet_records:

            loc = data.find(record)

            if record[len(record ) -2] is not 0:

                xls_file.seek(loc + 8)
                sheet_name = self.carve_sheet_name(data, record)
                print("Sheet: \"%s\" - Patching file at offset %s with \\x00 byte. Patched XLS file: %s"
                      % (str(sheet_name), str(hex(loc + 8)), patched_name))

                patched_file.write(b'\x00')

            else:
                continue
        xls_file.close()
        patched_file.close()

    def parse_sst(self, data):

        """
        https://www.openoffice.org/sc/excelfileformat.pdf

         Shared Strings Table Structure:
         -------------------------------
         Abs. stream offset Rel. rec. offset Contents    Description
         ----------------------------------------------------------------------------------------
         00020000H           0000H           00FCH       SST identifier
         00020002H           0002H           1000H       Size of the SST record
         00020004H           0004H           00000011H   Total number of strings in the document
         00020008H           0008H           00000011H   Number of unique strings following
         0002000CH           000CH           String 0    (total size = 0100H bytes)
         0002010CH           010CH           String 1    (total size = 0200H bytes)
         0002030CH           030CH           String 2    (total size = 0100H bytes)
         00020800H           0800H           String 8    (total size = 0100H bytes)
         00021004H           0000H           003CH       CONTINUE identifier
         00021006H           0002H           0320H       Size of the CONTINUE record
         00021008H           0004H                       Continuation of string 14 (size = 0020H bytes)
         00021028H           0024H                       String 15 (total size = 0100H bytes)
         00021128H           0124H                       String 16 (total size = 0200H bytes)
         00021328H           0000H           00FFH       EXTSST identifier
         0002132AH           0002H           001AH       Size of the EXTSST record
         0002132CH           0004H           0008H       8 strings in each portion
         0002132EH           0006H           0002000CH   Absolute stream position of string 0
         00021332H           000AH           000CH       Relative record position of string 0 (in SST)
         00021334H           000CH           0000H       Not used
         00021336H           000EH           00020800H   Absolute stream position of string 8
         0002133AH           0012H           0800H       Relative record position of string 8 (in SST)
         0002133CH           0014H           0000H       Not used
         0002133EH           0016H           00021128H   Absolute stream position of string 16
         00021342H           001AH           0124H       Relative record position of string 16 (in CONTINUE)
         00021344H           001CH           0000H       Not used
        """

        print("\nShared String Table (SST):")

        sst_table = BeautifulTable(maxwidth=100)
        sst_table.columns.alignment = BeautifulTable.ALIGN_RIGHT
        sst_table.headers = (["Field", "Value"])
        sst_table.rows.append(["Field", "Value"])

        sst_offset = re.search(rb'\xfc\x00[\x00-\xff]{2}', data)
        sst_sector_size = struct.unpack("<h", data[sst_offset.start( ) +2:sst_offset.start( ) +4])[0]

        if sst_sector_size > 0:

            sst_table.rows.append(["SST offset in file", str(hex(sst_offset.start()))])
            sst_table.rows.append(["SST sector size", str(sst_sector_size)])

            sst_strings_offset = sst_offset.start() + 12
            sst_table.rows.append(["SST strings offset", str(hex(sst_strings_offset))])

            sst_chunk = data[sst_strings_offset:sst_strings_offset + sst_sector_size]

            # carve each string by string length:
            test = sst_chunk[:3]

            sst_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            print(sst_table)

            try:
                str_length = struct.unpack("<hb", test)[0]

                print("Length of first string: %d" % str_length)
                first_string = sst_chunk[3:3 + str_length]
                try:
                    print(first_string.decode('utf-8'))
                except UnicodeDecodeError:
                    pass

                offset = 0
                while True:

                    curr_str_start = offset
                    try:
                        curr_str_start += str_length + 3
                        offset = curr_str_start

                        test = sst_chunk[offset:offset + 3]
                        str_length = struct.unpack("<hb", test)[0]

                        print("String Length: %d" % str_length)

                        string = sst_chunk[offset + 3:offset + str_length + 3]
                        try:
                            print(string.decode('utf-8'))
                        except UnicodeDecodeError:
                            continue

                    except IndexError:
                        break

            except struct.error:
                return 0
        else:
            print("[-] Couldn't find a valid Shared Strings Table...")

            
