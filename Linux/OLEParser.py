import re
import os
import sys
import olefile
import binascii
import msoffcrypto
# from capstone import *
from printy import *
from beautifultable import BeautifulTable

from DocParser import *
from XLSParser import *
from helpers import Helpers
from VBADecompress import VBADecompress


class OLEParser:
    """
    The OLEParser class will parse an OLE object and conduct an extensive static analysis on its streams/storages.
    Extracts VBA, embedded objects, Excel 4 macros, strings, and more.
    Can detect Equation Editor exploits.

    Has a dedicated parser for OLE Excel files (XLSParser())
    - Parse BOF records (Beginning of File headers)
    - Parse BOUNDSHEET records (sheets)
    - Detect hidden sheets via BOUNDSHEET records
    - Detect if a sheet has XLM macros via BOUNDSHEET records
    - Extract strings from sheets.
    - Extract Shared Strings Table strings.

    """
    def __init__(self, data):
        self.data = data

    helpers = Helpers()

    def parse_cfb_header(self, data):
        """
        https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml

        CFB header:
        Header Signature for the CFB format with 8-byte Hex value D0CF11E0A1B11AE1. Gary Kessler notes that the
        beginning of this string looks like "DOCFILE".

        CFB header (Compund File Binary)
          -  16 bytes of zeroes
          -  2-byte Hex value 3E00 indicating CFB minor version 3E
          -  2-byte Hex value 0300 indicating CFB major version 3 or value 0400 indicating CFB major version 4. [Note:
          All XLS files created recently by compilers of this resource (in versions of Excel for MacOS and Windows) and
          examined with a Hex dump utility have been based on CFB major version 3. Comments welcome.]
          -  2-byte Hex value FEFF indicating little-endian byte order for all integer values. This byte order applies
           to all CFB files.
          -  2-byte Hex value 0900 (indicating the sector size of 512 bytes used for major version 3) or 0C00
          (indicating the sector size of 4096 bytes used for major version 4)
          -  480 bytes for remainder of the 512-byte header, which fills the first sector for a CFB of major version 3
          -  For a CFB of major version 4, the rest of the first sector, 3,584 bytes of zeroes

        """
        # Prepare CFB header table.
        cfb_table = BeautifulTable(maxwidth=100)
        cfb_table.headers = (["Field", "Value"])

        printy("[bw]\nCFB (compound file binary) Header:@")
        print("=" * len("CFB (compound file binary) Header:"))

        # Carve CFB header magic bytes from data.
        cfb_header = data[:8]
        cfb_table.rows.append(["CFB Header magic", cfb_header])

        # Parse CFB header minor version
        cfb_minor_version = data[24:26]
        if str(binascii.hexlify(cfb_minor_version)) == "3E00":
            print("   CFB Minor Version: (Version 3E / 0x3E)", cfb_minor_version)
            cfb_table.rows.append(["CFB Minor Version", "Version 3E / 0x3E)@" + str(cfb_minor_version)])

        # Parse CFB header major version
        cfb_major_version = data[26:28]
        if str(binascii.hexlify(cfb_major_version)) == "3000":
            cfb_table.rows.append(["CFB Major Version", "(Version 3 / 0x3)" + str(cfb_major_version)])

        if cfb_major_version == b'\x03\x00':
            cfb_table.rows.append(["CFB Minor Version", "Little-endian integers (0x3)"])

        # Parse CFB sector size.
        sector_size = data[30:32]
        if sector_size == b'\x09\x00':
            # remainder = data[32:512]  # in major version 3.
            cfb_table.rows.append(["CFB sector length", "512 bytes"])
            cfb_table.rows.append(["CFB sector remainder size", "480 bytes - in major version 3 (512 -32)"])

        elif sector_size == b'\x0c\x00':
            # remainder = data[32:4096]  # in major version 4 (512 + 3,584).
            cfb_table.rows.append(["CFB sector length", "4096 bytes"])
            cfb_table.rows.append(["CFB sector remainder size", "4,064 bytes - in major version 3 (4096 -32)"])

        # Prepare and print CFB header table.
        cfb_table.columns.alignment = BeautifulTable.ALIGN_LEFT
        print(cfb_table)

    def extract_embedded_ole(self, stream_name, fname):
        """
        The main method of OLEParser().
        Executes all OLE related analysis methods

        """
        stream_table = BeautifulTable()
        stream_table.headers = (["Stream", "Comments"])
        stream_table.maxwidth = 500

        try:
            # Parse input file as OLE to analyze its streams/storages.
            ole = olefile.OleFileIO(fname)
            print("=" * (len(stream_name)+34))
            printy("[bw]Analyzing streams in OLE file: %s@" % stream_name)
            print("=" * (len(stream_name)+34))

            # Read input file data.
            file_data = open(fname, "rb").read()

            # Iterate over each stream in the OLE file.
            for stream in ole.listdir():
                printy("\n[bw]Analyzing stream: %s@" % "\\".join(stream))
                print("=" * (len("\\".join(stream))+18))

                # Check if document is protected.
                if 'StrongEncryptionDataSpace' in stream or "Encryption" in stream or "EncryptedPackage" in stream:
                    print("[!] Document is protected.\n[+] Starting decryption function.")
                    # Attempt decryption using known default password "VelvetSweatShop".
                    self.decrypt_cdfv2(fname)

                # Open current stream and read its data.
                ole_stream = ole.openstream(stream)
                stream_data = ole_stream.read()

                # Search for Equation Editor fingerprints.
                self.eqnedt32_detect(stream, stream_data, file_data)

                # Look and process embedded/internal files.
                self.inline_ole(stream, stream_data)

                for s in stream:
                    if str(s) not in stream[:len(stream) - 1]:
                        # Extract and decompress VBA macros from stream data.
                        decompress_obj = VBADecompress(stream_data)
                        decompressed = decompress_obj.SearchAndDecompress(stream_data)

                        if decompressed == 0:
                            # Nothing was decompressed, no VBA macros in stream.

                            # Ignore default/special streams.
                            if "CompObj" not in s and "Summary" not in s:
                                # Create temp file for analysis.
                                f = open("test.bin", "ab")
                                f.write(stream_data)
                                printy("\n[y][+] Extracting generic strings from stream: %s@" % s)

                                # Extract strings from stream.
                                self.extract_unicode_and_ascii_string(s, stream_data)

                                # Close and remove temp file.
                                f.close()
                                os.remove(f.name)
                        else:
                            # VBA macros were detected.
                            printy("\n[r>][+] VBA Macros Detected:@")

                            # VBA macros output filename.
                            outfile_name = s + "_vbamacros"

                            # Prepare content for printing and tables.
                            print_string = raw_format("[r>]Found VBA macros in stream \'%s\'@\nSaving VBA macros from to file: %s\n---------@\n%s@" \
                                           % (str("\\".join(stream)), outfile_name, decompressed))

                            summary_string = raw_format("[r>]Found VBA macros in stream \'%s\\%s\'@" % (
                            str(stream_name), str("\\".join(stream))))

                            # Print VBA indication for static analysis report.
                            print(summary_string)

                            # Print VBA macros.
                            printy("[BI]" + decompressed + "@")

                            # Scan macros code against known function names and keywords.
                            self.helpers.find_susp_functions_vba(stream, decompressed)

                            # Add VBA macros indication to final summary table.
                            self.helpers.add_summary_if_no_duplicates(summary_string, decompressed[:100])

                            # Add indication to analysis report stream table.
                            stream_table.rows.append([str("\\".join(stream)), print_string])

                            # Write VBA macro to output file.
                            try:
                                with open(outfile_name, "x") as vba_out_file:
                                    vba_out_file.write(decompressed)
                                    vba_out_file.close()
                            except OSError:
                                pass
                    else:
                        continue
            stream_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            #print(stream_table)

        except OSError as e:
            #printy("[r>][-] %s: %s@" % (fname, e))
            #printy("[r>][-] Failed parsing OLE object (fragmented/corrupted)@")
            #printy("[r>][-] Indicates that an OLE file header was parsed but the data is fragmented and was not fully "
            #       "constructed@")
            #printy("[r>][-] If you didn\'t see the CFB (Compound File Binary) header parsed prior to this error "
            #       "- not an OLE file. ***@")
            #self.helpers.add_summary_if_no_duplicates()
            pass

    def eqnedt32_detect(self, stream, stream_data, file_data):
        """
        Detect Equation Editor exploit:
        - Scans objects for Equation object CLSID.
        - Scans for Equation known keywords.

        """
        eqedit32 = re.findall(self.helpers.EQ_EDIT_CLSID_RE, stream_data)
        equation_editor = re.findall(self.helpers.EQUATION_EDITOR_RE, stream_data)

        if (eqedit32 or equation_editor) and len(stream_data) > 50:
            printy("[r>][!] Indication of Equation Editor exploit detected in stream:@ % s " % "".join(stream)[1:].strip('\x01'))
            # md = Cs(CS_ARCH_X86, CS_MODE_32)
            if bool(eqedit32) and bool(equation_editor):
                summary_string = raw_format("[r>]Detected Equation Editor CLSID@\n")
                summary_desc = 'Equation Editor\n%s\nPossible exploitation of CVE-2017-11882 in stream: %s\n' \
                               '%s\nCLSID: %s' % ("".join(stream).strip('\x01'),stream, equation_editor[0], eqedit32[0])
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            elif eqedit32:
                summary_string = raw_format("[r>]Indication of Equation Editor CLSID@.\n Possible exploitation of CVE-2017-11882 in " \
                                 "stream: %s" % stream)
                summary_desc = 'Equation Editor\n\'%s\'' % "".join(stream).strip('\x01')
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            elif equation_editor:
                summary_string = "Detected Equation Editor CLSID.\n Possible exploitation of CVE-2017-11882 in " \
                                 "stream: %s\n\'%s\'" % \
                                 (stream, equation_editor[0])
                summary_desc = 'Equation Editor\n\'%s\'' % "".join(stream).strip('\x01')
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            if "CompObj" not in "".join(stream):
                print("[!] Possible Equation Editor exploit in stream: %s" % "".join(stream).strip('\x01'))

                # print("\nDisassembly: %s\n--------------------------" % ("".join(stream)))
                # disassembly = md.disasm(stream_data, 0x00)

                # for i in disassembly:
                #    if i.mnemonic is "jmp" and int(i.op_str, 16) < 4096:
                #        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                #    else:
                #        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def extract_unicode_and_ascii_string(self, filename, data):
        """
        Extract ASCII and wide char strings.

        """
        unicode_final_decoded = ''
        ascii_final_decoded = ''

        # wide char string matches.
        unicode_matches = re.findall(self.helpers.unicode_regex, data)

        # ASCII string matches.
        ascii_matches = re.findall(self.helpers.ascii_regex, data)

        printy("\n\n[y][+] Decoded UNICODE bytes from stream:@")

        # Join all strings into one string.
        for match in unicode_matches:
            unicode_final_decoded += match.decode('utf-8')

        # split strings properly.
        splitted_strings = unicode_final_decoded.split(" ")

        # print strings.
        for str in splitted_strings:
            print(str)

        printy("\n[y][+] Decoded ASCII bytes from stream:@")
        f = open("data.txt", "a")

        # print strings.
        for match in ascii_matches:
            ascii_final_decoded += match.decode('utf-8')

            if len(match.decode('utf-8')) > 8:

                if len(match) > 500:
                    # if string is long, write it to a file.
                    f.write(match.decode('utf-8'))
                    print(match.decode('utf-8')[:50])
                    self.helpers.search_indicators_in_string(filename, match.decode('utf-8')[:1000])

                else:
                    print(match.decode('utf-8'))
                    self.helpers.search_indicators_in_string(filename, match.decode('utf-8'))
        f.close()

        # Print final ASCII strings.
        if len(ascii_final_decoded) > 2000:
            print(ascii_final_decoded[:1000])
        else:
            print(unicode_final_decoded)

        # Search base64 encoded strings.
        base64_matches = re.findall(self.helpers.base64_regex, ascii_final_decoded)
        if base64_matches:
            summary_desc = []

            for m in base64_matches:
                if len(m) > 50:
                    summary_desc.append(m)

            if summary_desc:
                summary_string = raw_format("[y>][!] Possible Base64 encoded strings found in stream@")
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc[:20])

    def inline_ole(self, stream, stream_data):

        if len(stream_data):

            ole_regex = rb'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
            MICROSOFT_EXCEL = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x63\x65\x6c'
            MICROSOFT_OFFICE_WORD = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4f\x66\x66\x69\x63\x65\x20\x57\x6f\x72\x64'
            WORD_DOCUMENT = b'\x57\x6F\x72\x64\x2E\x44\x6F\x63\x75\x6D\x65\x6E\x74'

            if re.findall(ole_regex, stream_data):
                print("\n\n[!!!] Found OLE file %s!" % str("\\".join(stream)))
                summary_string = "Found OLE file %s" % str("\\".join(stream))
                summary_desc = "Embedded OLE file\n%s" % str("\\".join(stream))
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                self.parse_cfb_header(stream_data)

                with open("temp.bin", "ab") as f:

                    f.write(stream_data)
                    self.extract_embedded_ole(str("\\".join(stream)), f.name)
                    if MICROSOFT_EXCEL in stream_data:
                        xls_parser = XLSParser(stream_data)
                        xls_parser.parse_boundsheet_record(stream_data)
                        xls_parser.parse_bof_records(stream_data)
                        xls_parser.unhide_sheets(f.name)
                        # ms_ole.extract_strings(data)
                        xls_parser.extract_sheets(f.name)
                        decompress_obj = VBADecompress(stream_data)
                        decompressed = decompress_obj.SearchAndDecompress(stream_data)
                        xls_parser.parse_sst(stream_data)
                        f.close()
                        os.remove(f.name)
                        printy("\n\n[bc>][+] Continuing original file analysis:@\n" + "=" * 50)

                    elif MICROSOFT_OFFICE_WORD in stream_data or WORD_DOCUMENT in stream_data:
                        doc_parser = DocParser(stream_data)
                        print("\n\n[bc>][+] Continuing original file analysis:@\n" + "=" * 50)
                        pass
        else:
            pass

    def decrypt_cdfv2(self, filename):

        file = msoffcrypto.OfficeFile(open(filename, "rb"))

        # Use password (default password)
        file.load_key(password="VelvetSweatshop")
        decrypted_outfile = "DECRYPTED"

        try:
            file.decrypt(open(decrypted_outfile, "wb"))
            printy("    Used default password: VelvetSweatshop\n    [o>]Saved decrypted document to file: %s@\n"
                  "Please check the decrypted file, rerun the tool and use the decrypted file" % decrypted_outfile)
            #return decrypted_outfile
            exit(0)
        except msoffcrypto.exceptions.InvalidKeyError:
            print("[-] Could not decrypt protected document - password is not the default...\nRun the document in a sandbox")
            exit(0)
            return
