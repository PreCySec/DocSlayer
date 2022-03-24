import binascii
import re
import sys
import hexdump
# from capstone import *
from printy import *
from helpers import *
from helpers import Helpers
from beautifultable import BeautifulTable
from OLEParser import *
from OOXMLParser import *


class RTF:
    """
    The RTF() class parses and analyzes RTF documents.
    RTF document usually embed a malicious OLE object that can very from:
    - Equation Editor exploit (Eqution object containing shellcode or a shell command).
    - Office document (Excel/Word/PowerPoint) containing macros
    - Packages/scripts
    - PE files
    - etc.

    The class will:
    - Attempt to scan for hex data and construct all blobs it finds.
    - Print blobs to the console in hex
    - If it finds an OLE file, it will initiate the OLEParser class for recursive analysis
    - Gather indicators such as URLs, known code strings (scripts), PE magic bytes, etc.
    """
    helpers = Helpers()

    def __init__(self, data):
        self.data = data

    def clean_hex_data(self, data):
        """
        Remove all \x0d, \x0a, \x09 and \x20" bytes from RTF hex blobs.
        In many cases, the malicious RTF documents are embedded with hexadecimal data. The data is added with
        additional junk bytes that break its hexadecimal representation and need to be removed,

        """
        # rb"\x0d|\x0a|\x09|\x20"
        clean = re.sub(self.helpers.rtf_clean_regex, b"", data)
        return clean

    def search_ole_obj(self, data):
        """
        This is the main method in the class and executes the main functionality.
        It searches for embedded objects and arbitrary hex data and analyzes them.

        It will:
          - Analyze OLE files if it finds any and manages to parse them (ole blobs).
          - If failed parsing data as OLE, will process it as arbitrary blob (blobs).

        """
        # Extract OLE blobs (CFB header was detected in hex).
        ole_blobs = re.findall(self.helpers.rtf_ole_blob_regex, data)

        # Extract hex blobs, regardless of OLE magic.
        blobs = re.findall(self.helpers.rtf_binary_blob_regex, data)

        filename = "obj.bin"
        f = open(filename, "w+b")

        # Save lengths of lists.
        len_ole_blobs = len(ole_blobs)
        len_blobs = len(blobs)

        # Process OLE blobs
        self.analyze_ole_blob(ole_blobs, len_ole_blobs, filename)

        # Process arbitrary hex blobs.
        self.analyze_blob(blobs, len_blobs, f, filename, data)

    def analyze_ole_blob(self, ole_blobs, length, filename):
        """
        For each extracted OLE hex blob in the list (ole_blobs), unhexlifies and further analyzes it.

        """
        # Initial check if the list is empty.
        if length > 0:
            # Handle each object in the list.
            for obj in ole_blobs:
                # Verify if object has meaningful data/not empty.
                if obj is not b'' and len(obj) > 200:
                    try:
                        # Unhexlify object data ("01" --> b'\x01') and convert all to uppercase.
                        obj_data = binascii.unhexlify(obj.upper())
                    except Exception:
                        # Unhexlify and keep in lowercase.
                        obj_data = binascii.unhexlify(obj)

                    # Initiate the OLEParser() class with the object hex bytes.
                    ms_ole = OLEParser(obj_data)
                    f = open(filename, "w+b")
                    f.write(obj_data)


                    printy("\n[r>][!] Found \'d0cf11e0\' magic in the RTF file contents@")
                    printy("[y][+] Saved OLE file contents to: %s@" % f.name)

                    # Add indication of OLE magic bytes to final summary table.
                    summary_string = raw_format("[o>]OLE file magic bytes in file %s@" % filename)
                    summary_desc = "Found \'d0cf11e0\' magic in file: %s" % filename
                    self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

                    f.close()

                    # Start of OLE recursive static analysis.
                    print("\n" + ("=" * len("Starting analysis on OLE object")))
                    printy("[bw]Starting analysis on OLE object@")
                    print("=" * len("Starting analysis on OLE object"))

                    # Run OLEParser() methods on object.
                    ms_ole.extract_embedded_ole(f.name, f.name)

                    # Create file and write object's hex data to it.
                    self.prepare_blob_file(f, filename, obj_data)

    def analyze_blob(self, blobs, length, f, filename, data):
        """
        Any hex data that was found but was unsuccessfully parsed as OLE, will be handled by this method.

        Checks for Equation Editor fingerprints and any potential malicious code/scripts.
        Prints further recommendations on how to further examine arbitrary hex data.

        It has an auxiliary code section in the conditional flow that is triggered when initial hex blob extracting
        regular expressions failed to find any blobs.

        """
        # Initial check if the list is empty.
        if length > 0:
            printy("\n[bw][+] Starting analysis on binary streams@")
            # Flag is used to tell in general if any blobs were found.
            blob_flag = True

            # Flag is used to tell in general if any blobs were found.
            auxiliary_used = False

            # Iterate over each hex blob and analyze it.
            for blob in blobs:
                # Each blob is a list of smaller streams, therefore, iterate over each stream in the inline list.
                for b in blob:
                    # Save stream length.
                    b_len = len(b)

                    # Only process blobs that have enough data to be meaningful.
                    if b_len > 200:
                        try:
                            blob_data = binascii.unhexlify(b.upper())
                        except binascii.Error:
                            # Could not unhexlify uppercase data.
                            try:
                                # Unhexlify in lowercase.
                                blob_data = binascii.unhexlify(b)
                            except binascii.Error:
                                # Binascii could not unhexlify data because its length is not even (len(b) % 2 != 0)
                                # Therefore, check if auxiliary code was used before proceeding to it.
                                if auxiliary_used:
                                    break

                                # Auxiliary Code:
                                # ---------------
                                # Triggered when initial hex blob extracting regular expressions failed to find any
                                # blobs.

                                # Set flag that tells if auxiliary code was used to True.
                                auxiliary_used = True

                                # Use auxiliary regex to find hex blobs.
                                print("Using auxiliary regex to find data blobs...")
                                aux_regex = rb"[A-Z]\}([\x00-\x66]+)\{\\|[A-Z]\}|[a-z]([\x00-\x66]+)"
                                aux_matches = re.findall(aux_regex, data)

                                # Iterate over matches from the auxiliary regex.
                                for t in aux_matches:
                                    # Each match is a list, therefore have to add another for loop...
                                    for m in t:
                                        # Process blobs that have enough data to be meaningful.
                                        if len(m) > 200:
                                            try:
                                                # Convert hex to UPPERCASE and unhexlify.
                                                blob_data = binascii.unhexlify(m.upper())

                                                # Print blob in hex view, search functions, extract ASCII/wide
                                                # char strings. Then Create file and write blob data to it.
                                                self.arbitrary_blob_analysis(f, filename, blob_data)
                                            except binascii.Error:
                                                # Could not unhexlify hex data in uppercase
                                                try:
                                                    # Unhexlify hex data as lowercase.
                                                    blob_data = binascii.unhexlify(m)
                                                except binascii.Error:
                                                    print("\n[-] binascii error: hex data length is not an even "
                                                          "number... probably missing a character to make data hex "
                                                          "readable.")
                                                    # Print blob data anyway.
                                                    print(m)
                                                    continue
                                                else:
                                                    # Hex data was successfully unhexlified in lowercase.
                                                    # Print blob in hex view, search functions, extract ASCII/wide
                                                    # char strings. Then Create file and write blob data to it.
                                                    self.arbitrary_blob_analysis(f, filename, blob_data)
                            else:
                                # Hex data was successfully unhexlified in lowercase and now is analyzed.
                                # Print hex view of blob, search for Equation Editor exploit, extract ASCII/wide char
                                # strings
                                self.arbitrary_blob_analysis(f, filename, data)

                        else:
                            # Hex data was successfully unhexlified in UPPERCASE and now is analyzed.
                            # Print hex view of blob, search for Equation Editor exploit, extract ASCII/wide char
                            # strings
                            self.arbitrary_blob_analysis(f, filename, blob_data)

            if blob_flag:
                # Add to summary table if any blobs were found.
                summary_string = raw_format("[o>]Arbitrary Data (Possibly shellcode)@")
                summary_desc = "A binary stream of bytes was found in the RTF document.\n" \
                               "It was not detected as an OLE file.\n" \
                               "You should check the printed disassembly to verify if there is some shellcode.\n\n" \
                               "- Paste the contents of \"obj.bin\" (tool's directory) in CyberChef (\"from x86 " \
                               "disassemble\" as filter).\n" \
                               "--- Change to \"x86\" in the disassembly mode.\n" \
                               "- You can use any quick online/offline disassembler you are femiliar with.\n" \
                               "- If identified as shellcode:\n--- Run in a debugger using an emulator " \
                               "(like \"blob_runner.exe\" utility).\n" \
                               "--- *** This requires you to know the start offset of the shellcode in the data " \
                               "and carve " \
                               "it out manually.\n--- If it is Equation Editor exploit shellcode, EQNEDT32.exe needs " \
                               "to be debugged in x86 mode."

                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

    def arbitrary_blob_analysis(self, f, filename, data):
        """
        This method takes hex data after it was unhexlified and analyzes it.

        Relevant only for arbitrary hex blobs.
        Blobs that were identified as OLE files will be processed using the OLEParser() class.

        """
        # Print hex view of the blob data.
        print(hexdump.hexdump(data))

        # Initiate the OLEParser() class with the blob data.
        ms_ole = OLEParser(data)

        # Extract and decode ASCII / wide char strings.
        ms_ole.extract_unicode_and_ascii_string(f.name, data)

        # Search for Equation Editor exploit fingerprints.
        self.search_eqnedt32(data, filename)

        # Check for functions in data.
        if b'Function' in data or b'Sub ' in data:
            func_regex = rb'Function [a-zA-z0-9]{3,20}'
            func_string = re.findall(func_regex, data)

            summary_string = raw_format("[o>]Scripting in file:@ %s" % filename)
            summary_desc = "Possible function detected in stream: %s" % func_string
            self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

        # Create file and write blob data to it.
        self.prepare_blob_file(f, filename, data)

    def prepare_blob_file(self, f, filename, data):
        """
        Creates the hex blob file on disk and writes the data to it.
        Closes the file when finished.

        Used both for OLE object and arbitrary hex blobs.

        """
        if f.closed:
            f = open(filename, "w+b")
        f.write(data)
        f.close()
        # os.remove(f.name)

    """
    def disassembly(self, data):
    """
    #    Disassembles hex data as opcodes/byte code.
    #    Uses the Capstone engine.

    """
        try:
            print("\nDisassembly: %s\n--------------------------" % ("".join(f.name)))
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            disassembly = md.disasm(data, 0x00)
            for i in disassembly:
                if i.mnemonic is "jmp" and int(i.op_str, 16) < 4096:
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                else:
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        except Exception:
            print(sys.exc_info()[1])
    """

    def search_eqnedt32(self, data, filename):
        """
        Search Equation Editor exploit fingerprints in hex blobs.

        """
        equation = re.findall(self.helpers.equation_byte_regex, data)
        equation1 = re.findall(self.helpers.equation_regex, data)
        summary_desc = ""
        if equation or equation1:
            summary_string = raw_format("[r>]Indication of Equation Editor exploit "
                                        "(CVE-2017-11882) in stream:@ %s" % filename)

            if equation:
                summary_desc = "Found \'%s\' in binary data stream" % equation

            if equation1:
                summary_desc = "Found \'%s\' in binary data stream" % equation1

            self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

    def search_pe_file(self, data):
        """
        Not in use yet..
        Will be used to search PE signatures in hex blobs.

        """
        mz_only = re.findall(data, self.helpers.pe_header_regex)
        pe_header = re.findall(data, self.helpers.pe_magic_str)

        for s in mz_only:
            print(s)
        for y in pe_header:
            print(y)
