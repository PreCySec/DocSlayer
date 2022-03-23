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
        """
        unified = b''
        test_blobs_regex = re.compile(rb'[\}|\{]([\x00-\x66]+)[\}|\{]|[\}|\{]([\x00-\x76]+?)\}|[\}|\{]([\x00-\x66]+)\\')
        test_blobs = re.search(test_blobs_regex, data)
        for match in re.finditer(test_blobs_regex, data):
            blob = b""
            for b in list(match.groups()):
                if b is not None:
                    if b"\\" in b or b"^" in b or b"=" in b or b"{" in b or b"}" in b or b"*" in b or b"?" in b or \
                            b"%" in b or b":" in b or b">" in b or b"<" in b or b"#" in b or b"$" in b or \
                            re.findall(rb'[A-Z]', b):
                        continue
                    else:
                        unified += b
        """


        """
        STRONG OPTION:
        ==============
        
        temp = b""

        rtf_nests_regex = rb'[\{]{1,50}[\x00-\xff]+?[\}]{1,50}|\\\\|\''
        control_word_regex = rb'\\[a-z]+|\\\\[a-z]+|\\\\\*\\\\[a-z]+'
        special_chars_regex = rb'[@_!#$%^&*()<>?/\|}{~:\'\\\)\(\]\[\+\=\.]'
        junk_data_regex = rb'[g-zA-Z].*[g-zA-Z]'
        temp = re.sub(rtf_nests_regex, b'', data)
        temp = re.sub(rb'\\\\', b'', temp)
        temp = re.sub(rb'\\', b'', temp)
        temp = re.sub(rb'\'', b'', temp)
        #temp = re.sub(control_word_regex, b"", temp)
        temp = self.remove_control_words(temp)
        temp = re.sub(special_chars_regex, b"", temp)
        temp = re.sub(junk_data_regex, b"", temp)
        #temp = re.sub(rb'\\\\\*\\\\bin|\\\\\*\\\\field|\\x', b'', temp)
        temp = re.sub(rb'g-zG-Z', b'', temp)
        pass
        """

        # Extract OLE blobs (CFB header was detected in hex).
        ole_blobs = re.findall(self.helpers.rtf_ole_blob_regex, data)

        # Extract hex blobs, regardless of OLE magic.
        blobs = re.findall(self.helpers.rtf_binary_blob_regex_1, data)
        if len(blobs) > 90:
            blobs = re.findall(self.helpers.rtf_binary_blob_regex_2, data)

        filename = "obj.bin"
        f = open(filename, "w+b")

        # Save lengths of lists.
        len_ole_blobs = len(ole_blobs)
        len_blobs = len(blobs)

        # Process OLE blobs
        self.analyze_ole_blob(ole_blobs, len_ole_blobs, filename)

        # Process arbitrary hex blobs.
        self.analyze_blob(blobs, len_blobs, f, filename, data)

    def test(self, data):

        #rtf_control_words_regex = rb'(\\\*)?\\[a-z]+(-?[0-9]+)? ?'
        rtf_control_words_regex = rb"[\\\*]?\\[a-z]+[-?[0-9]+]? ?"
        RTF_START = 0
        RTF_EOF = len(data)
        EOF = False
        i = 0
        control_words = re.findall(rtf_control_words_regex, data)

        for i in range(0, len(control_words) - 1):

            word_hex_regex = rb'[a-f0-9]+$|[0-9]+$'
            word = control_words[i]

            try:
                word_hex = re.findall(word_hex_regex, word)

                if word_hex is []:
                    pass
                else:
                    if len(word_hex) > 5:
                        print(hexdump.hexdump(word_hex[0]))

            except Exception as e:
                print(e)

            word_length = len(word)
            word_last_char = word[word_length-1]

            if i is (len(control_words) - 1):
                EOF = True
            if EOF:
                break

            if chr(word_last_char) is "\\":
                continue

            print("\n[+] Control Word:\n%s" % word.decode('utf-8'))
            if data.find(word) is RTF_START + 1:
                continue

            section_start = data.find(control_words[i])
            try:
                section_end = data.find(control_words[i + 1])
            except IndexError:
                section_end = EOF - 1

            section_length = section_end - section_start

            if section_start < 0:
                print("[+] Section Length: %s" % section_length)
                print("[+] Section start Offset: %s" % section_start)
                print("\n")
            else:
                continue

            if section_end < 0:
                print("[+] Section End Offset: %s" % section_end)
                print("\n")
            else:
                print("\n")
                i += 1
                continue

        print("\n")
        print(len(control_words))
        print("\n")

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

                if b'a1b11ae100000000000000000000000000000000' in blob and b'd0cf11e' not in blob:
                    complete_ole = self.reconstruct_ole(blob)
                    blob_data = binascii.unhexlify(complete_ole.upper())
                    # print(hexdump.hexdump(blob_data[:1500]))
                    ms_ole = OLEParser(blob_data)
                    with open(filename, "wb") as f:
                        f.write(blob_data)
                        ms_ole.extract_embedded_ole(filename, filename)
                        continue

                # Each blob is a list of smaller streams, therefore, iterate over each stream in the inline list.
                # Only process blobs that have enough data to be meaningful.
                if len(blob) > 200:
                    try:
                        blob_data = binascii.unhexlify(blob.upper())
                    except binascii.Error:
                        # Could not unhexlify uppercase data.
                        try:
                            # Unhexlify in lowercase.
                            blob_data = binascii.unhexlify(blob)
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
                                self.arbitrary_blob_analysis(f, filename, blob_data)

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
        if len(data) < 2000:
            print(hexdump.hexdump(data))
        else:
            print(hexdump.hexdump(data[:2000]))

        # Initiate the OLEParser() class with the blob data.
        ms_ole = OLEParser(data)

        # Although failed to parse as OLE, try to see if it matches one of the object CLSIDs (identifiers).
        ms_ole.scan_clsid(data, filename)

        # Extract and decode ASCII / wide char strings.
        ms_ole.extract_unicode_and_ascii_string(f.name, data)

        # Search for Equation Editor exploit fingerprints.
        self.search_eqnedt32(data, filename)

        # Search for embedded file objects (packages).
        ms_ole.find_package(data)

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
        equation1 = re.findall(self.helpers.EQ_EDIT_CLSID_RE, data)
        summary_desc = ""
        if equation or equation1:
            summary_string = raw_format("[r>]Indication of Equation Editor exploit "
                                        "(CVE-2017-11882) in stream:@ %s" % filename)

            if equation:
                summary_desc = "Found \'%s\' in binary data stream" % equation

            if equation1:
                summary_desc = "Found \'%s\' in binary data stream" % equation1

            self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

    def reconstruct_ole(self, data):

        if b'a1b11ae100000000000000000000000000000000' in data:
            broken_ole_regex = re.compile(rb'a1b11ae1(00000000000000000000000000000000.*)')
            no_docfile_data = re.search(broken_ole_regex, data).group(1)
            complete = b'd0cf11e0a1b11ae1' + no_docfile_data
            return complete
        else:
            return None

    def remove_control_words(self, data):
        temp = data
        for word in self.helpers.RTF_CONTROL_WORDS:
            if word in temp:
                try:
                    re.sub(word, b"", temp)
                except re.error:
                    temp.strip(word)
        return temp

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
