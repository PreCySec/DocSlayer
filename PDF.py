import re
import zlib
import hexdump
import binascii
from printy import *
from io import StringIO
from beautifultable import BeautifulTable

from RTF import RTF
from helpers import *
from helpers import Helpers
from OLEParser import OLEParser


class PDF:
    """
    PDF() class will parse the PDF document file data and analyze each object separately.
    It will print a object table showing all the PDF objects and their types.
    Run multiple checks for common PDF weaponizing vectors.

    """

    # the Helpers() class holds all regular expressions and required helper functions
    helpers = Helpers()

    def __init__(self, data):
        self.data = data

    def enum_objects(self, data):

        """
        Enumerate all objects in the PDF document.
        The main method in the class, running all other methods.
        Analyzes each object separately using the PDF() methods.
        """

        # Prepare PDF object table before populating it
        obj_table = BeautifulTable(maxwidth=100)
        obj_table.headers = (["Object", "Type"])
        obj_table.rows.append(["Object", "Type"])

        printy("\n[bw][+] Enumerating PDF objects@")
        # Extract all objects to a list for later processing
        objects = re.findall(self.helpers.obj_regex, data)

        # Print a short list of all objects and their types before analyzing each object
        self.print_obj_short(objects, obj_table)

        # The previous function populated the objects table, no print it to the terminal
        obj_table.columns.alignment = BeautifulTable.ALIGN_LEFT
        print(obj_table)

        # Loop over all objects. Each "obj" the object binary string (b'').
        for obj in objects:
            readable_obj = ""
            for char in obj:
                # Add each char to the readable_obj string to later pretty-print the object.
                readable_obj += chr(char)

            # Carve the object number from the object binary string.
            obj_num_bin = obj[:2]
            printy("\n\n[bw]Object %s:@" % obj_num_bin)
            print("=" * len("Object %s:" % obj_num_bin))
            printy("[y][+] Readable object (first 1,000 bytes):@\n")

            # Check obj size before printing to avoid overflowing the terminal
            if len(readable_obj) > 1000:
                print(readable_obj[:1000])
            else:
                print(readable_obj)

            # Extract all URIs to list
            uris = self.extract_uri(obj)

            # If there are any /URI in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for uri in uris:

                printy("[r>][+] Found URI in object %s:@\n%s" % (obj_num_bin, uri.decode('utf-8')))
                summary_string = raw_format("Found URI in object %s:@" % obj_num_bin)
                summary_desc = "%s" % uri.decode('utf-8')
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Extract all embedded files ("\EmbeddedFile") to list
            emb_files = self.find_emb_files(obj)
            # If there are any /EmbeddedFile in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for emb_file in emb_files:

                printy("\n[r>][+] Found embedded file in object %s:@\n%s" % (obj_num_bin, emb_file.decode('utf-8')))
                summary_string = raw_format("Found embedded file in object %s:@" % obj_num_bin)
                summary_desc = "%s" % emb_file.decode('utf-8')
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Find object streams
            obj_stm = self.find_objstm(obj)

            # If there are any /ObjStm in the document, it will enter the for loop to log it and add it to the
            # summary table.
            for stm in obj_stm:
                printy("\n[r>][+] Found object stream (ObjStm) in object %s:@\n%s" % (obj_num_bin, stm.decode('utf-8')))
                summary_string = raw_format("Found object stream (ObjStm) in object %s:@" % obj_num_bin)
                summary_desc = "%s" % stm.decode('utf-8')
                self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)

            # Run additional checks on the object data.

            # find JavaScript references from one object to another
            self.find_js_reference(obj, obj_num_bin)

            # find /OpenAction
            self.open_action(obj, obj_num_bin)

            # find /Launch
            self.find_launch(obj, obj_num_bin)

            # find /FileSpec
            self.find_filespec(obj)

            # find "this.exportDataObject" (embedded files)
            self.find_export_data_obj(obj)

            # This function will check if there is a potential hex blob that can be decoded to see if there is any
            # interesting data or files.
            self.validate_hex_data(obj)

            # Find potential UNC paths (shares) - can indicate NTLM hash leaking via connecting to a attacker
            # controlled SMB share (sends NTLM hash to target as part of authentication)
            self.find_unc_path(data, obj_num_bin)

            # Find GoTo references (file/object within the document, remote or embedded object)
            self.find_goto_ref(data, obj_num_bin)

            # Find /SubmitForm - a form which will send data to a URL
            self.find_submitform(data, obj_num_bin)

            # If there is a stream in the object
            if b"stream" in obj:
                # Extract the stream contents from the object.
                stream_data = re.findall(self.helpers.stream_regex, obj)[0]

                # Try to LZW decompress it
                try:
                    decompressed = self.lzw_decode(stream_data)
                    printy('\n[y][+] Decompressed stream (LZW decompression):@')
                    print(decompressed)

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if self.helpers.determine_mimetype(decompressed) == 'rtf':
                        rtf = RTF(decompressed)
                        summary_string = raw_format("[r>]Embedded document@")
                        summary_desc = "Found RTF document"
                        self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(decompressed)
                        rtf.search_ole_obj(clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif self.helpers.determine_mimetype(decompressed) == 'ole':
                        ms_ole = OLEParser(decompressed)
                        f = open("ole_temp.bin", "r+b")
                        f.write(decompressed)
                        ms_ole.extract_embedded_ole(f.name, f.name)
                        f.close()

                except AttributeError:
                    pass

                decompressed = self.flate_decode(stream_data, obj_num_bin)
                mimetype = self.helpers.determine_mimetype(decompressed)
                try:
                    # Check if there is any code in the object. If there is, print the entire object
                    if b"var " in decompressed or b"function" in decompressed:
                        print(decompressed.decode('utf-8'))
                    else:
                        print(decompressed[:1000])

                        # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                        # the RTF document.
                        if mimetype == 'rtf':
                            rtf = RTF()
                            summary_string = raw_format("[r>]Embedded document@")
                            summary_desc = "Found RTF document"
                            self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                            clean = rtf.clean_hex_data(decompressed)
                            rtf.search_ole_obj(clean)

                        # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                        # analysis of the OLE file.
                        elif mimetype is 'ole':
                            ms_ole = OLEParser(data)
                            with open("ole_temp.bin", "ab") as f:
                                f.write(decompressed)
                                ms_ole.extract_embedded_ole("ole_temp.bin", "ole_temp.bin")
                                f.close()
                except TypeError:

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if mimetype == 'rtf':
                        rtf = RTF()
                        summary_string = raw_format("[r>]Embedded document@")
                        summary_desc = "Found RTF document"
                        self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(decompressed)
                        rtf.search_ole_obj(clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif mimetype is 'ole':
                        ms_ole = OLEParser(data)
                        f = open("ole_temp.bin", "ab")
                        f.write(decompressed)
                        ms_ole.extract_embedded_ole("ole_temp.bin", "ole_temp.bin")
                        f.close()
                except UnicodeError:
                    # If .decode('utf-8') on the decompressed data failed
                    print(decompressed)

                    # If decompression succeeded and the file is RTF, initiate the RTF class for inline analysis of
                    # the RTF document.
                    if mimetype == 'rtf':
                        rtf = RTF()
                        summary_string = raw_format("[r>]Embedded document@")
                        summary_desc = "Found RTF document"
                        self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                        clean = rtf.clean_hex_data(decompressed)
                        rtf.search_ole_obj(clean)

                    # If decompression succeeded and the file is OLE, initiate the OLEParser class for inline
                    # analysis of the OLE file.
                    elif mimetype is 'ole':
                        ms_ole = OLEParser(data)
                        f = open("ole_temp.bin", "r+b")
                        f.write(decompressed)
                        ms_ole.extract_embedded_ole(f.name, f.name)
                        f.close()
                #try:
                #    printy("\n[y][+] Hex View@")
                #    print(hexdump.hexdump(decompressed)[:2000])
                #except TypeError:
                #    pass


    def print_obj_short(self, objects, obj_table):

        """
        Prints a short list of the objects and their types..
        """

        for obj in objects:
            headers = re.findall(self.helpers.obj_header, obj)
            for header in headers:
                try:
                    obj_table.rows.append(["Object %s" % obj[:2].decode('utf-8'), header.decode('utf-8')])
                except UnicodeError:
                    try:
                        obj_table.rows.append(["Object %s" % obj[:2].decode('utf-8'), header])
                    except UnicodeError:
                        obj_table.rows.append(["Object %s" % obj[:2], header])

    def flate_decode(self, data, obj_num_bin):

        """
        Decompresses Zlib Inflated streams.
        """
        try:
            data = data.strip(b'\r\n')
            decompressed = zlib.decompress(data)  # Here you have your clean decompressed stream
            printy("\n[y][+] Decompressed stream (Zlib Inflate):@\n")
            decomp_file = "decompressed_obj_%s" % obj_num_bin
            f = open(decomp_file, "w+b")
            f.write(decompressed)
            f.close()
            return decompressed
        except zlib.error as e:
            print(e)
            return 0

    def lzw_decode(self, data):

        """
        Decompresses LZW compressed streams.
        """
        # Build the dictionary.
        dict_size = 256
        dictionary = dict((i, chr(i)) for i in range(dict_size))
        result = StringIO()
        w = chr(data.pop(0))
        result.write(w)
        for k in data:
            if k in dictionary:
                entry = dictionary[k]
            elif k == dict_size:
                entry = w + w[0]
            else:
                raise ValueError('Bad compressed k: %s' % k)
            result.write(entry)

            # Add w+entry[0] to the dictionary.
            dictionary[dict_size] = w + entry[0]
            dict_size += 1

            w = entry
        return result.getvalue()

    def find_export_data_obj(self, data):
        """
        Another approach to find embedded files - this.exportDataObject().
        """
        export_data_objects = re.findall(self.helpers.export_data_regex, data)
        for exp in export_data_objects:
            printy("\n[r>][+] Found embedded file/object:@")
            print(exp.decode('utf-8'))
            self.helpers.add_summary_if_no_duplicates("Found embedded file/object", exp.decode('utf-8'))
            break

    def find_filespec(self, data):
        """
        Find embedded files - /FileSpec
        """
        if re.findall(self.helpers.filespec_regex, data):
            filespec = re.findall(self.helpers.file_regex, data)
            for file in filespec:
                printy("\n[r>][+] Found file reference:@")
                print(file.decode('utf-8'))
                if b'downl.SettingContent-ms' in file:
                    printy("[r>][!] Possible abuse of SettingContent-ms file to download malicious content.@")
                    self.helpers.add_summary_if_no_duplicates("Found embedded file/object", file.decode('utf-8'))
                break

    def find_unc_path(self, data, obj_num_bin):
        """
        Find UNC paths (shares)
        Can indicate possible exploitation of CVE-2018-4993
        """
        unc = re.findall(self.helpers.unc_regex, data)
        for p in unc:
            printy("\n[r>][!] Found UNC path (possible Adobe Reader NTLM hash leak vulnerability CVE-2018-4993) "
                   "in object %s, to path: %s@" % (obj_num_bin, p))
            self.helpers.add_summary_if_no_duplicates(raw_format('[r>]Found UNC path (possible Adobe Reader NTLM '
                                                                 'hash leak vulnerability CVE-2018-4993)@'), p)

    def extract_uri(self, data):
        """
        Find /URI
        """
        uris = re.findall(self.helpers.uri_regex, data)
        return uris

    def find_emb_files(self, data):
        """
        Find /Type /EmbeddedFile
        """
        emb_files = re.findall(self.helpers.emb_file_regex, data)

        if re.findall(self.helpers.emb_file_regex, data):
            printy("\n[r>][+] Found file reference:@")
            file_ref = re.findall(self.helpers.file_ref_regex, data)
            for file in file_ref:
                print(file.decode('utf-8'))
                if b'downl.SettingContent-ms' in file:
                    printy("[r>][!] Possible abuse of SettingContent-ms file to download malicious content.@")
                break
        return emb_files

    def find_objstm(self, data):
        """
        Find /Objstm
        """
        emb_files = re.findall(self.helpers.objstm_regex, data)
        return emb_files

    def find_js_reference(self, data, obj_num_bin):
        """
        Find "/JS <obj_num> 0 R" - references to objects with JavaScript
        """
        js_ref_regex = re.compile(self.helpers.js_ref_pattern)
        for match in re.finditer(js_ref_regex, data):
            referred_obj = data[match.span(0)[0]:match.span(0)[1]][12:14]
            printy("\n[r>][!] Found JS reference in object %s, to object %s@" % (obj_num_bin, referred_obj))


    def open_action(self, data, obj_num_bin):

        """
        Find "/AA and /OpenAction" - automatic actions that are executed when the document is opened.
        """
        # /AA and /OpenAction
        aa_regex = re.compile(self.helpers.auto_action_pattern)
        openaction_regex = re.compile(self.helpers.open_action_regex)
        o_regex = re.compile(self.helpers.o_regex)

        for match in re.finditer(aa_regex, data):
            printy("\n[r>][!] Found automatic action /AA in object %s@" % obj_num_bin)

        for match in re.finditer(openaction_regex, data):
            printy("\n[r>][!] Found OpenAction in object %s@" % obj_num_bin)

        for match in re.finditer(o_regex, data):
            printy("\n[r>][!] Found /O actions dictionary in object %s" % obj_num_bin)

        for match in re.finditer(self.helpers.open_a_ref_regex, data):
            referred_obj = data[match.span(0)[0]:match.span(0)[1]][12:14]
            printy("[r>][!] Found OpenAction reference in object %s, to object: %s@" % (obj_num_bin, referred_obj.decode('utf-8')))

    def find_launch(self, data, obj_num_bin):
        """
        Find "/Launch" - execute other applications.
        """
        # /Launch
        aa_regex = re.compile(self.helpers.auto_action_pattern)
        for match in re.finditer(aa_regex, data):
            printy("\n[r>][!] Found \"/Launch\" in object %s@" % obj_num_bin)
            print(match)

    def find_goto_ref(self, data, obj_num_bin):

        """
        Find /GoTo* references:
        GoTo: “Go-to” a destination within the document
        GoToR: “Go-to remote” destination
        GoToE: “Go-to embedded” destination
        """
        try:
            goto_ref = re.findall(self.helpers.goto_regex, data)[0]
        except IndexError:
            return 0
        else:
            for ref in goto_ref:
                printy("\n[r>][!] Found \"/Goto*\" in object %s@" % obj_num_bin)
                print(ref)

    def find_submitform(self, data, obj_num_bin):
        """
        Find /SubmitForm
        """
        try:
            submit_form = re.findall(self.helpers.submitform_regex, data)[0]
        except IndexError:
            return 0
        else:
            for sub in submit_form:
                printy("\n[r>][!] Found \"/SubmitForm\" in object %s@" % obj_num_bin)
                print(sub)


    def validate_hex_data(self, data):
        """
        Attempts to clean hex data found in "ASCIIHexDecode streams.
        If there is valid hex data, it is decoded and the magic bytes are checked.
        If the decoded data is an OLE or RTF file, maldoc_parser will recursively analyze the data using the OLEParser
        or RTF classes.
        """
        if b'ASCIIHexDecode' in data or b'ASCII85HexDecode' in data:
            try:
                stream_data = re.findall(self.helpers.stream_regex, data)[0]
            except IndexError:
                return 0
            else:
                # check if there are any non-hexadecimal characters in the stream data.
                clean = re.sub(b' ', b'', stream_data)
                clean = re.sub(b'\r\n', b'', clean)
                test = re.findall(rb'^[A-Fa-f0-9]+', clean)
                for hex in test:
                    if len(hex) > 1:
                        print(binascii.unhexlify(test[0]).decode('utf-8'))
                        hex_data = binascii.a2b_hex(hex)
                        chunk = hex_data[:4]
                        if b'\\rt' in chunk:
                            rtf = RTF(hex_data)
                            summary_string = raw_format("[r>]Embedded document@")
                            summary_desc = "Found RTF document"
                            self.helpers.add_summary_if_no_duplicates(summary_string, summary_desc)
                            # Find and "clean" hex data
                            clean = rtf.clean_hex_data(hex_data)
                            # Search any OLE files and binary blobs in the "cleaned" hex data.
                            rtf.search_ole_obj(clean)
                        break

                        
