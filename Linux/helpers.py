import re
import os
import sys
import hexdump
from printy import *
from beautifultable import BeautifulTable


class Helpers:
    """
    The Helpers() class has helper methods and regular expressions that are used by all other classes

    """
    summary_table = BeautifulTable(maxwidth=200)
    summary_table.headers = (["Indication", "Description"])
    summary_table.columns.width = 100

    # Magic byte regular expressions:
    #################################
    RTF = b'\x7b\x5c\x72\x74'
    OLE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    OOXML = b'\x50\x4b\x03\x04'
    PDF = b'%PDF-'

    # OLE related regular expressions:
    ##################################
    MICROSOFT_EXCEL = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x78\x63\x65\x6c'
    MICROSOFT_OFFICE_WORD = b'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x4f\x66\x66\x69\x63\x65\x20\x57\x6f\x72\x64'
    OLE_FILE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    EQ_EDIT_CLSID_RE = rb'\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
    # EQ_EDIT_CLSID_RE = rb'\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'
    EQUATION_EDITOR_RE = rb'\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x45\x71\x75\x61\x74\x69\x6f\x6e\x20\x33\x2e\x30'
    equation_regex = r'[[e|E][q|Q][u|U][a|A][t|T][i|I][o|O][n|N]]{8}'
    equation_byte_regex = rb'[\x65\x45\x71\x51\x75\x55\x61\x41\x74\x54\x69\x49\x6F\x4F\x6E\x4E]{8}'
    OLE_DDE_RE = rb'\x13\s*\x44\x44\x45\x41\x55\x54\x4f[^\x14]+'

    # OLE Excel files related regular expressions:
    ##############################################
    BOF_RECORD_RE = rb'\t\x08[\x08|\x10]\x00\x00[\x05|\x06][\x00-\xff]{6}'
    BOF_RECORDS_RE = rb'\t\x08[\x08|\x10]\x00\x00[\x05|\x06][\x00-\xff]{6}'
    EOF_BOF = rb"\x0a\x00\x00\x00\x09\x08"
    BOUNDHSEET_RECORD = rb'\x85\x00[\x01-\x88]\x00[\x00-\xff]{4}[\x00-\x02][\x00|\x01]'
    SHEET_NAME_1 = rb'\x85\x00[\x00-\xff]\x00[\x00-\xff]{5}[\x00|\x01]([\x00-\xff]{1,16})\x85\x00'
    SHEET_NAME_2 = rb'\x85\x00[\x00-\xff]\x00[\x00-\xff]{5}[\x00|\x01]([\x00-\xff]{1,12})'

    # RTF related regular expressions:
    ##################################
    rtf_clean_regex = rb"\x0d|\x0a|\x09|\x20"
    rtf_ole_blob_regex = rb"(\x64\x30\x63\x66\x31\x31\x65[\x00-\x66]+)\}"
    rtf_binary_blob_regex = rb"[A-Z]\}([\x00-\x66]+)\{\\|\x62\x69\x6e([\x00-\x66]+)\}|\}([\x00-\x66]+)\}|\x6d\x61\x74\x68([\x00-\x66]+)\}|\}([\x00-\x5b]+)|[\x61-\x7a]{3,20}([\x00-\x5b\x61-\x7a]+)\{|\\[\x00-\x5b\x61-\x7a]{3,5}([\x00-\x5b\x61-\x7a]+)"
    pe_header_regex = r"4d5a[a-z0-9]{100,500}546869732070726f6772616d"
    pe_magic_str = r"4d5a"

    # PDF related regular expressions:
    ##################################
    obj_regex = rb"\d{1,2} \d obj[\x00-\xff]+?endobj"
    obj_header = rb"\d{1,2} \d obj[\x00-\xff]<<[\x00-\xff]+?>>"
    export_data_regex = rb'this\.exportDataObject\((.*?)\)'
    filespec_regex = rb'/Type /Filespec|/Type/Filespec'
    file_regex = rb'/F \(.*?\)|/F\(.*?\)'
    unc_regex = rb'F\(\\\\\\\\\d{1,3}\.d{1,3}\.d{1,3}\.d{1,3}\\\\.*?\) 0 R'
    uri_regex = rb'URI \(.* ?\)|URI\(.* ?\)'
    emb_file_regex = rb'/Type /EmbeddedFile|/Type/EmbeddedFile'
    file_ref_regex = rb'F (\d{1,2}) 0 R'
    objstm_regex = rb'/Type /ObjStm'
    js_ref_pattern = rb'JS (\d{1,2}) 0 R'
    auto_action_pattern = rb'/AA'
    open_action_regex = rb'/OpenAction'
    o_regex = rb'/O (\d{1,2}) 0 R'
    open_a_ref_regex = rb'/OpenAction 9 0 R'
    launch_regex = rb'/Launch'
    stream_regex = rb'stream([\x00-\xff]+?)endstream'
    goto_regex = rb'/GoTo|/GoToR|/GoToE'
    # goto_remote_regex = rb'/GoToR'
    # goto_emb_regex = rb'/GoToE'
    submitform_regex = rb'/SubmitForm'

    # Generic regular expressions:
    ##############################
    unicode_regex = rb'[\x20-\x7e]\x00[\x20-\x7e]\x00'
    ascii_regex = rb'[\x20-\x7e]{10,1000}'
    base64_regex = r'(?:[A-Za-z\d+/]{4})|(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)'

    # OLE object identifier CLSIDs (the CLSID is at raw offset 0x450 in the OLE file):
    ##################################################################################
    CLSIDS = {
        rb'\x00\x02\x08\x10\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Sheet.5',
        rb'\x00\x02\x08\x11\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Chart.5',
        rb'\x00\x02\x08\x20\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Microsoft Excel 97-2003 Worksheet (Excel.Sheet.8)',
        rb'\x00\x02\x08\x21\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Chart.8',
        rb'\x00\x02\x08\x30\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel.Sheet.12',
        rb'\x00\x02\x08\x32\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel sheet with macro enabled (Excel.SheetMacroEnabled.12)',
        rb'\x00\x02\x08\x33\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Excel binary sheet with macro enabled (Excel.SheetBinaryMacroEnabled.12)',
        rb'\x00\x02\x09\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word 6.0-7.0 Document (Word.Document.6)',
        rb'\x00\x02\x09\x06\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word 97-2003 Document (Word.Document.8)',
        rb'\x00\x02\x09\x07\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Word Picture (Word.Picture.8)',
        rb'\x00\x02\x0C\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x14\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Windows LNK Shortcut file',  #
        rb'\x00\x02\x17\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 2.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\x26\x01\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x26\x02\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x02\x26\x03\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x02\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\xCE\x02\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x02\xCE\x03\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'MathType Equation Object',
        rb'\x00\x03\x00\x0B\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'Microsoft Equation (Known Related to CVE-2017-11882 or CVE-2018-0802)',
        rb'\x00\x03\x00\x0C\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x03\x00\x0D\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x00\x03\x00\x0E\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46': 'OLE Package Object (may contain and run any file)',
        rb'\x04\x8E\xB4\x3E\x20\x59\x42\x2F\x95\xE0\x55\x7D\xA9\x60\x38\xAF': 'Microsoft Powerpoint.Slide.12',
        rb'\x06\x29\x0B\xD3\x48\xAA\x11\xD2\x84\x32\x00\x60\x08\xC3\xFB\xFC': 'Script Moniker, aka Moniker to a Windows Script Component (may trigger CVE-2017-0199)',
        rb'\x18\xA0\x6B\x6B\x2F\x3F\x4E\x2B\xA6\x11\x52\xBE\x63\x1B\x2D\x22': 'Word.DocumentMacroEnabled.12 (DOCM)',
        rb'\x30\x50\xF4\xD8\x98\xB5\x11\xCF\xBB\x82\x00\xAA\x00\xBD\xCE\x0B': 'HTML Application (may trigger CVE-2017-0199)',
        rb'\x44\xF9\xA0\x3B\xA3\xEC\x4F\x3B\x93\x64\x08\xE0\x00\x7F\x21\xDF': 'Control.TaskSymbol (Known Related to CVE-2015-1642 & CVE-2015-2424)',
        rb'\x46\xE3\x13\x70\x3F\x7A\x11\xCE\xBE\xD6\x00\xAA\x00\x61\x10\x80': 'Forms.MultiPage',
        rb'\x4C\x59\x92\x41\x69\x26\x10\x1B\x99\x92\x00\x00\x0B\x65\xC6\xF9': 'Forms.Image (may trigger CVE-2015-2424)',
        rb'\x64\x81\x8D\x10\x4F\x9B\x11\xCF\x86\xEA\x00\xAA\x00\xB9\x29\xE8': 'Microsoft Powerpoint.Show.8',
        rb'\x64\x81\x8D\x11\x4F\x9B\x11\xCF\x86\xEA\x00\xAA\x00\xB9\x29\xE8': 'Microsoft Powerpoint.Slide.8',
        rb'\x6E\x18\x20\x20\xF4\x60\x11\xCE\x9B\xCD\x00\xAA\x00\x60\x8E\x01': 'ActiveX Control: Forms.Frame',
        rb'\x20\x20\x18\x6E\x60\xF4\xCE\x11\x9B\xCD\x00\xAA\x00\x60\x8E\x01': 'ActiveX Control: Microsoft Forms 2.0 Frame',
        rb'\x88\xD9\x69\xEB\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.ServerXMLHTTP.5.0',
        rb'\x88\xD9\x69\xEA\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XMLHTTP.5.0',
        rb'\x88\xD9\x69\xE7\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XMLSchemaCache.5.0',
        rb'\x88\xD9\x69\xE8\xF1\x92\x11\xD4\xA6\x5F\x00\x40\x96\x32\x51\xE5': 'Msxml2.XSLTemplate.5.0',
        rb'\x97\x8C\x9E\x23\xD4\xB0\x11\xCE\xBF\x2D\x00\xAA\x00\x3F\x40\xD0': 'Microsoft Forms 2.0 Label (Forms.Label.1)',
        rb'\xB8\x01\xCA\x65\xA1\xFC\x11\xD0\x85\xAD\x44\x45\x53\x54\x00\x00': 'Adobe Acrobat Document - PDF file',
        rb'\xC0\x8A\xFD\x90\xF2\xA1\x11\xD1\x84\x55\x00\xA0\xC9\x1F\x38\x80': 'ShellBrowserWindow',
        rb'\xC6\x2A\x69\xF0\x16\xDC\x11\xCE\x9E\x98\x00\xAA\x00\x57\x4A\x4F': 'Forms.Form',
        rb'\xCF\x4F\x55\xF4\x8F\x87\x4D\x47\x80\xBB\x58\x08\x16\x4B\xB3\xF8': 'Microsoft Powerpoint.Show.12',
        rb'\xD7\x05\x32\x40\xCE\x69\x11\xCD\xA7\x77\x00\xDD\x01\x14\x3C\x57': 'Microsoft Forms 2.0 CommandButton',
        rb'\xF2\x0D\xA7\x20\xC0\x2F\x11\xCE\x92\x7B\x08\x00\x09\x5A\xE3\x40': 'OLE Package Object (may contain and run any file)',
        rb'\xF4\x14\xC2\x60\x6A\xC0\x11\xCF\xB6\xD1\x00\xAA\x00\xBB\xBB\x58': 'jscript.dll - JScript Language (ProgID: ECMAScript, JavaScript, JScript, LiveScript)',
        rb'\xF4\x75\x4C\x9B\x64\xF5\x4B\x40\x8A\xF4\x67\x97\x32\xAC\x06\x07': 'Microsoft Word Document (Word.Document.12)'}

    def determine_mimetype(self, data):
        """
        Determine the file type by the magic bytes/signatures.
        Returns a string indicating the file type ("ole"/"ooxml"/"rtf"/"pdf")

        """

        # https://www.garykessler.net/library/file_sigs.html
        try:
            if self.OLE == data[:len(self.OLE)]:
                printy("[y][+] Mime type: Object Linking and Embedding (OLE) Compound File (CF)@")
                return "ole"
            elif self.OOXML == data[:len(self.OOXML)]:
                printy("[y][+] Mime type: Microsoft Office Open XML Format (OOXML) Document@")
                return "ooxml"
            elif self.RTF == data[:len(self.RTF)]:
                printy("[y][+] Mime type: RTF (Rich text format) word processing file - \"{\\rtf\"@")
                return "rtf"
            elif self.PDF == data[:len(self.PDF)]:
                printy("[y][+] Mime type: PDF document - \"%PDF-1.x\"@")
                return "pdf"
        except TypeError:
            return 0

    def scan_for_obj_type(self, stream_name, data):
        """
        Scans an OLE object to identify its type using the CLSIDS dictionary

        """
        printy("[y][+] Attempting to determine the object type@")

        for clsid in self.CLSIDS:
            if re.findall(clsid, data):
                try:
                    print_string = raw_format("[o>]Object type:@ %s" % self.CLSIDS[clsid])
                    printy(print_string)
                except Exception:
                    print("[+] Object type: %s" % self.CLSIDS[clsid])
                    print_string = "Object type: %s" % self.CLSIDS[clsid]
                    self.add_summary_if_no_duplicates(print_string, stream_name)
                else:
                    self.add_summary_if_no_duplicates(print_string, stream_name)

    def deduplicate_table(self, string, summary_string):
        """
        Removes duplicates from the final summary table

        """
        no_duplicates = True
        temp1 = list(self.summary_table.rows)
        for row in temp1:
            for c in row:
                try:
                    if string in c:
                        no_duplicates = False
                except TypeError:
                    continue
        return no_duplicates

    def add_summary_if_no_duplicates(self, summary, desc):
        """
        Adds a new row to the summary table if it does not exist in it already.
        It is the only function that adds rows to the final summary table.

        """
        no_duplicates = self.deduplicate_table(desc, summary)
        if no_duplicates:
            self.summary_table.rows.append([summary, desc])

    def search_indicators_in_string(self, filename, string):
        """
        Scans a string against multiple known keywords to extract more indications in the analysis report and
        summary table.

        """

        no_duplicates = True

        if "URLMON" in string or "urlmon" in string or "loadToFile" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = raw_format("[y>]Indication of file download in extracted strings from:@ %s"
                                            % clean_filename.strip('\x01'))
            else:
                summary_string = raw_format("[y>]Indication of file download in extracted strings from:@ %s"
                                            % filename)

            self.add_summary_if_no_duplicates(summary_string, string)

        if ("http:" in string or "https:" in string) and "crl" not in string and "thawte" not in string and \
                                                          "verisign" not in string and "symantec" not in string and \
                                                          "ocsp" not in string and "openxml" not in string and \
                                                          "theme" not in string and "schema" not in string and \
                                                          "microsoft" not in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = raw_format("[o>]URL found in extracted strings, from:@ %s" % clean_filename)
            else:
                summary_string = raw_format("[o>]URL found in extracted strings, from:@ %s" % filename.strip('\x01'))

            self.add_summary_if_no_duplicates(summary_string, string)

        if "CreateFile" in string or "CreateDirectory" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = raw_format("[y>]Indication of file creation in extracted strings, from:@ %s"
                                            % "".join(clean_filename.strip('\x01')))
            else:
                summary_string = raw_format("[y>]Indication of file creation in extracted strings, from:@ %s"
                                            % "".join(filename.strip('\x01')))

            self.add_summary_if_no_duplicates(summary_string, string)

        if "ShellExecute" in string or "Shell32.Shell" in string or "cmd /c" in string or "powershell" in string:
            if '\x01' in filename:
                clean_filename = filename.strip('\x01')
                summary_string = raw_format("[o>]Indication of shell command execution in file:@ %s"
                                            % "".join(clean_filename.strip('\x01')))
            else:
                summary_string = raw_format("[o>]Indication of shell command execution in file:@ %s"
                                            % "".join(filename.strip('\x01')))

            self.add_summary_if_no_duplicates(summary_string, string)

        if (".exe" in string or
                ".EXE" in string or
                ".exe" in string or
                ".sct" in string or
                ".ocx" in string or
                ".php" in string or
                "ProgramData" in string or
                "Desktop" in string or
                "Downloads" in string or
                "C:\\Users" in string or
                ".com" in string or
                ".ocx" in string or
                ".hta" in string or
                ".tmp" in string or
                ".dat" in string or
                ".txt" in string or
                re.findall(r"[a-z]+\.[a-z]", string)) and \
                "theme" not in string and \
                "_rels" not in string and \
                "openxml" not in string and \
                "theme" not in string and \
                "schema" not in string and \
                "crl" not in string and \
                "thawte" not in string and \
                "verisign" not in string and \
                "symantec" not in string and \
                "ocsp" not in string and \
                "openxml" not in string and \
                "theme" not in string and \
                "schema" not in string and \
                "java" not in string and \
                "Java" not in string and \
                "jvm" not in string and \
                "mscoree.dll" not in string and \
                "kernel32.dll" not in string and \
                "gdiplus32.dll" not in string and \
                "gdiplus.dll" not in string and \
                "advapi32.dll" not in string and \
                "native" not in string and \
                "microsoft" not in string:

            if "Ole10Native" in filename:
                summary_string = raw_format("[o>]Suspicious file path or possible domain found in:@ %s" % filename.strip('\x01'))
            else:
                summary_string = raw_format("[o>]Suspicious file path or possible domain found in:@ %s"
                                            % "".join(filename.strip('\x01')))
            if no_duplicates and len(string) < 100:
                self.add_summary_if_no_duplicates(summary_string, string)

        if "This program" in string or "DOS mode" in string:
            if "Ole10Native" in filename:
                summary_string = raw_format("[r>]Possible PE (Portable Executable) payload in stream:@ %s" % filename.strip('\x01'))
                self.add_summary_if_no_duplicates(summary_string, string)

            else:
                summary_string = raw_format("[r>]Possible PE (Portable Executable) payload in stream:@ %s" % "".join(filename.strip('\x01')))
                self.add_summary_if_no_duplicates(summary_string, string)

        eq = re.findall(self.equation_regex, string)
        if eq:
            if "Ole10Native" in filename:
                summary_string = raw_format("[r>]Possible Equation Editor exploit:@ " % filename.strip('\x01'))
                self.add_summary_if_no_duplicates(summary_string, string)
            else:
                summary_string = raw_format("[r>]Possible Equation Editor exploit:@ %s" % "".join(filename.strip('\x01')))
                self.add_summary_if_no_duplicates(summary_string, string)

    def find_susp_functions_vba(self, filename, decompressed):
        """
        Scans decompressed VBA projects for known function keywords to provide nore insight on the code behavior.

        """

        if "Auto_Open" in decompressed or "Document_Open" in decompressed:
            summary_string = raw_format("[r>]VBA macro auto execution:@ Auto_Open()/Document_Open() found in: %s" % "\\".join(filename))
            summary_desc = "%s: Auto_Open()/Document_Open() - will execute VBA code when doc is opened" % "\\".join(filename)
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "Auto_Close" in decompressed:
            summary_string = raw_format("[r>]VBA macro:@ Auto_Close() in:@ %s" % str("\\".join(filename)))
            summary_desc = "%s: Auto_Close() - will execute VBA code when doc is closed" \
                           % "\\".join(filename)
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "Shell(" in decompressed or "WScript.Shell" in decompressed:
            summary_string = raw_format("[r>]VBA macro: the code invokes the shell (Shell()\Wscript.Shell) in:@ %s"
                                        % str("\\".join(filename)))
            summary_desc = "%s: Shell() - Macro code will invoke the shell to execute code" \
                           % "\\".join(filename)
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

        if "http" in decompressed:
            summary_string = raw_format("[r>]VBA macro: URL found in:@ %s" % str("\\".join(filename)))
            self.add_summary_if_no_duplicates(summary_string, re.findall(r'http[s]{0,1}\:\/\/.*\..*\/.*\"',
                                                                         decompressed)[0])

    def find_susp_functions_xlm(self, filename, decompressed):
        """
        Scans XLM macros in sheets for known function keywords to provide nore insight on the code behavior.

        """

        if "HALT()" in decompressed or "RETURN(" in decompressed or "EXEC()" in decompressed or \
                "WRITE(" in decompressed or "FOR(" in decompressed or "FOR(" in decompressed or \
                "FORMULA(" in decompressed:
            summary_string = raw_format("[r>]Excel 4.0 (XLM) macro\n XLM macro functions detected in: %s"
                                        % "\\".join(filename.strip('\x01')))
            summary_desc = decompressed[:150]
            self.add_summary_if_no_duplicates(summary_string, summary_desc)

