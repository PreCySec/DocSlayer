import re
import glob
from pyxlsb import open_workbook as open_xlsb
import zipfile
from printy import *
import xml.etree.ElementTree as ET
#from XLSParser import XLSParser
from OLEParser import OLEParser
import VBADecompress
from helpers import *
from helpers import Helpers


class OOXMLParser:
    """
    The OOXML() class parses and analyzes Office Open XML documents.
    It specifically handles OLE Excel files, as those have additional parsing and logic that needs to be applicaed
    to fully parse/analyze the file.

    The class will:
    - Extract and read data from all XML and binary files in the OOXML zip container
    - Extract VBA macros
    - Extract and recursively analyze embedded objects (OLEParser/XLSParser)
    - Detect potential Equation Editor exploitation
    - Print sheet cells contents to a table
    - Extract strings from sheets
    - Extract Shared Strings Table strings
    - Detect DDE usage
    - Detect Office template injections
    - Detect URLs in external relationships
    - Detect ActiveX OLE objects and analyze them (OLEParser)
    - Detect potential exploitation of the MSHTML engine

    """
    binary_ooxml = False
    doc_type = ""
    helpers = Helpers()

    def __init__(self, data):
        self.data = data

    def zip_extrcat(self, filename):
        extract_path = "unzipped"
        #print("\n- Extracting archive to: %s" % extract_path)
        zip = zipfile.ZipFile(filename)
        zip.extractall(extract_path)
        path = extract_path
        return path

    def list_archive_files(self, data, filename):

        path = self.zip_extrcat(filename)

        files = glob.glob(path + "**/**/**/*.*", recursive=True)
        files = list(dict.fromkeys(files))
        return files

    def detect_emb_ole(self, data, filename):

        # ms_ole = OLE_Parser(data)
        # emb_ole_files = re.findall(self.OLE_FILE_MAGIC, data)
        files = self.list_archive_files(data, filename)

        printy("\n[bw]OOXML Archive files:@")
        print("=" * len("OOXML Archive files:"))
        for f in files:
            print(f.replace(".\\unzipped", ""))
            if "\\word\\" in f:
                self.doc_type = "word"
            elif"\\xl\\" in f:
                self.doc_type = "excel"
            elif "\\ppt\\" in f:
                self.doc_type = "ppt"
            else:
                continue

        printy("\n[bw]Analyzing files in archive")
        print("=" * len("Analyzing files in archive:"))

        indicators = BeautifulTable()
        indicators.headers = ["Indication", "Description"]
        indicators.columns.width = [50, 70]

        for file in files:

            file_data = open(file, "rb").read()

            if ".bin" in file or self.helpers.OLE_FILE_MAGIC in file_data[:len(self.helpers.OLE_FILE_MAGIC)]:
                ms_ole = OLEParser(data)
                self.parse_ole_file(file_data, file)
                #ms_ole.parse_cfb_header(file, file_data)
                ms_ole.extract_embedded_ole(file, file)

            if ".rels" in file:
                xml_data = open(file, "r").read()
                reference = self.find_ext_references(xml_data, file)
                if reference:
                    print_string = "External relationships in file: %s" % file
                    indicators.rows.append([print_string, reference])

            if "sharedStrings.xml" in file:
                tree = ET.parse(file)
                root = tree.getroot()
                clean_sst_strings = []

                for child in root:
                    for attrib in child:
                        if attrib.text is not None:
                            clean_sst_strings.append(attrib.text)

                if clean_sst_strings:
                    print_line = raw_format("[bw]Shared Strings Table Strings@")
                    indicators.rows.append([print_line, ", ".join(clean_sst_strings)])
                    self.helpers.add_summary_if_no_duplicates(print_line, ", ".join(clean_sst_strings))

            if "webSettings.xml" in file:
                try:
                    xml_data = open(file, "r").read()
                    frame = re.findall(r'frame\" Target=\".*\" TargetMode=\"External\"\/\>\<\/Relationships\>', xml_data)

                    if frame:
                        print_line = raw_format("[r>]Detected external relationship to MSHTML frame in file:@ %s" % file.strip('\x01'))
                        self.helpers.add_summary_if_no_duplicates(print_line, frame)

                except UnicodeDecodeError as e:
                    print("[-] Error reading %s: %s" % (str(file), str(e)))
                    continue

            if "document.xml" in file or "workbook.xml" in file:
                try:
                    print("[+] TRY !")
                    xml_data = open(file, "r").read()
                    dde_command = self.detect_dde(xml_data, file)
                    if dde_command:
                        print("[+] Entered DDE function")
                        print_line = raw_format("[r>]Detected DDE usage in file:@ %s" % file.strip('\x01'))
                        indicators.rows.append([print_line, dde_command])
                        print("DDE !!!!")
                        self.helpers.add_summary_if_no_duplicates(print_line, dde_command)

                    if "&lt" in xml_data:
                        possible_payload = re.findall(r">&lt(.*)", xml_data)
                        print_line = "Possible payload in file: %s" % file.strip('\x01')
                        indicators.rows.append([print_line, possible_payload])
                        self.helpers.add_summary_if_no_duplicates(print_line, possible_payload[:100])

                except UnicodeDecodeError as e:
                    print("[-] Error reading %s: %s" % (str(file), str(e)))
                    continue
            if "macrosheets" in file or "worksheets" in file:

                xml_data = open(file, "r", errors="ignore").read()
                emb_ole_tag_data = self.detect_emb_ole_tag(xml_data)
                if emb_ole_tag_data:
                    print_line = raw_format("[o>]reference to embedded OLE object in file:@ %s" % file.strip('\x01'))
                    indicators.rows.append([print_line, emb_ole_tag_data])
                    self.helpers.add_summary_if_no_duplicates(print_line, emb_ole_tag_data)

        indicators.columns.alignment = BeautifulTable.ALIGN_LEFT
        print(indicators)

    def find_ext_references(self, data, filename):
        # Target=\"(.*)</Relationship.*TargetMode="External"
        # .*TargetMode=\"External\" Target=\"(.*)\".*
        mshtml = re.findall(r'oleObject\" Target=\"mhtml:.*TargetMode=\"External\"', data)
        ext_template = re.findall(r'attachedTemplate\" Target=\"http.*TargetMode=\"External\"', data)
        hyperlinks = re.findall(r'hyperlink\" Target=\".*\"\ TargetMode=\"External\"', data)
        external_oleobj = re.findall(r'oleObject\" TargetMode=\"External\" Target=\".*\"', data)

        if mshtml:
            mshtml_string = str(", ".join(mshtml))
            #printy("\n[r>][!] Found Possible MSHTML abuse in file:@ %s" % filename)
            summary_string = raw_format("[r>]Found Possible MSHTML abuse in file:@ %s"
                                        % filename.replace("\\unzipped", ""))
            self.helpers.add_summary_if_no_duplicates(summary_string, mshtml_string)
            print("[+] Found MSHTML abuse")
            return mshtml_string

        if ext_template:
            reference = str(", ".join(ext_template))
            #printy("\n[o>]Found external relationship in file:@ %s -- %s" % (filename, reference))
            summary_string = raw_format("[o>]Found Possible Template injection in file:@ %s"
                                        % filename.replace("\\unzipped", ""))
            self.helpers.add_summary_if_no_duplicates(summary_string, reference[0])
            print("[+] Found external template (Office template injection)")
            return reference

        if hyperlinks:
            links = str(", ".join(hyperlinks))
            #printy("\n[r>][!] Found hyperlinks in file:@ %s" % filename)
            summary_string = raw_format("[r>]Found hyperlinks in file:@ %s"
                                        % filename.replace("\\unzipped", ""))
            self.helpers.add_summary_if_no_duplicates(summary_string, links)
            return links

        if external_oleobj:
            oleobj = str(", ".join(external_oleobj))
            #printy("\n[r>][!] Found external reference to OLE object in file:@ %s" % filename)
            summary_string = raw_format("[r>]Found external relationship to OLE object in file:@ %s"
                                        % filename.replace("\\unzipped", ""))
            self.helpers.add_summary_if_no_duplicates(summary_string, oleobj)
            return oleobj

    def extract_strings_sst(self, data, filename):
        # <t>(.*)</t>
        shared_strings = re.findall('<t>(.*)</t>', data)
        if shared_strings:
            printy("\n[c>][+] Shared strings table found in file: %s@" % filename)
            for string in shared_strings:
                print(string)
        else:
            pass

    def parse_ole_file(self, data, filename):
        ms_ole = OLEParser(data)
        ms_ole.extract_embedded_ole(filename, filename)

    def detect_eqedit32(self, data):
        """
        https://www.forcepoint.com/blog/x-labs/assessing-risk-office-documents-part-3-exploited-%E2%80%9Cweaponized%E2%80%9D-rtfs

        """
        eqedit32_clsid = re.findall(self.helpers.EQ_EDIT_CLSID_RE, data)
        if eqedit32_clsid:
            return eqedit32_clsid
        else:
            return "    Did not detect an Equation Editor CLSID..."

    def detect_activex(self, filename):

        path = self.zip_extrcat(filename)
        activex_dir = path + "\\xl\\activeX"
        files = glob.glob(activex_dir + "\\*.*", recursive=False)
        if files:
            printy("\n[bw]Searching for ActiveX OLE objects@")
            activex_ole_files = []

            for file in files:
                if ".bin" in file:
                    file_data = open(file, "rb").read()
                    activex_ole_files.append(file)
                    self.parse_ole_file(file_data, file)

            if activex_ole_files:
                summary_string = raw_format("[y]ActiveX objects in file:@ %s" % filename)
                self.helpers.add_summary_if_no_duplicates(summary_string, ", ".join(activex_ole_files))

            return activex_ole_files

    def detect_dde(self, data, filename):
        print("[+] Searching for DDE usage and keywords")
        DDE_PATTERN = "DDEAUTO.*|INCLUDE.*"

        dde = re.findall(DDE_PATTERN, data)
        #dde_command = []
        if dde:

            if ".xml" in filename:
                tree = ET.parse(filename)
                root = tree.getroot()

                for child in root:
                    dde_command = self.inline_xml(child)

                final_dde_command = "".join(dde_command)
                return final_dde_command

    def detect_emb_ole_tag(self, data):

        EMB_OLE_TAG_PATTERN = r"\<oleObjects\>.*\<\/oleObjects\>"
        emb_ole_tag = re.findall(EMB_OLE_TAG_PATTERN, data)

        if emb_ole_tag:
            return emb_ole_tag

    def inline_xml(self, child):

        clean_string = []

        for attrib in child:
            for val in attrib:
                y = filter(lambda v: v.text is not None, val)
                [clean_string.append(x.text) for x in list(y)]

        return clean_string


class OOXML_Excel(OOXMLParser):
    """
    The OOXML_Excel() class is a sub class of the OOXMLParser() class.
    It exports methods that handle and read data from Excel sheets and specific methods for binary Excel worksheets.

    """

    # Prepare a sheets table
    sheet_cells = BeautifulTable(maxwidth=100)
    sheet_cells.headers = ["Cell #", "Cell Content"]

    def read_sheets(self, filename, read_macros=True):

        printy("\n[bw]Reading Excel sheets:@")
        print("=" * len("Reading Excel sheets:"))
        path = self.zip_extrcat(filename)
        sheets_dir = path + "\\xl\\worksheets"
        sheet_types = ["worksheet"]
        macros_sheets = ""

        if read_macros:
            sheet_types.append("macrosheets")
            macros_dir = path + "\\xl\\macrosheets"
            macros_sheets = glob.glob(macros_dir + "\\*.*", recursive=False)

        sheets = glob.glob(sheets_dir + "\\*.*", recursive=False)

        for type in sheet_types:

            if type == "macrosheets":
                self.sheet_cells.columns.alignment = BeautifulTable.ALIGN_LEFT
                print(self.sheet_cells)
                self.sheet_cells.clear()

                sheets = macros_sheets
                self.print_cells(filename, sheets)
                self.sheet_cells.columns.alignments = BeautifulTable.ALIGN_LEFT
                print(self.sheet_cells)
                break

            self.print_cells(filename, sheets)

    def print_cells(self, filename, sheets):

        for sheet in sheets:
            if ".xml" in sheet:
                tree = ET.parse(sheet)
                root = tree.getroot()
                printy("[y][+] Sheet: %s@" % sheet)
                for child in root:
                    m = filter(self.inline_cell(filename, child, self.sheet_cells), root)

    def inline_cell(self, filename, child, sheet_cells):

        if "sheetData" in child.tag:
            for attrib in child:
                for val in attrib:
                    y = filter(lambda v: v.text != "0", val)
                    for x in list(y):
                        sheet_cells.rows.append([val.attrib.get("r"), x.text])
                        self.helpers.search_indicators_in_string(filename, x.text)

    def read_binary_excel_sheets(self, file):

        sheet_binary_table = BeautifulTable(maxwidth=200)
        sst_table = BeautifulTable(maxwidth=100)
        content = []

        with open_xlsb(file) as wb:
            sheets = wb._sheets

            for sheet_name, sheet_path in sheets:
                if sheet_path:
                    with wb.get_sheet(sheet_name) as s:
                        for row in s.rows():
                            for item in row:
                                if item.v is not None and item.v is not False and type(item.v) is str and len(item.v) \
                                        > 1:
                                    content.append(item.v)
                                    sheet_binary_table.rows.append(["Cell at row:" + str(item.r) + ", col:" +
                                                                    str(item.c), item.v.replace("\x00", "")])

                                    self.helpers.search_indicators_in_string(sheet_name, item.v)
                else:
                    continue

                sheet_binary_table.columns.alignment = BeautifulTable.ALIGN_LEFT
                print("\nSheet name: %s" % sheet_name)
                print(sheet_binary_table)

            self.print_binary_sst(file, sst_table)

    def print_binary_sst(self, file, sst_table):
        print("Shared Strings Table (SST):")
        with open_xlsb(file) as wb:
            sst_table.rows.append(["Shared Strings Table", " , ".join(wb.stringtable._strings)])
            sst_table.columns.alignment = BeautifulTable.ALIGN_LEFT
            print(sst_table)

    # def list_contents(self, filename):
    #
    #    indicators = BeautifulTable(maxwidth=100)
    #    path = self.zip_extrcat(filename)
    #    files = glob.glob(path + "**\\**\\**\\*.*", recursive=True)
    #    if files:
    #        for file in files:
    #
    #            file_data = open(file, "rb").read()
    #            eqedit32 = self.detect_eqedit32(file_data)
    #
    #            if self.helpers.OLE_FILE_MAGIC in file_data[:len(self.helpers.OLE_FILE_MAGIC)]:
    #
    #                ms_ole = OLEParser(file_data)
    #                ms_ole.extract_embedded_ole(file)
    #
    #                if eqedit32:
    #                    print_string = "[!] Detected Equation Editor CLSID"
    #                    indicators.rows.append([print_string, file])
    #
    #            if "vbaProject.bin" in file:
    #                self.parse_ole_file(file_data, file)
    #                continue
    #
    #        indicators.columns.alignment = BeautifulTable.ALIGN_LEFT
    #        print(indicators)


class OOXML_PowerPoint(OOXMLParser):
    """
    This class is not used.
    If PowerPoint OOXML specific functionality will be added, it will be here.

    """
    def search_slides(self):
        pass


class OOXML_Word(OOXMLParser):
    """
    This class is not used.
    If Word OOXML specific functionality will be added, it will be here.

    """
