########################################################################################################################
##
##
##  __   __       _     _              _____
## |  \\/  |     | |   | |            |  __ \
## | \\  / | __ _| | __| | ___   ___  | |__) |_ _ _ __ ___  ___ _ __
## | |\\/| |/ _` | |/ _` |/ _ \ / __| |  ___/ _` | '__/ __|/ _ \ '__|
## | |   | | (_| | | (_| | (_) | (__  | |  | (_| | |  \__ \  __/ |
## |_|   |_|\__,_|_|\___,|\___/ \___| |_|   \__,_|_|  |___/\___|_|
##
##
## Author: @danielbres93
##
## maldoc_parser is a static analysis tool for common Office formats and PDF files.
## The main goal of the tool is to automate static analysis as much as possible.
## It currently supports OLE, OOXML, RTF and PDF files.
##
## Tested on Windows with Python 3.x
##
##
## References:
## ===========
## https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml
## https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf
## https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml
## https://xlsxwriter.readthedocs.io/working_with_macros.html#:~:text=The%20vbaProject.,t%20stored%20in%20XML%20format.
## https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc#directory_entry_types
##
##
########################################################################################################################


import sys
import shutil, os
import os.path
from os import path
import hashlib
from XLSParser import *
from printy import *
from sys import exit
from OLEParser import *
from DocParser import *
from VBADecompress import VBADecompress
from OOXMLParser import *
from helpers import *
from helpers import Helpers
from RTF import RTF
from PDF import *


def print_banner():

    printy("\n")
    printy("[bw] __  __       _     _              _____                             @")
    printy("[bw]|  \\/  |     | |   | |            |  __ \\                           @")
    printy("[bw]| \\  / | __ _| | __| | ___   ___  | |__) |_ _ _ __ ___  ___ _ __     @")
    printy("[bw]| |\\/| |/ _` | |/ _` |/ _ \\ / __| |  ___/ _` | '__/ __|/ _ \\ '__| @")
    printy("[bw]| |  | | (_| | | (_| | (_) | (__  | |  | (_| | |  \\__ \\  __/ |     @")
    printy("[bw]|_|  |_|\\__,_|_|\\__,_|\\___/ \\___| |_|   \\__,_|_|  |___/\\___|_| @\n")
    printy("[bw]Author: Daniel Bresler@\n")


def main():

    # check if a file path was provided to the tool
    if len(sys.argv) < 2:
        print_banner()
        printy("\n[r>]maldocs_parser: provide file path\nUsage: maldocs_parser.exe <file_path>@\n")
        exit(0)
    helpers = Helpers()
    filename = sys.argv[1]
    print_banner()

    printy("[y][+] Parsing file: %s@" % filename)

    # Read the file binary data
    file = open(filename, 'r+b')
    data = file.read()

    # Calculate SHA256 hash
    readable_hash = hashlib.sha256(data).hexdigest()
    printy("[y][+] File sha256: %s@" % str(readable_hash))

    print("\n\n+----------------------------------------------------------------------+")
    printy("+======================= [bw]Static Analysis Report@ ======================+")
    print("+----------------------------------------------------------------------+")

    # Determine file type via magic bytes/signature
    mimetype = helpers.determine_mimetype(data)

    # If the file is OLE
    if mimetype == "ole":
        # Initiate the OLEParser class
        ms_ole = OLEParser(data)
        # Parse CFB header, extract all streams and analyze them
        ms_ole.extract_embedded_ole(filename, filename)

        # If the OLE file is Excel, apply more parsing and logic
        if helpers.MICROSOFT_EXCEL in data:

            # Initiate the XLSParser class
            xls_parser = XLSParser(data)

            # Parse BOF records
            xls_parser.parse_bof_records(data)

            # Parse BOUNDSHEET records (sheet headers)
            xls_parser.parse_boundsheet_record(data)

            # Unhide hidden sheets via BOUNDSHEET record patching
            xls_parser.unhide_sheets(file)

            # Extract data from sheets (XLM 4 macros)
            xls_parser.extract_sheets(filename)

            # Attempt to extract VBA macros if there are any
            decompressed = None
            try:
                decompress_obj = VBADecompress(data)
                decompressed = decompress_obj.SearchAndDecompress(data)
            except TypeError:
                pass

            # Extract strings from Shared Strings table (SST)
            xls_parser.parse_sst(data)

        elif helpers.MICROSOFT_OFFICE_WORD in data:
            # the DocParser() class has no use.
            # If there will be any Word specific functionality for OLE files it will be executed under this statement.
            doc_parser = DocParser(data)
            pass

    # If the file is RTF
    elif mimetype == "rtf":
        # Initiate the RTF() class with the document data.
        rtf = RTF(data)

        # Find and "clean" hex data
        clean = rtf.clean_hex_data(data)

        # Search any OLE files and binary blobs in the "cleaned" hex data.
        rtf.search_ole_obj(clean)

    # If the file is Office Open XML
    elif mimetype == "ooxml":

        # Initiate the OOXMLParser() class
        ooxml_obj = OOXMLParser(data)

        # Find and extract embedded OLE files.
        print("[+] Looking for embedded OLE files in OOXML ZIP container")
        ooxml_obj.detect_emb_ole(data, filename)

        # If the OOXML file is Excel
        if ooxml_obj.doc_type == "excel":
            # Initiate a OOXML_Excel class using the already initiated OOXMLParser object
            ooxml_excel = OOXML_Excel(ooxml_obj)

            # check file extension to know how to read sheets
            if "xlsx" or "xlsm" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                print("[+] Reading Excel sheets")
                ooxml_excel.read_sheets(filename)
            # If the Excel is a binary worksheet (.xlsb)
            if "xlsb" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                print("[+] Reading binary Excel sheets (.xlsb)")
                ooxml_excel.read_binary_excel_sheets(filename)

        if ooxml_obj.doc_type == "ppt":
            #ooxml_ppt = OOXML_PowerPoint(ooxml_obj)
            #ooxml_ppt.search_slides(filename)
            pass

        ooxml_obj.parse_ole_file(data, filename)
        print("[+] Looking for ActiveX objects in OOXML ZIP container")
        ooxml_obj.detect_activex(filename)

    # If the file is a PDF document
    elif mimetype == 'pdf':
        # Initiate the PDF() class.
        pdf_parser = PDF(data)

        # List and analyze all PDF objects
        pdf_parser.enum_objects(data)

    print("\n\n+----------------------------------------------------------------------+")
    printy("+======================= [bw]Static Analysis Summary@ ======================+")

    # Prepare and print final summary analysis table
    helpers.summary_table.columns.alignment = BeautifulTable.ALIGN_LEFT
    print(helpers.summary_table)

    if path.isdir('unzipped'):
        shutil.rmtree("unzipped")

    if path.isfile('data.txt'):
        try:
            os.remove("data.txt")
        except FileNotFoundError:
            pass

    if path.isfile("obj.bin"):
        try:
            os.remove("obj.bin")
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
