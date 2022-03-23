########################################################################################################################
#
#
#  _____              _____ _                       
# |  __ \            / ____| |                      
# | |  | | ___   ___| (___ | | __ _ _   _  ___ _ __ 
# | |  | |/ _ \ / __|\___ \| |/ _` | | | |/ _ \ '__|
# | |__| | (_) | (__ ____) | | (_| | |_| |  __/ |   
# |_____/ \___/ \___|_____/|_|\__,_|\__, |\___|_|   
#                                    __/ |          
#                                   |___/           
#
# @PreCySec
#
# DocSlayer is a static analysis tool for common Office formats and PDF files.
# The main goal of the tool is to automate static analysis as much as possible.
# It currently supports OLE, OOXML, RTF and PDF files.
#
# Python 3.x
#
#
# References:
# ===========
# https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml
# https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf
# https://www.loc.gov/preservation/digital/formats/fdd/fdd000395.shtml
# https://xlsxwriter.readthedocs.io/working_with_macros.html#:~:text=The%20vbaProject.,t%20stored%20in%20XML%20format.
# https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc#directory_entry_types
#
#
########################################################################################################################

import os
import sys
import shutil
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

    print("\n")
    printy("[bw]  _____              _____ _                       @")
    printy("[bw] |  __ \            / ____| |                      @")
    printy("[bw] | |  | | ___   ___| (___ | | __ _ _   _  ___ _ __ @")
    printy("[bw] | |  | |/ _ \ / __|\___ \| |/ _` | | | |/ _ \ '__|@")
    printy("[bw] | |__| | (_) | (__ ____) | | (_| | |_| |  __/ |   @")
    printy("[bw] |_____/ \___/ \___|_____/|_|\__,_|\__, |\___|_|   @")
    printy("[bw]                                    __/ |          @")
    printy("[bw]                                   |___/           @")

    #printy("[bw]Author: Daniel Bresler@\n")


def main():

    # check if a file path was provided to the tool
    if len(sys.argv) < 2:
        print_banner()
        printy("\n[r>]maldocs_parser: provide file path\nUsage: maldocs_parser.exe <file_path>@\n")
        exit(0)

    helpers = Helpers()
    filename = sys.argv[1]

    # If the given path is a directory it will run the tool on each sample in the directory.
    if os.path.isdir(filename):
        print("[+] Analyzing multiple samples\n")
        samples = helpers.list_files(filename)
        helpers.read_stdout(samples)
        exit(0)

    printy("[y][+] Parsing file: %s@" % filename)

    # Read the file binary data
    file = open(filename, 'r+b')
    data = file.read()

    # Calculate SHA256 hash
    readable_hash = hashlib.sha256(data).hexdigest()
    printy("[y][+] File sha256: %s@" % str(readable_hash))

    # Determine file type via magic bytes/signature
    mimetype = helpers.determine_mimetype(data)

    print("\n\n+----------------------------------------------------------------------+")
    printy("+======================= [bw]Static Analysis Report@ ======================+")
    print("+----------------------------------------------------------------------+")

    # If the file is OLE
    if mimetype is "ole":
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

            # Extract strings from Shared Strings table (SST)
            xls_parser.parse_sst(data)

        elif helpers.MICROSOFT_OFFICE_WORD in data:
            # the DocParser() class has no use.
            # If there will be any Word specific functionality for OLE files it will be executed under this statement.
            doc_parser = DocParser(data)
            pass

    # If the file is RTF
    elif mimetype is "rtf":
        # Initiate the RTF() class with the document data.
        rtf = RTF(data)

        # Find and "clean" hex data
        rtf.test(data)
        clean = rtf.clean_hex_data(data)

        # Search any OLE files and binary blobs in the "cleaned" hex data.
        rtf.search_ole_obj(clean)

    # If the file is Office Open XML
    elif mimetype is "ooxml":

        # Initiate the OOXMLParser() class
        ooxml_obj = OOXMLParser(data)

        # Find and extract embedded OLE files.
        ooxml_obj.detect_emb_ole(data, filename)

        # If the OOXML file is Excel
        if ooxml_obj.doc_type == "excel":
            # Initiate a OOXML_Excel class using the already initiated OOXMLParser object
            ooxml_excel = OOXML_Excel(ooxml_obj)

            # check file extension to know how to read sheets
            if "xlsx" or "xlsm" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                ooxml_excel.read_sheets(filename)
            # If the Excel is a binary worksheet (.xlsb)
            if "xlsb" in filename:
                # The below method is specific to reading data from sheets in binary Excel worksheets
                ooxml_excel.read_binary_excel_sheets(filename)

        if ooxml_obj.doc_type == "ppt":
            #ooxml_ppt = OOXML_PowerPoint(ooxml_obj)
            #ooxml_ppt.search_slides(filename)
            pass

        ooxml_obj.parse_ole_file(data, filename)
        ooxml_obj.detect_activex(filename)
        #os.rmdir('unzipped')


    # If the file is a PDF document
    elif mimetype is 'pdf':
        # Initiate the PDF() class.
        pdf_parser = PDF(data)

        # List and analyze all PDF objects
        pdf_parser.enum_objects(data)


    if os.path.isdir('.\\unzipped'):
        shutil.rmtree('.\\unzipped', ignore_errors=True)

    print("\n\n+----------------------------------------------------------------------+")
    printy("+======================= [bw]Static Analysis Summary@ ======================+")

    # Prepare and print final summary analysis table
    helpers.summary_table.columns.alignment = BeautifulTable.ALIGN_LEFT
    print(helpers.summary_table)


if __name__ == "__main__":
    print_banner()
    main()
