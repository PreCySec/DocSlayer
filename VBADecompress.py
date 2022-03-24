import re
import math


class VBADecompress:
    '''
    The code of the class methods was taken from oledump by Didier Stevens:
    https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py

    '''

    def __init__(self, data):
        self.data = data

    def MacrosContainsOnlyAttributesOrOptions(self, stream):
        lines = self.SearchAndDecompress(stream).split('\n')
        for line in [line.strip() for line in lines]:
            if line != '' and not line.startswith('Attribute ') and not line == 'Option Explicit':
                return False
        return True

    def P23Ord(self, value):
        if type(value) == int:
            return value
        else:
            return ord(value)

    def ParseTokenSequence(self, data):
        flags = self.P23Ord(data[0])
        data = data[1:]
        result = []
        for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            if len(data) > 0:
                if flags & mask:
                    result.append(data[0:2])
                    data = data[2:]
                else:
                    result.append(data[0])
                    data = data[1:]
        return result, data

    def OffsetBits(self, data):
        numberOfBits = int(math.ceil(math.log(len(data), 2)))
        if numberOfBits < 4:
            numberOfBits = 4
        elif numberOfBits > 12:
            numberOfBits = 12
        return numberOfBits

    def Decompress(self, compressedData, replace=True):
        if self.P23Ord(compressedData[0]) != 1:
            return (False, None)
        remainder = compressedData[1:]
        decompressed = ''
        while len(remainder) != 0:
            decompressedChunk, remainder = self.DecompressChunk(remainder)
            if decompressedChunk == None:
                return (False, decompressed)
            decompressed += decompressedChunk
        if replace:
            return (True, decompressed.replace('\r\n', '\n'))
        else:
            return (True, decompressed)

    def DecompressChunk(self, compressedChunk):
        if len(compressedChunk) < 2:
            return None, None
        header = self.P23Ord(compressedChunk[0]) + self.P23Ord(compressedChunk[1]) * 0x100
        size = (header & 0x0FFF) + 3
        flagCompressed = header & 0x8000
        data = compressedChunk[2:2 + size - 2]

        if flagCompressed == 0:
            return data.decode(errors='ignore'), compressedChunk[size:]

        decompressedChunk = ''
        while len(data) != 0:
            tokens, data = self.ParseTokenSequence(data)
            for token in tokens:
                if type(token) == int:
                    decompressedChunk += chr(token)
                elif len(token) == 1:
                    decompressedChunk += token
                else:
                    if decompressedChunk == '':
                        return None, None
                    numberOfOffsetBits = self.OffsetBits(decompressedChunk)
                    copyToken = self.P23Ord(token[0]) + self.P23Ord(token[1]) * 0x100
                    offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                    length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                    copy = decompressedChunk[-offset:]
                    copy = copy[0:length]
                    lengthCopy = len(copy)
                    while length > lengthCopy:  # a#
                        if length - lengthCopy >= lengthCopy:
                            copy += copy[0:lengthCopy]
                            length -= lengthCopy
                        else:
                            copy += copy[0:length - lengthCopy]
                            length -= length - lengthCopy
                    decompressedChunk += copy
        return decompressedChunk, compressedChunk[size:]

    def SkipAttributes(self, text):
        oAttribute = re.compile('^Attribute VB_.+? = [^\n]+\n')
        while True:
            oMatch = oAttribute.match(text)
            if oMatch == None:
                break
            text = text[len(oMatch.group()):]
        return text

    def FindCompression(self, data):
        return data.find(b'\x00Attribut\x00e ')

    def SearchAndDecompressSub(self, data):
        position = self.FindCompression(data)
        if position == -1:
            return (False, '')
        else:
            compressedData = data[position - 3:]
        return self.Decompress(compressedData)

    def SearchAndDecompress(self, data, skipAttributes=False):
        result, decompress = self.SearchAndDecompressSub(data)
        if result:
            if skipAttributes:
                return self.SkipAttributes(decompress)
            else:
                return decompress
        else:
            return 0

          
