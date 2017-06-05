# Copyright (C) 2005-2017 Splunk Inc.  All Rights Reserved.  Version 6.x
# Author: Andrew Quill
import sys,splunk.Intersplunk
import string
import getpass
import re

def replace_xns(field):
    try:
       punydecode = field.encode("idna").decode("idna")
    except:
       punydecode = field
    return punydecode


def chardetect(field1, detection):
    vargroup = []
    isXN = re.compile("^[Xx][Nn]\--.*$")
    isAlpha = re.compile('[\w\d]')
    for xngroup in re.split('[\\\.]', field1):
        try:
            vargroup.append(str(xngroup.lower().encode("idna").decode("idna")))
        except:
            detection.append("Wide Mode Unicode")
    #roll through the var groups only checking the xn domains
    for chgroup in vargroup:
        dgbcounter = 0
        for character in list(chgroup.decode()):
            #make an umodified backup for plain chars
            backupchar = character
            try:
                character = repr(character.decode()).lstrip('\'\\\u').rstrip("'")
                if int(character, 16) < 0x0080:
                    detection.append("English Latin Base")
                elif int(character, 16) < 0x02AF:
                    detection.append("English Latin Extended")
                elif int(character, 16) < 0x036F:
                    detection.append("Diacritical Marks")
                elif int(character, 16) < 0x03FF:
                    detection.append("Greek and Coptic")
                elif int(character, 16) < 0x052F:
                    detection.append("Cyrillic")
                elif int(character, 16) < 0x058F:
                    detection.append("Armenian")
                elif int(character, 16) < 0x06FF:
                    detection.append("Hebrew")
                elif int(character, 16) < 0x06FF:
                    detection.append("Arabic")
                elif int(character, 16) < 0x074F:
                    detection.append("Syriac")
                elif int(character, 16) < 0x07BF:
                    detection.append("Thaana")
                elif int(character, 16) < 0x097F:
                    detection.append("Devanagari")
                elif int(character, 16) < 0x09FF:
                    detection.append("Bengali")
                elif int(character, 16) < 0x0A7F:
                    detection.append("Gurmukhi")
                elif int(character, 16) < 0x0AFF:
                    detection.append("Gujarati")
                elif int(character, 16) < 0x0B7F:
                    detection.append("Oriya")
                elif int(character, 16) < 0x0BFF:
                    detection.append("Tamil")
                elif int(character, 16) < 0x0C7F:
                    detection.append("Telugu")
                elif int(character, 16) < 0x0CFF:
                    detection.append("Kannada")
                elif int(character, 16) < 0x0D7F:
                    detection.append("Malayalam")
                elif int(character, 16) < 0x0DFF:
                    detection.append("Sinhala")
                elif int(character, 16) < 0x0E7F:
                    detection.append("Thai")
                elif int(character, 16) < 0x0EFF:
                    detection.append("Lao")
                elif int(character, 16) < 0x0FFF:
                    detection.append("Tibetan")
                elif int(character, 16) < 0x109F:
                    detection.append("Myanmar")
                elif int(character, 16) < 0x10FF:
                    detection.append("Georgian")
                elif int(character, 16) < 0x11FF:
                    detection.append("Hangul")
                elif int(character, 16) < 0x137F:
                    detection.append("Ethiopic")
                elif int(character, 16) < 0x13FF:
                    detection.append("Cherokee")
                elif int(character, 16) < 0x167F:
                    detection.append("Canadian Aboriginal")
                elif int(character, 16) < 0x169F:
                    detection.append("Ogham")
                elif int(character, 16) < 0x16FF:
                    detection.append("Runic")
                elif int(character, 16) < 0x171F:
                    detection.append("Tagalog")
                elif int(character, 16) < 0x173F:
                    detection.append("Hanunoo")
                elif int(character, 16) < 0x175F:
                    detection.append("Buhid")
                elif int(character, 16) < 0x177F:
                    detection.append("Tagbanwa")
                elif int(character, 16) < 0x17FF:
                    detection.append("Khmer")
                elif int(character, 16) < 0x18AF:
                    detection.append("Mongolian")
                elif int(character, 16) < 0x194F:
                    detection.append("Limbu")
                elif int(character, 16) < 0x197F:
                    detection.append("Tai Le")
                elif int(character, 16) < 0x19FF:
                    detection.append("Khmer")
                elif int(character, 16) < 0x1EFF:
                    detection.append("English Latin Extended")
                elif int(character, 16) < 0x1FFF:
                    detection.append("Greek")
                elif int(character, 16) < 0x206F:
                    detection.append("English Latin Base")
                elif int(character, 16) < 0x209F:
                    detection.append("Super and Subscripts")
                elif int(character, 16) < 0x20CF:
                    detection.append("Currency Symbols")
                elif int(character, 16) < 0x21FF:
                    detection.append("Letterlike Symbols / Number Forms / Arrows")
                elif int(character, 16) < 0x2BFF:
                    detection.append("Symbols and Shapes")
                elif int(character, 16) > 0x2E80 and int(character, 16) < 0x2FFF:
                    detection.append("CJK Combined")
                elif int(character, 16) > 0x2FF0 and int(character, 16) < 0x2FFF:
                    detection.append("CJK Combined")
                elif int(character, 16) > 0x3040 and int(character, 16) < 0x309F:
                    detection.append("Hiragana")
                elif int(character, 16) > 0x30A0 and int(character, 16) < 0x30FF:
                    detection.append("Katakana")
                elif int(character, 16) > 0x4E000 and int(character, 16) < 0x9FBFF:
                    detection.append("CJK Combined")
                elif int(character, 16) > 0x4E000 and int(character, 16) < 0x9FFFF:
                    detection.append("CJK Combined")
                elif int(character, 16) > 0xAC00 and int(character, 16) < 0xD7AF:
                    detection.append("Hangul")
                elif int(character, 16) > 0xFB50 and int(character, 16) < 0xFDFF:
                    detection.append("Arabic")
                elif int(character, 16) > 0xFE20 and int(character, 16) < 0xFE6F:
                    detection.append("CJK Combined")
                elif int(character, 16) > 0xFE50 and int(character, 16) < 0xFE6F:
                    detection.append("English Latin Base")
                elif int(character, 16) > 0xFE70 and int(character, 16) < 0xFEFF:
                    detection.append("Arabic")
                elif int(character, 16) > 0x2F800 and int(character, 16) < 0x2FA1F:
                    detection.append("CJK Combined")
                else:
                    detection.append("Unidentified Other")
            except:
                try:

                    alphaVal = repr(backupchar.decode()).lstrip('\'\\\u').rstrip("'")
                    if re.match(isAlpha, alphaVal) is not None:
                        detection.append("English Latin Base")
                except:
                    detection.append("Extended Unicode (Emoji, Symbol or Other)")

    return sorted(set(detection))


def main():
    results = []
    output_results = []

    keywords,options = splunk.Intersplunk.getKeywordsAndOptions()
    results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()
    if not options.has_key('field'):
        output_result = splunk.Intersplunk.generateErrorResults("Usage: punydecode field=<field-to-decode> [detection]")
        splunk.Intersplunk.outputResults( output_result )
        exit(0)
    field = options.get('field', None)

    detect = None
    if 'detection' in keywords:
        detect = True

    try:
        for r in results:
            match = re.compile(r'[Xx][Nn]\-\-[\w\d\-\_]*')
            if field in r.keys():
                r['punydecoded'] = r[field]

                for item in re.findall(match, r[field]):
                    r['punydecoded'] = r['punydecoded'].replace(item, replace_xns(item.lower()))

                if detect:
                    r['detection'] = []
                    for item in re.findall(match, r[field].lower()):
                        r['detection'] = chardetect(item, r['detection'])
                    r['detection'] = sorted(set(r['detection']))
            output_results.append(r)

    except:
        import traceback
        stack =  traceback.format_exc()
        output_results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))

    splunk.Intersplunk.outputResults( output_results )

if __name__ == "__main__":
    main()
