#!/usr/bin/env python2.7
# 
# a wrapper for olevba since it is python2

import argparse
import codecs
import json
import os
import os.path
import sys
import traceback

parser = argparse.ArgumentParser(description="Analyzes a given file with olevba parser and saves the output in a useful way.")
parser.add_argument('file', help="The file to analyze.")
parser.add_argument('-d', '--output-dir', dest='output_dir', required=False, default=None,
    help="The directory to put the output.  Defaults to file_path.olevba")
parser.add_argument('--olevba-lib-path', dest='olevba_lib_path', required=False, default='/opt',
    help="Alternate directory of olevba library path.")
args = parser.parse_args()

if args.output_dir is None:
    args.output_dir = '{}.olevba'.format(args.file)

if not os.path.isdir(args.output_dir):
    os.makedirs(args.output_dir)

sys.path.append(args.olevba_lib_path)

from oletools.olevba import VBA_Parser, VBA_Scanner, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

result = {}

try:
    vba_parser = VBA_Parser(args.file)
    result['type'] = vba_parser.type
    
    if result['type'] not in [ TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML ]:
        sys.exit(0)

    #with open(os.path.join(args.output_dir, 'type'), 'w') as fp:
        #fp.write(vba_parser.type)
        #sys.stdout.write(os.path.join(args.output_dir, 'type') + '\n')

    if not vba_parser.detect_vba_macros():
        sys.exit(0)

except Exception, e:
    sys.exit(2)

# make a directory to put all the macros in
macro_dir = None

# extract all the macroses ;)
macro_index = 0
for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
    if not macro_dir:
        macro_dir = os.path.join(args.output_dir, 'macros')
        if not os.path.isdir(macro_dir):
            os.makedirs(macro_dir)

        result['macros'] = []

    macro_path = os.path.join(macro_dir, 'macro_{}.bas'.format(macro_index))
    macro_index += 1
    with open(macro_path, 'w') as fp:
        fp.write(vba_code)

    macro_json = {}
    macro_json['path'] = macro_path
    macro_json['filename'] = filename
    macro_json['stream_path'] = stream_path
    macro_json['vba_filename'] = unicode(vba_filename, 'utf-8', errors='replace')

    #sys.stdout.write(macro_path + '\n')

    #details_path = os.path.join(macro_dir, 'macro_{0}.details'.format(macro_index))
    #with codecs.open(details_path, 'w', encoding='unicode_escape') as fp:
        #try:
            #fp.write(u'filename: {0}\nstream_path: {1}\nvba_filename: {2}\n'.format(
                #filename,
                #stream_path, 
                #unicode(vba_filename, 'unicode_escape')))
        #except:
            #traceback.print_exc()

    #sys.stdout.write(details_path + '\n')

    macro_json['analysis'] = []

    scanner = VBA_Scanner(vba_code)
    #analysis_path = os.path.join(macro_dir, 'macro_{0}.analysis'.format(macro_index))
    kw_counts = {} # key = keyword, value = int
    #with open(analysis_path, 'w') as fp:
    for kw_type, keyword, description in scanner.scan(include_decoded_strings=True):
        macro_json['analysis'].append({'kw_type': unicode(kw_type, encoding='utf-8', errors='replace'), 
                                       'keyword': unicode(keyword, encoding='utf-8', errors='replace', ), 
                                       'description': unicode(description, 'utf-8', errors='replace')})
        #fp.write('{0}\t{1}\t{2}\n'.format(kw_type, keyword, description))
        if kw_type.lower() not in kw_counts:
            kw_counts[kw_type.lower()] = 0
        kw_counts[kw_type.lower()] += 1

    # generate a summary of the olevba keywords
    macro_json['olevba_summary'] = {}
    # and update a global summary of all of them
    if 'olevba_summary' not in result:
        result['olevba_summary'] = {}

    #sys.stdout.write(analysis_path + '\n')

    #summary_path = os.path.join(macro_dir, 'macro_{0}.summary'.format(macro_index))
    #with open(summary_path, 'w') as fp:
    for keyword in kw_counts.keys():
        macro_json['olevba_summary'][keyword] = kw_counts[keyword]
        if keyword not in result['olevba_summary']:
            result['olevba_summary'][keyword] = 0
        result['olevba_summary'][keyword] += kw_counts[keyword]
        #fp.write('{0}\t{1}\n'.format(keyword, str(kw_counts[keyword])))

    #sys.stdout.write(summary_path + '\n')

    result['macros'].append(macro_json)

sys.stdout.write(json.dumps(result).encode(errors='replace'))
