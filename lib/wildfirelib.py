#!/usr/bin/env python3
# vim: sw=4:ts=4:et

import json
import logging
import os.path
import sys
import requests
import pprint
import hashlib
import time

try:
    import defusedexpat as expat
except ImportError:
    from xml.parsers import expat
from xml.sax.saxutils import XMLGenerator
from xml.sax.xmlreader import AttributesImpl
try:  # pragma no cover
    from cStringIO import StringIO
except ImportError:  # pragma no cover
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO
try:  # pragma no cover
    from collections import OrderedDict
except ImportError:  # pragma no cover
    try:
        from ordereddict import OrderedDict
    except ImportError:
        OrderedDict = dict

try:  # pragma no cover
    _basestring = basestring
except NameError:  # pragma no cover
    _basestring = str
try:  # pragma no cover
    _unicode = unicode
except NameError:  # pragma no cover
    _unicode = str

requests.packages.urllib3.disable_warnings()

class ParsingInterrupted(Exception):
    pass


class _DictSAXHandler(object):
    def __init__(self,
                 item_depth=0,
                 item_callback=lambda *args: True,
                 xml_attribs=True,
                 attr_prefix='@',
                 cdata_key='#text',
                 force_cdata=False,
                 cdata_separator='',
                 postprocessor=None,
                 dict_constructor=OrderedDict,
                 strip_whitespace=True,
                 namespace_separator=':',
                 namespaces=None,
                 force_list=None):
        self.path = []
        self.stack = []
        self.data = []
        self.item = None
        self.item_depth = item_depth
        self.xml_attribs = xml_attribs
        self.item_callback = item_callback
        self.attr_prefix = attr_prefix
        self.cdata_key = cdata_key
        self.force_cdata = force_cdata
        self.cdata_separator = cdata_separator
        self.postprocessor = postprocessor
        self.dict_constructor = dict_constructor
        self.strip_whitespace = strip_whitespace
        self.namespace_separator = namespace_separator
        self.namespaces = namespaces
        self.force_list = force_list

    def _build_name(self, full_name):
        if not self.namespaces:
            return full_name
        i = full_name.rfind(self.namespace_separator)
        if i == -1:
            return full_name
        namespace, name = full_name[:i], full_name[i+1:]
        short_namespace = self.namespaces.get(namespace, namespace)
        if not short_namespace:
            return name
        else:
            return self.namespace_separator.join((short_namespace, name))

    def _attrs_to_dict(self, attrs):
        if isinstance(attrs, dict):
            return attrs
        return self.dict_constructor(zip(attrs[0::2], attrs[1::2]))

    def startElement(self, full_name, attrs):
        name = self._build_name(full_name)
        attrs = self._attrs_to_dict(attrs)
        self.path.append((name, attrs or None))
        if len(self.path) > self.item_depth:
            self.stack.append((self.item, self.data))
            if self.xml_attribs:
                attr_entries = []
                for key, value in attrs.items():
                    key = self.attr_prefix+self._build_name(key)
                    if self.postprocessor:
                        entry = self.postprocessor(self.path, key, value)
                    else:
                        entry = (key, value)
                    if entry:
                        attr_entries.append(entry)
                attrs = self.dict_constructor(attr_entries)
            else:
                attrs = None
            self.item = attrs or None
            self.data = []

    def endElement(self, full_name):
        name = self._build_name(full_name)
        if len(self.path) == self.item_depth:
            item = self.item
            if item is None:
                item = (None if not self.data
                        else self.cdata_separator.join(self.data))

            should_continue = self.item_callback(self.path, item)
            if not should_continue:
                raise ParsingInterrupted()
        if len(self.stack):
            data = (None if not self.data
                    else self.cdata_separator.join(self.data))
            item = self.item
            self.item, self.data = self.stack.pop()
            if self.strip_whitespace and data:
                data = data.strip() or None
            if data and self.force_cdata and item is None:
                item = self.dict_constructor()
            if item is not None:
                if data:
                    self.push_data(item, self.cdata_key, data)
                self.item = self.push_data(self.item, name, item)
            else:
                self.item = self.push_data(self.item, name, data)
        else:
            self.item = None
            self.data = []
        self.path.pop()

    def characters(self, data):
        if not self.data:
            self.data = [data]
        else:
            self.data.append(data)

    def push_data(self, item, key, data):
        if self.postprocessor is not None:
            result = self.postprocessor(self.path, key, data)
            if result is None:
                return item
            key, data = result
        if item is None:
            item = self.dict_constructor()
        try:
            value = item[key]
            if isinstance(value, list):
                value.append(data)
            else:
                item[key] = [value, data]
        except KeyError:
            if self._should_force_list(key, data):
                item[key] = [data]
            else:
                item[key] = data
        return item

    def _should_force_list(self, key, value):
        if not self.force_list:
            return False
        try:
            return key in self.force_list
        except TypeError:
            return self.force_list(self.path[:-1], key, value)


def parse(xml_input, encoding=None, expat=expat, process_namespaces=False,
          namespace_separator=':', **kwargs):
    handler = _DictSAXHandler(namespace_separator=namespace_separator,
                              **kwargs)
    if isinstance(xml_input, _unicode):
        if not encoding:
            encoding = 'utf-8'
        xml_input = xml_input.encode(encoding)
    if not process_namespaces:
        namespace_separator = None
    parser = expat.ParserCreate(
        encoding,
        namespace_separator
    )
    try:
        parser.ordered_attributes = True
    except AttributeError:
        # Jython's expat does not support ordered_attributes
        pass
    parser.StartElementHandler = handler.startElement
    parser.EndElementHandler = handler.endElement
    parser.CharacterDataHandler = handler.characters
    parser.buffer_text = True
    try:
        parser.ParseFile(xml_input)
    except (TypeError, AttributeError):
        parser.Parse(xml_input, True)
    return handler.item


def _emit(key, value, content_handler,
          attr_prefix='@',
          cdata_key='#text',
          depth=0,
          preprocessor=None,
          pretty=False,
          newl='\n',
          indent='\t',
          full_document=True):
    if preprocessor is not None:
        result = preprocessor(key, value)
        if result is None:
            return
        key, value = result
    if (not hasattr(value, '__iter__')
            or isinstance(value, _basestring)
            or isinstance(value, dict)):
        value = [value]
    for index, v in enumerate(value):
        if full_document and depth == 0 and index > 0:
            raise ValueError('document with multiple roots')
        if v is None:
            v = OrderedDict()
        elif not isinstance(v, dict):
            v = _unicode(v)
        if isinstance(v, _basestring):
            v = OrderedDict(((cdata_key, v),))
        cdata = None
        attrs = OrderedDict()
        children = []
        for ik, iv in v.items():
            if ik == cdata_key:
                cdata = iv
                continue
            if ik.startswith(attr_prefix):
                if not isinstance(iv, _unicode):
                    iv = _unicode(iv)
                attrs[ik[len(attr_prefix):]] = iv
                continue
            children.append((ik, iv))
        if pretty:
            content_handler.ignorableWhitespace(depth * indent)
        content_handler.startElement(key, AttributesImpl(attrs))
        if pretty and children:
            content_handler.ignorableWhitespace(newl)
        for child_key, child_value in children:
            _emit(child_key, child_value, content_handler,
                  attr_prefix, cdata_key, depth+1, preprocessor,
                  pretty, newl, indent)
        if cdata is not None:
            content_handler.characters(cdata)
        if pretty and children:
            content_handler.ignorableWhitespace(depth * indent)
        content_handler.endElement(key)
        if pretty and depth:
            content_handler.ignorableWhitespace(newl)


class WfStreamServer(object):
    def __init__(self, api_key):
        """
        initialize the instance
        :param api_key: this is the wildfire service apikey provided by wildfire
        """
        self.api_key = api_key

    def submit_data(self,fname,data,jsonoutput=True):
        """
        This submits the contents of a file to wildfire for processing
        :param data: The bytes string of the file contents.
        :param jsonoutput: Boolean.  Defaults to True
        :return: If jsonoutput set to True, instead of a python dictionary, this function will return a json encoded string
        """
        print(fname)
        job = {
            "apikey": self.api_key
        }
        file = {
            "file" : (fname, data)
        }
        requesturl="https://wildfire.paloaltonetworks.com/publicapi/submit/file"
        r = requests.post(requesturl, data=job, files=file, verify=False)
        if r.status_code!=200:
            data={"status":r.status_code,"data":r.text}
        else:
            data = r.text
            data=parse(data)
        if jsonoutput:
            data=json.dumps(data)
        return data

    def submit(self, files, jsonoutput=True):
        """
        Submits one or more files to wildfire for processing.
        :param files: A list of one or more file paths to process.
        :param jsonoutput: Boolean.  Defaults to True
        :return: If jsonoutput set to True, instead of a list of python dictionaries, this function will return a list of json encoded data.
        """
        datalist=[]
        for filepath in files:
            with open(filepath,"rb") as f:
                data=f.read()
            ret=self.submit_data(os.path.basename(filepath),data,jsonoutput)
            datalist.append(ret)
        return datalist

    def verdictbyhash(self,hash,jsonoutput=True):
        """
        Gets a verdict from wildfire on a file based on its sha256 hash
        :param hash: The sha256 hash of the file to be queried
        :param jsonoutput: Boolean.  Defaults to True
        :return: If jsonoutput set to True, instead of a python dictionary, this function will return a json encoded string
        """
        requesturl = "https://wildfire.paloaltonetworks.com/publicapi/get/verdict"
        job = {
            "apikey": self.api_key,
            "hash": hash
        }
        r = requests.post(requesturl, data=job, verify=False)
        if r.status_code != 200:
            data = {"status": r.status_code, "data": r.text}
        else:
            data = r.text
            data = parse(data)
            verdict = data["wildfire"]["get-verdict-info"]["verdict"]
            data["wildfire"]["get-verdict-info"]["msg"] = {
                "0": "The file is benign",
                "1": "The file is malware",
                "2": "The file is grayware",
                "-100": "Pending.  The sample exists, but there is currently no verdict",
                "-101": "There is an error processing the file",
                "-102": "Unknown.  Cannot find sample record in the database"
            }.get(verdict, "Verdict code of " + verdict + " undefined")
        if jsonoutput:
            data = json.dumps(data)
        return data

    def verdictbyfile(self, files, jsonoutput=True):
        """
        Gets a verdict for one or more files specified.
        :param files: A list of one or more file paths to process.
        :param jsonoutput: Boolean.  Defaults to True
        :return: If jsonoutput set to True, instead of a list of python dictionaries, this function will return a list of json encoded data.
        """
        datalist=[]
        results=self.submit(files,False)
        for result in results:
            datalist.append(self.verdictbyhash(result["wildfire"]["upload-file-info"]["sha256"],jsonoutput))
        return datalist

    def reportbyhash(self,hash,jsonoutput=True):
        """
            Gets a report from wildfire on a file based on its sha256 hash
            :param hash: The sha256 hash of the file to be queried
            :param jsonoutput: Boolean.  Defaults to True
            :return: If jsonoutput set to True, instead of a python dictionary, this function will return a json encoded string
        """
        requesturl = "https://wildfire.paloaltonetworks.com/publicapi/get/report"
        job = {
            "apikey": self.api_key,
            "hash": hash
        }
        r = requests.post(requesturl, data=job, verify=False)
        if r.status_code != 200:
            data = {"status": r.status_code, "data": r.text}
        else:
            data = r.text
            data = parse(data)
        if jsonoutput:
            data = json.dumps(data)
        return data

    def reportbyfile(self, files, jsonoutput=True):
        """
            Gets a report for one or more files specified.
            :param files: A list of one or more file paths to process.
            :param jsonoutput: Boolean.  Defaults to True
            :return: If jsonoutput set to True, instead of a list of python dictionaries, this function will return a list of json encoded data.
        """
        datalist = []
        results = self.submit(files, False)
        for result in results:
            datalist.append(self.reportbyhash(result["wildfire"]["upload-file-info"]["sha256"],jsonoutput))
        return datalist


def write_json_section(outdir, process_list,section_key,json_name):
    results = []
    for item in process_list:
        if section_key in item:
            results.append(item[section_key])

    filename = os.path.join(outdir, json_name)
    with open(filename, "w") as f:
        json.dump(results, f)
        print(filename)

    

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(description="Submit one or more files to wildfireupload-file-infoupload-file-info for processing.")
    parser.add_argument('-a','--apikey',required=False,dest="api_key",default='2e2c9a2b743ece062e96aa3794ab52c5', help="The API key for the WildFire service.")
    parser.add_argument('-v','--verdict',dest="verdict",action="store_true",help="Get the verdict for specified files.")
    parser.add_argument('-r', '--report', dest="report", action="store_true",
                        help="Get the report for specified files.")
    parser.add_argument('-s', '--sha256', dest="hash", action="store_true", help="Instead of a filename, use a sha256 hash.")
    parser.add_argument('-o','--output-dir',dest="output",default='wildfire.out',help="Store output in outputdir as <sha256>.json report.<sha256.json> verdict.<sha256>.json")
    parser.add_argument('-f','--force-upload',dest="force_upload",action="store_true",default=True,help="If the report exists on wildfire it can be retrieved, but if we didn't upload it then it isn't available in the reports in the gui of wildfire.  This option will force the upload even if it exists.")
    parser.add_argument('files', nargs="+", help="One or more files to submit. If -s is specified, instead of a filepath, use a sha256 hash.  Only one sha256 hash can be specified at a time.")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] - %(message)s')
    #logging.basicConfig(level=logging.ERROR, format='[%(asctime)s] [%(levelname)s] - %(message)s')
    logging.getLogger("requests").setLevel(logging.WARNING)

    server = WfStreamServer(args.api_key)

    if args.hash and len(args.files)>1:
        logging.critical("Only one hash can be processed at a time using the --sha256 option.")
        sys.exit(2)
    if len(args.files) > 1:
        logging.critical("Only one file at a time is currently supported")

    pp=pprint.PrettyPrinter(indent=4)
    if not args.verdict and not args.report:
        os.makedirs(args.output,exist_ok=True)


        #submit file
        # already submitted?  Yes -> get report, No -> submit file, repeat
        if not args.hash:
            fhash = hashlib.sha256(open(args.files[0], 'rb').read()).hexdigest()
            running = 1
            while running:
                verdict = None
                if args.force_upload:
                    server.submit(args.files,False)  
                    args.force_upload = False  #only force the submit onece, if we are waiting for it to complete we don't want to upload again
                    time.sleep(3)

                verdict = json.loads(server.verdictbyhash(fhash))
                logging.info(verdict)
                #if file error (for example if the file type is not runnable by wildfire), exit
                if verdict['wildfire']['get-verdict-info']['verdict'] == '-101':
                    logging.critical("ERROR: upload or file type exited with errors")
                    logging.critical(str(verdict['wildfire']['get-verdict-info']['msg']))
                    sys.exit(2)
                #if file hasn't been submitted before, submit it, save upload info
                elif verdict['wildfire']['get-verdict-info']['verdict'] == '-102':
                    logging.info("submitting "+str(args.files))
                    upload = server.submit(args.files,False)
                    
                    if "error" in str(upload):
                        logging.critical("ERROR: upload or file type exited with errors")
                        logging.critical(upload)
                        sys.exit(2)
                    
                    upload = upload[0] #because wildfire allows multiple submissions, it returns a list of OrderedDict objects, we only want the first one
                    filename=os.path.join(args.output,upload["wildfire"]["upload-file-info"]["sha256"]+".json")
                    with open(filename,"w") as f:
                        json.dump(upload,f)
                    logging.info("saving upload response - "+filename)
                    time.sleep(5) #if you ask for a verdict right away it doesn't know you submitted it and will cause the file to be submitted a few times before the verdict shows that it is pending
                #if file has already been submitted, then wait
                elif verdict['wildfire']['get-verdict-info']['verdict'] == '-100':
                    logging.info("waiting for sandbox to complete")
                    time.sleep(10)
                #report is ready, pull the report and save it
                else:
                    logging.info("sandbox results complete")
                    report=server.reportbyhash(str(verdict["wildfire"]["get-verdict-info"]["sha256"]),False) 
                    filename = os.path.join(args.output, "report." + str(report["wildfire"]["file_info"]["sha256"]) + ".json")
                    logging.info("saving report to "+filename)
                    print(filename)
                    with open(filename, "w") as f:
                        json.dump(report, f)

                    write_json_section(args.output, report['wildfire']['task_info']['report'],'network',"report.network_"+str(report["wildfire"]["file_info"]["sha256"]) + ".json")
                    write_json_section(args.output, report['wildfire']['task_info']['report'],'process_tree',"report.processtree_"+str(report["wildfire"]["file_info"]["sha256"]) + ".json")

                    running = 0

        else:
            logging.critical("You cannot submit a file using a hash.")
            sys.exit(2)
            
    if args.verdict:
        if args.output:
            os.makedirs(args.output,exist_ok=True)
            if not args.hash:
                data=server.verdictbyfile(args.files,False)
            else:
                data=server.verdictbyhash(args.files[0],False)

            if not 'wildfire' in data:
                print(repr(data))
                sys.exit(1)
            filename=os.path.join(args.output,"verdict."+data["wildfire"]["get-verdict-info"]["sha256"]+".json")
            with open(filename,"w") as f:
                json.dump(data,f)
            print(str(data["wildfire"]["get-verdict-info"]["sha256"]) + " - " + str(data["wildfire"]["get-verdict-info"]["msg"]))
            print(filename)
        else:
            if not args.hash:
                pp.pprint(server.verdictbyfile(args.files,False))
            else:
                pp.pprint(server.verdictbyhash(args.files[0],False))


    if args.report:
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            if not args.hash:
                data = server.reportbyfile(args.files, False)
            else:
                data = server.reportbyhash(args.files[0], False)

            if not 'wildfire' in data:
                print(repr(data))
                sys.exit(1)
            filename = os.path.join(args.output, "report." + str(data["wildfire"]["file_info"]["sha256"]) + ".json")
            print(filename)
            with open(filename, "w") as f:
                json.dump(data, f)
        else:
            if not args.hash:
                pp.pprint(server.reportbyfile(args.files, False))
            else:
                pp.pprint(server.reportbyhash(args.files[0], False))
