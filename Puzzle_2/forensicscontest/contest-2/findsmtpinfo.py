#!/usr/bin/env python
import base64
import hashlib
import sys
import os.path, os
import socket
import subprocess
import shutil
import email, mimetypes, errno
from optparse import OptionParser
import zipfile
try:
    import dpkt
    import pcap
    use_dpkt=True
except:
    use_dpkt=False

def python_dpkt(pcapfile, pathofexport):
    reader = pcap.pcapObject()
    reader.open_offline(os.path.join(pathofexport, pcapfile))

    dataset=[]
    session_set = {}
    while True:
        try:
            (crap, payload, tts) = reader.next()
        except:
            break
        i =  dpkt.ethernet.Ethernet(payload)
        if hasattr(i.data, "p") and i.data.p == 6:
            ipd = i.data
            srcip, dstip = map(socket.inet_ntoa, (ipd.src, ipd.dst))
            tcpd = ipd.data
            session = "%s:%s-%s:%s" % (srcip, tcpd.sport, dstip, tcpd.dport)
            if session_set.has_key(session):
                session_set[session]['pkt'].append(ipd)
            else:
                session_set[session] = {'pkt':[],'raw':""}
                session_set[session]['pkt'] = [ipd]
            if hasattr(tcpd, "data"):
                session_set[session]['raw'] += tcpd.data
        
    for i in session_set.keys():
        f = open(os.path.join(pathofexport, "%s"%(i)), "wb")
        f.write(session_set[i]['raw'])
        f.close()

def tcpflow_dpkt(pcapfile, pathofexport):
    retcode = subprocess.call("(cd %s && tcpflow -r %s)"%(pathofexport, "raw.pcap"), shell=True)
 
class pcapReport(object):
    def __init__(self, pcapfile, pathofreport="./report", pcapProcesser=None):
        assert pcapfile
        if not os.path.exists(pcapfile):
            raise TypeError("Pcap file is not at path specified")
        self.reportRoot = pathofreport
        if not os.path.exists(self.reportRoot):
            os.makedirs(self.reportRoot)
        if not os.path.exists(os.path.join(self.reportRoot, "flows")):
            os.makedirs(os.path.join(self.reportRoot, "flows"))
        shutil.copyfile(pcapfile, os.path.join(self.reportRoot, "flows", "raw.pcap"))
        pcapProcesser("raw.pcap", os.path.join(self.reportRoot, "flows"))
        self.toProcess = {}
        self.streamcounter = 0
        self.txt_report = ""
        for i in os.listdir(os.path.join(self.reportRoot, "flows")):
            if "pcap" not in i:
                x = os.path.join(self.reportRoot, "flows", i)
                if os.path.isfile(x):
                    self.toProcess[i] = {}
                    self.toProcess[i]['raw'] = file(x).read().split("\r\n")

    def get_names(self):
        names = []
        classes = [self.__class__]
        while classes:
            aclass = classes.pop(0)
            if aclass.__bases__:
                 classes = classes + list(aclass.__bases__)
                 names = names + dir(aclass)
            return names

    def log(self, x):
        self.txt_report += x + "\n"

    def run(self):
        for aFile in self.toProcess.keys():
            self.processFile(aFile)
            self.reportFile(aFile)
        
        print self.txt_report
        print "-"*40
        print "Writing complete report to: %s"%(os.path.join(self.reportRoot, "output-report.txt"))
        f = open(os.path.join(self.reportRoot, "output-report.txt"), "w")
        f.write(self.txt_report)
        f.close()
        print "MD5 Hash of report: %s"%(hashlib.md5(self.txt_report).hexdigest())
        print "Finished"

    def processFile(self, aFile): 
        decoders = {}
        for i in self.get_names():
            try:
                holder,name = i.split("_", 1)
                if holder == "decode":
                    if decoders.has_key(name):
                        decoders[name]['decoder'] = getattr(self,i)
                    else: 
                        decoders[name] = {'decoder':getattr(self,i), 'points':0}
                elif holder == "process":
                    if decoders.has_key(name):
                        decoders[name]['processer'] = getattr(self,i)
                    else: 
                        decoders[name] = {'processer':getattr(self,i), 'points':0}
            except:
                pass
        for i in self.toProcess[aFile]['raw']:
            for name in decoders.keys():
                decoders[name]['points'] = decoders[name]['decoder'](aFile)
        
        protocolSelected = ""
        for name in decoders.keys():
            if not protocolSelected:
                protocolSelected = name
            elif decoders[name]['points'] > decoders[protocolSelected]['points']:
                protocolSelected = name

        self.toProcess[aFile]['ptype'] = protocolSelected
        return decoders[protocolSelected]['processer'](aFile)



    def reportFile(self, aFile):
        if hasattr(self, "report_%s"%(self.toProcess[aFile]['ptype'])):
            f = getattr(self, "report_%s"%(self.toProcess[aFile]['ptype']))
            return f(aFile)
        else:
            self.log("No Reporter found for type := %s"%(self.toProcess[aFile]['ptype']))


    def decode_SMTP(self, i):
        if i.startswith("EHLO") or i.startswith("HELO"):
            return 1
        elif i.startswith("MAIL FROM") or i.startswith("RCPT TO"):
            return 1
        else: 
            return 0
            
    def process_SMTP(self, aFile):
        a = False
        b = False
        for i in self.toProcess[aFile]['raw']:

            if a and i.startswith("MAIL FROM"):
                a = False
            if b and i == ".":
                b = False

            if a:
                self.toProcess[aFile]['logindata'].append(i)
            if b: 
                self.toProcess[aFile]['msgdata'].append(i)

            if i == "AUTH LOGIN": 
                a = True
                self.toProcess[aFile]['logindata'] = []
            if i == "DATA": 
                b = True
                self.toProcess[aFile]['msgdata'] = []
            if i.startswith("MAIL FROM:"):
                self.toProcess[aFile]['msg_from'] = i[11:]
            if i.startswith("RCPT TO:"):
                self.toProcess[aFile]['rcpt_to'] = i[9:]


    def report_SMTP(self, aFile):
        self.log("-"* 40)
        self.log(" Report: %s"%(aFile))
        self.log("-"* 40 + "\n")
        self.log("Found SMTP Session data")
        #self.log(toProcess[aFile].keys()

        if self.toProcess[aFile].has_key("logindata"):
            self.log("SMTP AUTH Login: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][0])))
            self.log("SMTP AUTH Password: %s"%(base64.decodestring(self.toProcess[aFile]['logindata'][1])))
        if self.toProcess[aFile].has_key('msg_from'):
            self.log("SMTP MAIL FROM: %s"%(self.toProcess[aFile]['msg_from']))
        if self.toProcess[aFile].has_key("rcpt_to"):
            self.log("SMTP RCPT TO: %s"%(self.toProcess[aFile]['rcpt_to']))
        if self.toProcess[aFile].has_key('msgdata'):
            self.streamcounter += 1
            if not os.path.exists(os.path.join(self.reportRoot, "messages", str(self.streamcounter))):
                os.makedirs(os.path.join(self.reportRoot, "messages", str(self.streamcounter)))
            
            x = "\r\n".join(self.toProcess[aFile]['msgdata'])
            msg = email.message_from_string(x)
            f = open(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.msg"%(aFile)), "w")
            f.write(x)
            f.close()
            self.log("Found email Messages")
            self.log(" - Writing to file: %s"%(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.msg"%(aFile))))
            self.log(" - MD5 of msg: %s"%(hashlib.md5(x).hexdigest()))
            counter = 1
            # The great docs at http://docs.python.org/library/email-examples.html 
            # show this easy way of breaking up a mail msg
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                filename = part.get_filename()
                if not filename:
                    ext = mimetypes.guess_extension(part.get_content_type())
                    if not ext:
                        ext = '.bin'
                    filename = 'part-%03d%s' % (counter, ext)
                part_data = part.get_payload(decode=True)
                part_hash = hashlib.md5()
                part_hash.update(part_data)
                self.log("   - Found Attachment" )
                self.log("     - Writing to filename: %s "%( os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename)))
                f = open(os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename), "wb")
                f.write(part_data)
                f.close()
                self.log("     - Type of Attachement: %s"%(part.get_content_type()))
                self.log("     - MDS of Attachement: %s"%(part_hash.hexdigest()))
                if filename.endswith(".zip") or filename.endswith(".docx"):
                    self.log("       - ZIP Archive attachment extracting")
                    if not os.path.exists(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename))):
                        os.makedirs(os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename)))
                    zfp = os.path.join(self.reportRoot, "messages", str(self.streamcounter), "%s.unzipped"%(filename))
                    zf = zipfile.ZipFile(os.path.join(self.reportRoot, "messages", str(self.streamcounter), filename))
                    for name in zf.namelist():
                        try:
                            (path,fname) = os.path.split(os.path.join(zfp, name))
                            os.makedirs(path)
                        except:
                            pass
                        f = open(os.path.join(path, fname), 'wb')
                        data = zf.read(name)
                        f.write(data)
                        self.log("         - Found file")
                        self.log("           - Writing to filename: %s"%(os.path.join(path, fname)))
                        self.log("           - Type of file: %s"%(mimetypes.guess_type(os.path.join(path, fname))[0]))
                        self.log("           - MDS of File: %s"%(hashlib.md5(data).hexdigest()))
if __name__ == '__main__':

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-p", "--pcap", dest="pcapfile", help="Filename of the of the pcap to process")
    parser.add_option("-r", '--report', dest="report", default="./report",
            help="Directory for reporting and processed output and Created if neededneeded [Default: ./report]")
    parser.add_option("-f", '--force', dest="force", default=False, action="store_true", help="Force overwriting of files and direcorties")
    (options, args) = parser.parse_args(sys.argv)
    if use_dpkt:
        pr = python_dpkt
    else:
        code = subprocess.call("which tcpflow", shell=True)
        if code == 0:
            pr = tcpflow_dpkt
        else:
            parser.error("""Python packages pylibpcap or dpkt could not be loaded and tcpflow 
command cannot be located in the current path.

To fix this issue please do one of the following:

1. Install python packages and dependencies:
  - http://code.google.com/p/dpkt/
  - http://pypi.python.org/pypi/pylibpcap/0.6.2

2. Install tcpflow and dependencies:
  - http://www.circlemud.org/~jelson/software/tcpflow/
""")
    if not options.pcapfile:
        parser.error("-p|--pcap option must be specified please see --help for more details")
    if not os.path.isfile(options.pcapfile):
        parser.error("-f|--file %s must already be present on the system and accessable"%(options.pcapfile))
    if options.report and os.path.isfile(options.report):
        parser.error("-r|--report %s is a file and cannot be used for report output"%(options.report))
    if options.report and os.path.isdir(options.report) and not options.force:
        if os.listdir(options.report):
            parser.error("-r|--report path of '%s' and other files are present, please use -f|--force to allow for overwriting (not advised)"%(options.report))
            
    
    x = pcapReport(options.pcapfile, options.report, pr)
    x.run()


