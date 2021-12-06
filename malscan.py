# Volatility Malscan plugin
#
# Copyright (C) 2013 MaJ3stY (saiwnsgud@naver.com)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author  	  : MaJ3stY
@license 	  :	GNU General Public License 2.0 or later
@contect 	  :	saiwnsgud@naver.com
@organization :	maj3sty.tistory.com
"""


import volatility.utils as utils
import volatility.plugins.procdump as procdump
import os, hashlib, httplib, urllib, urllib2, mimetypes, simplejson, sys, time

VT_API_KEY = ""
class malscan(procdump.ProcExeDump):
	"""Memory image of the process you want to check whether the plug-in virus infection"""
	def __init__(self, config, *args):
		procdump.ProcExeDump.__init__(self, config, *args)
		config.add_option('OFFSET', short_option = 'o', default = None, help = 'EPROCESS offset (in hex) in the physical address space', action = 'store', type = 'int')
		config.add_option('PID', short_option = 'p', default = None, help = 'Operate on these Process IDs (comma-separated)', action = 'store', type = 'str')
	
	def get_content_type(self, filename):
		    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

	def post_multipart(self, host, selector, fields, files):
		content_type, body = self.encode_multipart_formdata(fields, files)
		h = httplib.HTTP(host)
		h.putrequest('POST', selector)
		h.putheader('content-type', content_type)
		h.putheader('content-length', str(len(body)))
		h.endheaders()
		h.send(body)
		errcode, errmsg, headers = h.getreply()
		return h.file.read()

	def encode_multipart_formdata(self, fields, files):
		BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
		CRLF = '\r\n'
		L = []
		for (key, value) in fields:
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"' % key)
			L.append('')
			L.append(value)
		for (key, filename, value) in files:
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
			L.append('Content-Type: %s' % self.get_content_type(filename))
			L.append('')
			L.append(value)
		L.append('--' + BOUNDARY + '--')
		L.append('')
		body = CRLF.join(L)
		content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
		return content_type, body

	def upload_file(self, filename, file_to_send):
		if VT_API_KEY == "":
			print "[+] VT_API_KEY Not hard coding."
			sys.exit()

		host = "www.virustotal.com"
		selector = "http://www.virustotal.com/vtapi/v2/file/scan"
		fields = [("apikey", VT_API_KEY)]
		files = [("file", filename, file_to_send)]
		json = self.post_multipart(host, selector, fields, files)
		json_parse = simplejson.loads(json)
		return json_parse
		
	def report(self, resource):
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource" : resource, "apikey" : VT_API_KEY}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json = response.read()
		json_parse = simplejson.loads(json)
		return json_parse

	def calculate(self):
		if self._config.DUMP_DIR == None:
			print "\n[!] Process to dump in the current directory."
			self._config.DUMP_DIR = os.getcwd()
		if self._config.PID != None:
			print "\n[+] To start a process dump."
			result = procdump.ProcExeDump(self._config).execute()
			filename = self._config.DUMP_DIR + "/executable.{0}.exe".format(self._config.PID)
			try:
				f = open(filename, "rb")
				file_to_send = f.read()
				resource = hashlib.md5(file_to_send).hexdigest()
				f.close()
			except:
				print "\n[!] Process dump failed."
				sys.exit()
			try:
				print "\n[+] Run the file to start uploading." 
				if type(self.upload_file(filename, file_to_send)) == type(dict()):
					print "\n[+] Run the file upload is complete."
					print "\n[+] File analysis...(About 3 minutes)"
					time.sleep(180)
					report_result = self.report(resource)
					for key, value in report_result.items():
						if key == 'scans':
							break
						print key + " : " + str(value)
					print "\n\t  AV Name\t\tDetected\tResult"
					for key, value in report_result['scans'].items():
						yield key, str(value['detected']), str(value['result'])
				else:
					print "\n[+] Run the file upload is fail."
					sys.exit()
			except:
				print "\n[!] Run the file upload is fail."
				sys.exit()
				
		else:
			print "[!] -p <PID> option please"
			sys.exit()

	
	def render_text(self, outfd, data):
		self.table_header(outfd,
				[(" ", "<31"),
					(" ", "<15"),
					(" ", "<40")
					])
		for key, detected, result in data:
			self.table_row(outfd, key, detected, result)
