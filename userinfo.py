# Volatility Userinfo plugin
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
@author  :        MaJ3stY
@license :        GNU General Public License 2.0 or later
@contect :        saiwnsgud@naver.com
@organization :    maj3sty.tistory.com
"""

import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks
from time import time
from urllib2 import unquote

site_list = ['facebook', 'google', 'daum', 'instagram', 'naver']
class userInfo(commands.Command):
    """The plugin user ID and password in the memory image acquisition plugin."""
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        self._config.add_option('NAME', short_option = 'n', default = None,
                                 help = "Process name to match",
                                 action = 'store', type = 'str')
        config.add_option('PID', short_option = 'p', default = None, help='Browser Process PID input plz', action='store', type='str')
        config.add_option('SITE', short_option = 's', default = None, help='Browser Process Site input plz -s facebook etc', action='store', type='str')

    def calculate(self):
        addr_space = utils.load_as(self._config)
        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() in ("iexplore.exe", "firefox", "firefox.exe", "chrome", "chrome.exe"):
                yield proc

    def Text_table(self, outfd, procData, vad_start, vad_length, site):
        for userId, userPw in self.Userinfo(procData, site):
            outfd.write(" [*] Vad Address Range : {0} ~ {1}\n".format(vad_start, vad_start+vad_length))
            outfd.write(" [*] {0} User Email : {1}\n".format(site, userId))
            outfd.write(" [*] {0} User Pass  : {1}\n\n".format(site, userPw))
   
    def parse_data(self, procData, email, pw, parse_end):
        userInfo = procData[procData.find(email):procData.find(parse_end)]
        if userInfo == '':
            pass
        else:
            userId = userInfo[userInfo.find(email)+len(email):userInfo.find(pw)]
            userPw = userInfo[userInfo.find(pw)+len(pw):]
            yield userId, userPw

    def Userinfo(self, procData, site):
        if site == 'facebook':
            for userId, userPw in self.parse_data(procData, '&email=', '&pass=', '&default_persistent='):
                yield userId, userPw

        elif site == 'google':
            for userId, userPw in self.parse_data(procData, '&Email=', '&Passwd=', '&signIn='):
                yield userId, unquote(userPw)

        elif site == 'instagram':
            for userId, userPw in self.parse_data(procData, '&mail=', '&Pass=', '&Signin='):
                yield userId, unquote(userPw)

        elif site == 'daum':
            for userId, userPw in self.parse_data(procData, '&id=', '&pw=', '&securityLevel='):
                yield userId, userPw

        elif site == 'naver':
            for userId, userPw in self.parse_data(procData, '&ID=', '&PWD=', '&SecurityLevel='):
                yield userId, userPw           

    def render_text(self, outfd, data):
        startTime = time()
        outfd.write('[PBL] **** Searching UserInfo in Memory Image!!! ****\n')
        for proc in data:
            if not self._config.PID == None and str(proc.UniqueProcessId) not in list(self._config.PID.split(',')):
                continue
            outfd.write("\n[+] Found Browser Process(PID) : {0}({1})\n".format(proc.ImageFileName, proc.UniqueProcessId))
            for vad, process_space in proc.get_vads():
                start = vad.Start
                offset = vad.Length
                processData = process_space.zread(start, offset)
                if processData == None:
                    if self._config.verbose:
                        outfd.write('[PBL] Memory Vad Range {0} ~ {1} Not Accessible\n'.format(start, start+offset))
                else:
                    if self._config.SITE == None:
                        for site in site_list:
                            self.Text_table(outfd, processData, start, offset, site)
                    else:
                        for site in list(self._config.SITE.split(',')):
                            self.Text_table(outfd, processData, start, offset, site)
        endTime = time()
        outfd.write("[PBL] Total Time : {0}\n\n".format(endTime-startTime))  
