#!/usr/bin/env python
# -*- coding: utf-8 -*-

#TODO
# yellow - normal connection
# red - if possible presence of malware or blacklisted IP addr
# if warning, notification via pynotify
# + scapy module for sniffing ?
#TODO asap
# check traceroute backup and replot them when reseting map (new loop feature)
# check thread state before closing gui (crash if running)
# keep tack of fast ploting, don't remove plot that we have to replot because connection keep open

# from matplotlib.backends.backend_gtk import FigureCanvasGTK as FigureCanvas
# from matplotlib.backends.backend_gtkagg import FigureCanvasGTKAgg as FigureCanvas
# from matplotlib.backends.backend_gtkcairo import FigureCanvasGTKCairo as FigureCanvas
from matplotlib.backends.backend_gtkagg import FigureCanvasGTKAgg as FigureCanvas, error_msg_gtk
from matplotlib.backends.backend_gtkagg import NavigationToolbar2GTKAgg as NavigationToolbar
from mpl_toolkits.basemap import Basemap
from datetime import datetime
from copy import copy
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import numpy as np
import gobject
import gtk
import thread
from threading import Thread, Event
import GeoIP
import socket
import urllib2
import re
import os
import time

def save_figure_mod(self, *args):
    fname, format = self.get_filechooser().get_filename_from_user()
    if fname:
        try:
            self.canvas.print_figure(fname, format=format, facecolor='black', bbox_inches='tight', pad_inches=0)
        except Exception, e:
            error_msg_gtk(str(e), parent=self)

# To set facecolor='black' and bbox_inches='tight' because not by default
NavigationToolbar.save_figure = save_figure_mod

import_error = ''

from worldmap.core.constants import WORLDMAP_PATH
# from worldmap.core.db import IP

gobject.threads_init()
gtk.gdk.threads_init()

FONT = fm.FontProperties(fname='%s/core/inconsolata-dz.otf' % WORLDMAP_PATH)#data-control.ttf')

COLOR_LOW_RISK = '#2EFE2E'
COLOR_WARN_RISK = 'y'
COLOR_HIGH_RISK = 'r'
COLOR_A = '1.0'
COLOR_B = '0.8'
COLOR_C = '0.5'
COLOR_D = '0.1'
COLOR_E = '0.0'


class Netstat(object):
    def __init__(self, event, ui):
        # Thread.__init__(self)
        self.thread = Thread(target=self.run)
        self.stopped = event
        self.ui = ui

    def run(self):
        print "\nnetstat thread"
        print "##############"
        # self.netstat(self.ui)

        wait_period = 0.5
        while not self.stopped.wait(wait_period):
            print "\nnetstat thread loop"
            print "###################"
            self.netstat(self.ui)

            # Config parameter used here
            for row in self.ui.liststore_config:
                if row[0] == "Period between each monitor loop (in seconds)":
                    if unicode(row[1]).isnumeric():
                        wait_period = float(row[1])
                    break

            print "wait_period", wait_period

        self.stopped.clear()

    def netstat(self, ui):
    ### retrieves the netstat table from /proc/net/tcp
    ### does practicly the same as typing netstat into the terminal

        # print "#" * 50
        # # print ui.liststore_netstat
        # for elem_stored in ui.liststore_netstat:
        #     print "Source IP : %s" % elem_stored[1]
        #     print "Source Port : %s" % elem_stored[2]
        #     print "Destination IP : %s" % elem_stored[3]
        #     print "Destination Port : %s" % elem_stored[4]
        #     print "PID : %s" % elem_stored[5]
        #     print "#" * 25
        # # print ui.traceroutes
        # print "#" * 50

        # ui.liststore_netstat.clear()

        # ### most likely a Linux distribution
        # ### TCP section:
        # ### first lets write all the tcp connections into the database
        # fTcp = open("/proc/net/tcp", "r")
        # ### create a handle to the procfs tcp file
        # if fTcp:
        # ### fTcp will not None when we can open the file
        #     fTcp.readline()
        #     ### get rid of some (for the machine) useless information:
        #     ### the info we purge:"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
        #     for line in fTcp:
        #     ### read out the connections line by line and store them in the database
        #         ip_src, ip_dst, port_src, port_dst = self.decodeIpPort(line)
        #         ### decode
        #         if ip_src != None and ip_dst != None and port_src != None and port_dst != None:
        #         ### check that it return not None
        #             # print(ip_src, ip_dst, port_src, port_dst, 'TCP')
        #             ui.liststore_netstat.append([ip_src, port_src, ip_dst, port_dst, 'TCP'])
        # else:
        #     print "error opening /proc/net/tcp"
        # fTcp.close()
        # ### close /proc/net/tcp file handle
        #
        # ### UDP section:
        # fUdp = open("/proc/net/udp", "r")
        # # read top line with info
        # if fUdp:
        # ### fUdp will be not None if we can open the file
        #     fUdp.readline()
        #     for line in fUdp:
        #         ip_src, ip_dst, port_src, port_dst = self.decodeIpPort(line)
        #         if ip_src != None and ip_dst != None and port_src != None and port_dst != None:
        #         ### check that it return None so we know that there was no except
        #             # print(ip_src, port_src, ip_dst, port_dst, 'UDP')
        #             ui.liststore_netstat.append([ip_src, port_src, ip_dst, port_dst, 'UDP'])
        # else:
        #     print "error opening /proc/net/udp"
        # fUdp.close()
        # ### close /proc/net/udp file handle

        # see : https://psutil.googlecode.com/hg/examples/
        import psutil

        # print ui.m
        # ui.m = Basemap(ui.m_orig)
        # print ui.m
        for plot in ui.plot_handle:
            plot.remove()
        ui.plot_handle = []
        gtk.gdk.threads_enter()
        ui.canvas.draw()
        gtk.gdk.threads_leave()

        no_connection = True
        for pid in psutil.get_pid_list():
            try:
                p = psutil.Process(pid)
            except:
                pass
            finally:
                c = p.get_connections()
                if c:
                    # Delete closed connections from liststore
                    for y in ui.liststore_netstat:
                        connexion_closed = True
                        for x in c:
                            if x.status == "ESTABLISHED":
                                if y[1] == x.local_address[0]\
                                and int(y[2]) == x.local_address[1]\
                                and y[3] == x.remote_address[0]\
                                and int(y[4]) == x.remote_address[1]\
                                and int(y[5]) == pid:
                                    connexion_closed = False
                            else:
                                connexion_closed = False

                        if connexion_closed is True:
                            # print y[5]
                            # y.destroy()
                            ui.liststore_netstat.remove(y.iter)

                    for x in c:
                        # print x
                        if x.status == "ESTABLISHED":
                            no_connection = False
                            # Add connection in liststore if not already exist
                            already_stored = False
                            for y in ui.liststore_netstat:
                                # print "Source IP : %s" % y[1]
                                # print "Source Port : %s" % y[2]
                                # print "Destination IP : %s" % y[3]
                                # print "Destination Port : %s" % y[4]
                                # print "PID : %s" % y[5]

                                # print "- " * 50
                                # print "y[1]", type(y[1]), y[1]
                                # print "x.local_address[0]", type(x.local_address[0]), x.local_address[0]
                                # print "- " * 50
                                # print "y[2]", type(y[2]), y[2]
                                # print "x.local_address[1]", type(x.local_address[1]), x.local_address[1]
                                # print "- " * 50
                                # print "y[3]", type(y[3]), y[3]
                                # print "x.remote_address[2]", type(x.remote_address[0]), x.remote_address[0]
                                # print "- " * 50
                                # print "y[4]", type(y[4]), y[4]
                                # print "x.remote_address[3]", type(x.remote_address[1]), x.remote_address[1]
                                # print "- " * 50
                                # print "y[5]", type(y[5]), y[5]
                                # print "pid", type(pid), pid
                                # print "- " * 25

                                if y[1] == x.local_address[0]\
                                and int(y[2]) == x.local_address[1]\
                                and y[3] == x.remote_address[0]\
                                and int(y[4]) == x.remote_address[1]\
                                and int(y[5]) == pid:
                                    already_stored = True

                            # Add if not already present in liststore
                            if already_stored is False:
                                print "%s %s:%d -> %s:%d (PID:%d CMD:'%s')" % (x.status, x.local_address[0], x.local_address[1], x.remote_address[0], x.remote_address[1], pid, ' '.join(p.cmdline))
                                ui.liststore_netstat.append([x.status, x.local_address[0], x.local_address[1], x.remote_address[0], x.remote_address[1], pid, ' '.join(p.cmdline)])#[ip_src, port_src, ip_dst, port_dst, 'UDP'])

                            # Retrieve my IP address if i don't know it
                            if ui.myip is None:
                                instWeb = Web()
                                ui.myip = Web.getMyIp(instWeb)

                            # ui.traceroutes[x.remote_address[0]]['state'] = 'mapped'
                            # print "ui.traceroutes :", ui.traceroutes

                            if not ui.traceroutes.has_key(x.remote_address[0]) or not ui.traceroutes[x.remote_address[0]]['traceroute']:
                                ui.traceroutes[x.remote_address[0]] = {'traceroute': dict(), 'error': None, 'state': 'working'}

                            instWhois = Whois()
                            try:
                                myloc = Whois.ip2coor(instWhois, ui.myip)
                                dstloc = Whois.ip2coor(instWhois, x.remote_address[0])
                            except Exception as err:
                                ui.traceroutes[x.remote_address[0]]['error'] = str(err)
                                ui.traceroutes[x.remote_address[0]]['state'] = 'error'
                                print err

                            if myloc[0] is not None and dstloc[0] is not None:
                                if already_stored is False:
                                    print '-> location found'
                                # Config parameter used here
                                fast = True
                                for row in ui.liststore_config:
                                    if row[0] == "Fast geoloc (without route nodes)":
                                        if row[1] == "False":
                                            fast = False
                                        break

                                if fast:
                                    # Connectons
                                    xpt1, ypt1 = ui.m(myloc[0], myloc[1])
                                    xpt2, ypt2 = ui.m(dstloc[0], dstloc[1])
                                    ui.plot_handle.append(ui.m.plot([xpt1, xpt2], [ypt1, ypt2], 'k', color=COLOR_HIGH_RISK)[0])

                                    # Hops
                                    nicon = 'o'
                                    nsize = 6
                                    xpt, ypt = ui.m(myloc[0], myloc[1])
                                    ui.plot_handle.append(ui.m.plot(xpt, ypt, nicon, color=COLOR_LOW_RISK, markersize=nsize)[0])
                                    xpt, ypt = ui.m(dstloc[0], dstloc[1])
                                    ui.plot_handle.append(ui.m.plot(xpt, ypt, nicon, color=COLOR_HIGH_RISK, markersize=nsize)[0])

                                    ui.traceroutes[x.remote_address[0]]['state'] = 'fast mapped'

                                    gtk.gdk.threads_enter()
                                    ui.canvas.draw()
                                    gtk.gdk.threads_leave()
                                else:
                                    instTrace = Trace()
                                    thread.start_new_thread(Trace.traceroute, (instTrace, ui, x.remote_address[0]))
                            else:
                                print '-> location not found'
                                ui.traceroutes[x.remote_address[0]]['error'] = 'no location found'
                                ui.traceroutes[x.remote_address[0]]['state'] = 'error'
        if no_connection is True:
            ui.liststore_netstat.clear()

        # if ui.liststore_netstat is not None:
        #     instTrace = Trace()
        #     for connection in ui.liststore_netstat:
        #         # print connection[0]
        #         # print connection[1]
        #         # print connection[2]
        #         # print connection[3]
        #         # print connection[4]
        #         # print connection[5]
        #         # print connection[6]
        #         if not Trace.isPrivateIp(instTrace, connection[3]):
        #             # print connection[3]
        #             Trace.traceroute(instTrace, ui, connection[3])

    # def decodeIpPort(self, string):
    # ### decodes source and destination Ip:Port from the kernel format (byte format) into normal form (127.0.0.1)
    #     gap = 0
    #     if string[5] == ':':
    #         gap = 1
    #     if string[6] == ':':
    #         gap = 2
    #
    #     try:
    #     ### incase it was fed garbage
    #         # SOURCE IP ADDRESS
    #         ip_src = string[6:14]  # get the IP address in byte format: 0A 00 00 10 => 192.168.0.161
    #         ### when IP = 10.0.0.1 :> ipA = 10, ipB = 0, ipC = 0, ipD = 1
    #         ipA = int(ip_src[6] + ip_src[7], 16)
    #         ipB = int(ip_src[4] + ip_src[5], 16)
    #         ipC = int(ip_src[2] + ip_src[3], 16)
    #         ipD = int(ip_src[0] + ip_src[1], 16)
    #
    #         ip_src = str(ipA)+'.'+str(ipB)+'.'+str(ipC)+'.'+str(ipD)
    #         ### make a nice and formated ip like 127.0.0.1 of ipA.ipB.ipC.ipD
    #
    #         port_src = int(string[15+gap:19+gap], 16) # turn the port into an int
    #
    #         # DESTINATION IP ADDRESS
    #         ip_dst = string[20+gap:28+gap] # get the IP address in byte format: 0A 00 00 10 => 192.168.0.161
    #         ### when IP = 10.0.0.1 :> ipA = 10, ipB = 0, ipC = 0, ipD = 1
    #         ipA = int(ip_dst[6] + ip_dst[7], 16)
    #         ipB = int(ip_dst[4] + ip_dst[5], 16)
    #         ipC = int(ip_dst[2] + ip_dst[3], 16)
    #         ipD = int(ip_dst[0] + ip_dst[1], 16)
    #
    #         ip_dst = str(ipA)+'.'+str(ipB)+'.'+str(ipC)+'.'+str(ipD)
    #         ### make a nice and formated ip like 127.0.0.1 of ipA.ipB.ipC.ip
    #
    #         port_dst = int(string[29+gap:33+gap], 16) # destination port
    #
    #         return ip_src, ip_dst, port_src, port_dst
    #     except Exception as err:
    #         print "Error: %s" % err
    #         return None, None, None, None

class Whois:
    def ip2coor(self, ip):
    ### turns ip into coordinates/ returns lat and longitude

        pattern="(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)"

        regex_res = re.findall(pattern, ip)

        if len(regex_res):
            fDatabase_v6 = '%s/core/GeoLiteCityv6.dat' % WORLDMAP_PATH #instData.getGeoIPDatabase()
            ### get the database filename
            gi_v6 = GeoIP.open(fDatabase_v6, GeoIP.GEOIP_STANDARD)
            ### give us some GeoIP object
            gir_v6 = gi_v6.record_by_addr_v6(ip)
            ### lookup the ip
            if gir_v6 is not None:
                return gir_v6['longitude'], gir_v6['latitude']
            else:
                return None, None
        else:
            fDatabase = '%s/core/GeoLiteCity.dat' % WORLDMAP_PATH #instData.getGeoIPDatabase()
            ### get the database filename
            gi = GeoIP.open(fDatabase, GeoIP.GEOIP_STANDARD)
            ### give us some GeoIP object
            gir = gi.record_by_addr(ip)
            ### lookup the ip
            if gir is not None:
                return gir['longitude'], gir['latitude']
                ### return the latitude and longitude
            else:
                return None, None

    def ip2country(self, ip):
    ### turns ip into country

        pattern="(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)"

        regex_res = re.findall(pattern, ip)

        if len(regex_res):
            fDatabase_v6 = '%s/core/GeoLiteCityv6.dat' % WORLDMAP_PATH #instData.getGeoIPDatabase()
            ### get the database filename
            gi_v6 = GeoIP.open(fDatabase_v6, GeoIP.GEOIP_STANDARD)
            ### give us some GeoIP object
            gir_v6 = gi_v6.record_by_addr_v6(ip)
            ### lookup the ip
            if gir_v6 is not None and gir_v6.has_key('country_name') and gir_v6['country_name'] is not None:
                return gir_v6['country_name'].decode('latin1').encode('utf-8')
            else:
                return None
        else:
            fDatabase = '%s/core/GeoLiteCity.dat' % WORLDMAP_PATH
            gi  = GeoIP.open(fDatabase, GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_addr(ip)
            if gir is not None and gir.has_key('country_name') and gir['country_name'] is not None:
                return gir['country_name'].decode('latin1').encode('utf-8')
            else:
                return None

    def ip2region(self, ip):
    ### takes an ip and turns it into city

        pattern="(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)"

        regex_res = re.findall(pattern, ip)

        if len(regex_res):
            fDatabase_v6 = '%s/core/GeoLiteCityv6.dat' % WORLDMAP_PATH
            gi_v6 = GeoIP.open(fDatabase_v6, GeoIP.GEOIP_STANDARD)
            gir_v6 = gi_v6.record_by_addr_v6(ip)
            if gir_v6 is not None and gir_v6.has_key('region_name') and gir_v6['region_name'] is not None:
                return gir_v6['region_name'].decode('latin1').encode('utf-8')
            else:
                return None
        else:
            fDatabase = '%s/core/GeoLiteCity.dat' % WORLDMAP_PATH #instData.getGeoIPDatabase()
            gi  = GeoIP.open(fDatabase, GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_addr(ip)
            if gir is not None and gir.has_key('region_name') and gir['region_name'] is not None:
                return gir['region_name'].decode('latin1').encode('utf-8')
            else:
                return None

    def ip2city(self, ip):
    ### takes ip and return city

        pattern="(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)"

        regex_res = re.findall(pattern, ip)

        if len(regex_res):
            fDatabase_v6 = '%s/core/GeoLiteCityv6.dat' % WORLDMAP_PATH
            gi_v6 = GeoIP.open(fDatabase_v6, GeoIP.GEOIP_STANDARD)
            gir_v6 = gi_v6.record_by_addr_v6(ip)
            if gir_v6 is not None and gir_v6.has_key('city') and gir_v6['city'] is not None:
                return gir_v6['city'].decode('latin1').encode('utf-8')
            else:
                return None
        else:
            fDatabase = '%s/core/GeoLiteCity.dat' % WORLDMAP_PATH #instData.getGeoIPDatabase()
            gi  = GeoIP.open(fDatabase, GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_addr(ip)
            if gir is not None and gir.has_key('city') and gir['city'] is not None:
                return gir['city'].decode('latin1').encode('utf-8')
            else:
                return None

class Trace:
    def traceroute(self, ui, dest_addr, force=False):
        print "traceroute START"
        # TODO db historique dc check si traceroute existant
        # si traceroute connu (dst_ipaddr dans liste)
        # display it

        # TODO HERE FOR TREEVIEW LIST DEST IPADDR
        struct_time = time.localtime()
        timestamp_time = time.mktime(struct_time)
        if dest_addr not in [row[0] for row in ui.liststore_dest_conn]:
            ui.liststore_dest_conn.append([dest_addr])#, time.strftime("%d/%m/%Y %H:%M:%S", struct_time)])
        print "ui.traceroutes :", ui.traceroutes
        if ui.traceroutes.has_key(dest_addr) and ui.traceroutes[dest_addr]['traceroute'] and not force:
            ui.on_bpress_dst_conn(None, dest_addr)
        else:
            ui.traceroutes[dest_addr] = {'traceroute': dict(), 'time':timestamp_time, 'error': None, 'state': 'working'}

            # si traceroute inconnu (dst_ipaddr pas dans liste)
            # do it !
            ui.liststore_traceroute.clear()

            port = 33434
            # Config parameter used here
            max_traceroute = 30
            timeout = 30.0
            for row in ui.liststore_config:
                if row[0] == "End hop":
                    # if row[1] == "True":
                    #     print "is true"
                    if unicode(row[1]).isnumeric():
                        max_traceroute = int(row[1])
                        print "is int"
                        # print row[1], type(row[1])
                if row[0] == "Timeout (sec)":
                    # if row[1] == "True":
                    #     print "is true"
                    if unicode(row[1]).isnumeric():
                        timeout = float(row[1])
                        print "is int -> float"
                        # print row[1], type(row[1])
            socket.setdefaulttimeout(timeout) # TODO check & treeview config
            icmp = socket.getprotobyname('icmp')
            udp = socket.getprotobyname('udp')

            nodes = []
            #     {
            #         'ttl': 1,
            #         'hostname': 'toto',
            #         'ipaddr': ''
            #     },
            #     {
            #         'ttl': 2,
            #         'hostname': None,
            #         'ipaddr': None
            #     }
            # ]

            home = None
            myip = None
            parent = None
            ttl = 1
            while True:
                print "in LOOP ###############################"
                recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_socket.bind(('', port))
                send_socket.sendto('', (dest_addr, port))
                curr_addr = None
                curr_name = None
                hop = {'ipaddr': curr_addr,
                       'hostname': curr_name,
                       'time': time.mktime(time.localtime())}
                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    curr_addr = curr_addr[0]
                    hop['ipaddr'] = curr_addr

                    # Config parameter used here
                    resolv = True
                    for row in ui.liststore_config:
                        if row[0] == "DNS resolving":
                            if row[1] == "False":
                                print "is false"
                                resolv = False
                            break
                    
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                        hop['hostname'] = curr_name
                    except socket.error:
                        curr_name = None
                except Exception as err:
                    print "Error: %s" % err
                    ui.traceroutes[dest_addr]['error'] = str(err)
                    ui.traceroutes[dest_addr]['state'] = 'error'
                    print ui.traceroutes
                    break
                finally:
                    send_socket.close()
                    recv_socket.close()

                if curr_addr and curr_addr is not None:
                    print "[%s] %s : %s (%s)" % (str(ttl) if len(str(ttl)) == 2 else '0%d' % ttl, 'Private IP Address' if self.isPrivateIp(curr_addr) else 'Public IP Address', curr_name, curr_addr)
                else:
                    print "curr_addr is None !"
                    break

                instWhois = Whois()
                ipaddr = hop['ipaddr']
                if self.isPrivateIp(ipaddr):
                    if ui.myip is None:
                        instWeb = Web()
                        ui.myip = Web.getMyIp(instWeb)
                    ipaddr = ui.myip

                try:
                    hop['loc'] = Whois.ip2coor(instWhois, ipaddr)
                    hop['country'] = Whois.ip2country(instWhois, ipaddr)
                    hop['region'] = Whois.ip2region(instWhois, ipaddr)
                    hop['city'] = Whois.ip2city(instWhois, ipaddr)
                    print "location : %s %s, %s, %s, %s" % (hop['loc'][0], hop['loc'][1], hop['country'], hop['region'], hop['city'])
                except Exception as err:
                    print "Error: %s" % err
                    ui.traceroutes[dest_addr]['error'] = str(err)
                    ui.traceroutes[dest_addr]['state'] = 'error'
                    ui.traceroutes[dest_addr]['traceroute'][ttl] = hop
                    print ui.traceroutes
                else:
                    ui.traceroutes[dest_addr]['traceroute'][ttl] = hop
                    print ui.traceroutes

                    ui.liststore_traceroute.append([str(ttl),
                                                    hop['ipaddr'],
                                                    hop['hostname'] if hop['hostname'] is not None else "unavailable",
                                                    hop['country'] if hop['country'] is not None else "unavailable",
                                                    hop['region'] if hop['region'] is not None else "unavailable",
                                                    hop['city'] if hop['city'] is not None else "unavailable",
                                                    str(hop['loc'][0]) if hop['loc'][0] is not None else "unavailable",
                                                    str(hop['loc'][1]) if hop['loc'][1] is not None else "unavailable"])

                    # Connectons
                    if parent is not None:
                        if hop.has_key('loc') and parent.has_key('loc') and hop['loc'][0] is not None and parent['loc'][0] is not None:
                            # print "parent : %s" % parent
                            xpt1, ypt1 = ui.m(hop['loc'][0], hop['loc'][1])
                            xpt2, ypt2 = ui.m(parent['loc'][0], parent['loc'][1])
                            ui.plot_handle.append(ui.m.plot([xpt1, xpt2], [ypt1, ypt2], 'k', color=COLOR_WARN_RISK)[0])
                        # else:
                        #     pass # TODO do something ?

                    if not ui.ex_traceroute.get_expanded():
                        ui.ex_traceroute.set_expanded(True)

                    # plt.clf()
                    # ui.canvas = FigureCanvas(ui.fig) # TODO check reset canvas ?
                    # ui.m = copy(ui.m_bak)
                    # plt = copy(self.plt)
                    # plt.hold(False)

                    # Hops
                    nicon = 'o'
                    nsize = 6
                    # print "hop", hop
                    if hop['loc'][0] is not None:
                        if hop['city'] is None and hop['region'] is None and hop['country'] is not None:
                            # Country
                            print "# country"
                            nicon = '*'
                            nsize = 12
                            # circ = plt.Circle((hop['loc'][0], hop['loc'][1]), radius=20, color='y')
                            # ui.m.ax.add_patch(circ)
                            xpt, ypt = ui.m(hop['loc'][0], hop['loc'][1])
                            ui.plot_handle.append(ui.m.plot(xpt, ypt, nicon, color=COLOR_LOW_RISK if parent is None else COLOR_HIGH_RISK, markersize=nsize if parent is not None else 14)[0])
                        elif hop['city'] is None and hop['region'] is not None:
                            print "# region"
                            pass
                            #TODO region
                        elif hop['city'] is not None:
                            print "# city"
                            xpt, ypt = ui.m(hop['loc'][0], hop['loc'][1])
                            ui.plot_handle.append(ui.m.plot(xpt, ypt, nicon, color=COLOR_LOW_RISK if parent is None else COLOR_HIGH_RISK, markersize=nsize if parent is not None else 8)[0])
                            # plt.text(xpt+100000, ypt+100000, '', size=10 , color=COLOR_A, alpha=0.5, fontproperties=FONT)
                    else:
                        print "# ooops !"
                        ui.traceroutes[dest_addr]['state'] = 'waiting'
                        print hop

                    print "ui.traceroutes[dest_addr]['state'] :", ui.traceroutes[dest_addr]['state']

                    gtk.gdk.threads_enter()
                    ui.canvas.draw()
                    gtk.gdk.threads_leave()

                if curr_addr == dest_addr or ttl > max_traceroute: # TODO max configurable
                    ui.traceroutes[dest_addr]['state'] = 'mapped'
                    print "TRACEROUTE END"
                    break
                else:
                    # if ttl == 1:
                    #     home = hop
                    parent = hop
                    ttl += 1
                    print "next"

                    # # Home
                    # #TODO decide if we put the home node on the map here or not ...
                    # if home is not None and home.has_key('loc'):
                    #     print "variable home exist"
                    # else:
                    #     print "variable home don't exist"
                    #     # xhomept, yhomept = ui.m(home['loc'][0], home['loc'][1])
                    #     # ui.m.plot(xhomept, yhomept, 'o', color=COLOR_LOW_RISK, markersize=8)
                    #     # plt.text(xhomept+100000, yhomept+100000, home['hostname'], size=10, color=COLOR_A, fontproperties=FONT)

    def isPrivateIp(self, strIp):
        if (self.ipToInteger(strIp) >= self.ipToInteger("10.0.0.0") and self.ipToInteger(strIp) <= self.ipToInteger("10.255.255.255")):
            return 1
        if (self.ipToInteger(strIp) >= self.ipToInteger("172.16.0.0") and self.ipToInteger(strIp) <= self.ipToInteger("172.31.255.255")):
            return 1
        if (self.ipToInteger(strIp) >= self.ipToInteger("192.168.0.0") and self.ipToInteger(strIp) <= self.ipToInteger("192.168.255.255")):
            return 1
        if (self.ipToInteger(strIp) >= self.ipToInteger("127.0.0.0") and self.ipToInteger(strIp) <= self.ipToInteger("127.255.255.255")):
            return 1
        if (self.ipToInteger(strIp) == self.ipToInteger("0.0.0.0")):
            return 1
        return 0

    def ipToInteger(self, strIp):
        lstIp = strIp.split('.')
        res = (int(lstIp[0]) * pow(256,3)) + (int(lstIp[1]) * pow(256,2)) + (int(lstIp[2]) * pow(256,1)) + int(lstIp[3])
        return res

class Web:
    def req(self, url, http_proxy=None, timeout=30, retry=2):
        result = None
        if not timeout or timeout is None:
            timeout = 30
        if retry is None or retry < 0:
            retry = 2
        if http_proxy:
            # http://username:password@someproxyserver.com:1337
            http_proxy_full_auth_string = "http://%s:%s@%s:%s" % (http_proxy["user"],
                                                                  http_proxy["passwd"],
                                                                  http_proxy["server"],
                                                                  http_proxy["port"])
            proxy_handler = urllib2.ProxyHandler({"http": http_proxy_full_auth_string,
                                                  "https": http_proxy_full_auth_string})
            opener = urllib2.build_opener(proxy_handler)
            #urllib2.install_opener(opener)
        else:
            proxy_handler = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy_handler)

        postDatas = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                     "Cache-Control": "no-cache",
                     "Pragma": "no-cache"}

        request = urllib2.Request(url, None, postDatas)
        loop = 0
        while not result and loop <= retry:
            try:
                # Permet de passer par le proxy sans installer d'opener
                # (dans le mode interatif, "desactiver_proxy" ne fonctionne pas si on installe un opener)
                connection = opener.open(request, timeout=timeout)
            except Exception as err:
                # Si il y a une erreur de connexion (timeout etc.)
                print "Error with %s: %s" % (url, err)
            else:
                retcode = connection.getcode()
                # if retcode != 200:
                #     result.log("Mauvais code retourne par %s: %d" % (url, retcode), logging.ERROR)
                # else:
                # try:
                source = connection.read()
                # except Exception as err:
                #     # Si il y a une erreur de connexion (timeout etc.)
                #     result.add_error(err, "%s ne repond pas" % url)
                # else:
                connection.close()
                # if not source:
                #     result.log("La page retournee par %s est vide" % url, logging.ERROR)
                # else:
                if source:
                    # result.add_data(source, display=False)
                    result = source
                    break
            loop += 1
        return result

    def getMyIp(self, http_proxy=None, timeout=10, retry=2):
        #TODO HTTP request is not the appropriate solution for this, getting it directly from DNS server.
        # See http://unix.stackexchange.com/questions/22615/how-can-i-get-my-external-ip-address-in-bash/81699#81699
        myip = None
        for url in ("http://checkip.dyndns.com",
                    "http://ip.nu",
                    "http://whatismyip.net",
                    "http://www.whatismyip.org",
                    "http://whatthehellismyip.com/?ipraw"):
            source = self.req(url, http_proxy, timeout, retry)
            # print source
            if source:
                print "Webservice used to retrieve my IP address : %s" % str(url)
                resRegExpIp = re.compile("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)").findall(source)
                # print "len(resRegExpIp) : %d" % len(resRegExpIp)
                if len(resRegExpIp) == 1:
                    myip = '.'.join(resRegExpIp[0])
                    print "My IP address found : %s" % str(myip)
                    break
        return myip

class UI():
    def quitDialog(self, widget=None, data=None):
        if self.yesnoDialog("Do you really want to exit\nPython World Map ?"):
            self.toggle_netstat_loop_stopped.set()
            delete()
        else:
            return 1

    def yesnoDialog(self, message):
        # Creation de la boite de message
        # Type : Question -> gtk.MESSAGE_QUESTION
        # Boutons : 1 OUI, 1 NON -> gtk.BUTTONS_YES_NO
        question = gtk.MessageDialog(self.win,
                                     gtk.DIALOG_MODAL,
                                     gtk.MESSAGE_QUESTION,
                                     gtk.BUTTONS_YES_NO,
                                     message)

        # Affichage et attente d une reponse
        reponse = question.run()
        question.destroy()
        if reponse == gtk.RESPONSE_YES:
            return 1
        elif reponse == gtk.RESPONSE_NO:
            return 0

    def msgbox(self, message, type_msg=0):
        msgb = gtk.MessageDialog(self.win,
                                 gtk.DIALOG_MODAL,
                                 gtk.MESSAGE_WARNING if type_msg else gtk.MESSAGE_INFO,
                                 gtk.BUTTONS_OK,
                                 message)
        msgb.run() # Affichage de la boite de message
        msgb.destroy() # Destruction de la boite de message

    def build_context_menu(self, event, ui):
        # entries = [
        #         (gtk.STOCK_ADD, self.on_add_clicked,1),
        #         (gtk.STOCK_REMOVE, self.on_delete_clicked,0),
        #         (_("Edit"), self.on_edit_clicked,0),
        #     ]

        menu = gtk.Menu()
        # for stock_id,callback,sensitivity in entries:
        #     item = gtk.ImageMenuItem(stock_id)
        #     if callback:
        #         item.connect("activate",callback)
        #     item.set_sensitive(sensitivity)
        #     item.show()
        #     menu.append(item)

        # instNetstat = Netstat()
        # instWhois   = Whois()
        instTrace   = Trace()

        try:
            (model, pathlist) = self.treeview_netstat.get_selection().get_selected_rows()
            for path in pathlist :
                tree_iter = model.get_iter(path)
                ipdest = model.get_value(tree_iter, 3)
        except Exception as err:
            print "Error: %s" % err
        else:
            # print ipdest

            done = False
            force = False #TODO use it in config ?
            if ipdest in [row[0] for row in ui.liststore_dest_conn]:
                if ui.traceroutes.has_key(ipdest):
                    if ui.traceroutes[ipdest]['error']:
                        force = True
                    elif ui.traceroutes[ipdest].has_key('traceroute') and ui.traceroutes[ipdest]['traceroute']:
                        done = True

            item = gtk.MenuItem("traceroute" if not force else "force traceroute")
            item.connect("activate", lambda e: thread.start_new_thread(Trace.traceroute, (instTrace, self, ipdest, force)))
            item.set_sensitive(True if not done else False)
            item.show()
            menu.append(item)
            menu.popup(None,None,None,event.button,event.time)

    def on_bpress_netstat(self, treeview, event, ui):
        if event.type == gtk.gdk.BUTTON_PRESS and event.button == 3:
            x = int(event.x)
            y = int(event.y)
            time = event.time
            pthinfo = treeview.get_path_at_pos(x, y)
            if pthinfo is not None:
                path, col, cellx, celly = pthinfo
                treeview.grab_focus()
                treeview.set_cursor( path, col, 0)
                # self.popup.popup( None, None, None, event.button, time)
                self.build_context_menu(event, ui)
            return True

    def on_bpress_dst_conn(self, parent, ipaddr):
        self.liststore_traceroute.clear()
        if ipaddr is None:
            ipaddr = self.liststore_dest_conn.get_value(self.treeview_dest_conn.get_selection().get_selected()[1],0)
        for ttl in self.traceroutes[ipaddr]['traceroute'].keys():
            self.liststore_traceroute.append([str(ttl),
                                            self.traceroutes[ipaddr]['traceroute'][ttl]['ipaddr'],
                                            self.traceroutes[ipaddr]['traceroute'][ttl]['hostname'] if self.traceroutes[ipaddr]['traceroute'][ttl]['hostname'] is not None else "unavailable",
                                            self.traceroutes[ipaddr]['traceroute'][ttl]['country'] if self.traceroutes[ipaddr]['traceroute'][ttl]['country'] is not None else "unavailable",
                                            self.traceroutes[ipaddr]['traceroute'][ttl]['region'] if self.traceroutes[ipaddr]['traceroute'][ttl]['region'] is not None else "unavailable",
                                            self.traceroutes[ipaddr]['traceroute'][ttl]['city'] if self.traceroutes[ipaddr]['traceroute'][ttl]['city'] is not None else "unavailable",
                                            str(self.traceroutes[ipaddr]['traceroute'][ttl]['loc'][0]) if self.traceroutes[ipaddr]['traceroute'][ttl]['loc'][0] is not None else "unavailable",
                                            str(self.traceroutes[ipaddr]['traceroute'][ttl]['loc'][1]) if self.traceroutes[ipaddr]['traceroute'][ttl]['loc'][1] is not None else "unavailable"])
        return True

    def fct_rappel_expanse(self, expander_obj, event, vbox_obj):
        if expander_obj.get_expanded():
            (expand, fill, padding, pack_type) = vbox_obj.query_child_packing(expander_obj)
            vbox_obj.set_child_packing(expander_obj, 1, fill, padding, pack_type)
        else:
            (expand, fill, padding, pack_type) = vbox_obj.query_child_packing(expander_obj)
            vbox_obj.set_child_packing(expander_obj, 0, fill, padding, pack_type)


    def __init__(self):
        # We set a simple GTK window (not GTKAgg)
        self.win = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.win.set_resizable(True)
        self.win.set_title("Python World Map - Free-knowledge")
        self.win.connect("delete_event", self.quitDialog) # ask before close
        self.win.connect('key-press-event', lambda o, event: event.keyval == gtk.keysyms.F11 and self.toggle_fullscreen())
        self.win.set_icon_from_file("%s/images/icone.png" % WORLDMAP_PATH) # use an icon
        self.win.set_position(gtk.WIN_POS_CENTER)
        self.win.set_border_width(10)
        self.win.set_size_request(1000, 500)

        self.fullscreen = 0
        self.myip = None
        self.traceroutes = dict()

        self.plot_handle = []

        vbox = gtk.VBox(False, 0)
        self.win.add(vbox)

        hbox = gtk.HBox(True, 0)
        vbox.pack_start(hbox)

        vbox2 = gtk.VBox(homogeneous=False, spacing=0)

        paned = gtk.HPaned()
        paned.pack1(vbox2, resize=True, shrink=True)

        fig = plt.figure(dpi=100, facecolor=COLOR_E)
        fig.subplots_adjust(left=0, bottom=0, right=10, top=1, wspace=0, hspace=0)

        self.m = Basemap(projection='mill',llcrnrlat=-90,urcrnrlat=90, \
                    llcrnrlon=-180,urcrnrlon=180,resolution='c')

        self.m.ax = fig.add_axes([0, 0, 1, 1])

        self.m.drawcoastlines(linewidth=0.5, color=COLOR_B)
        self.m.drawcountries(linewidth=0.3, color=COLOR_C)
        self.m.drawmapboundary(fill_color=COLOR_E)

        # NASA Blue Map
        # self.m.bluemarble()

        # Draw parallels and meridians.
        # label parallels on right and top
        # meridians on bottom and left
        parallels = np.arange(0.,81,10.)
        self.m.drawparallels(parallels,labels=[False,False,False,False],linewidth=0.2,color=COLOR_C) #labels=[False,True,True,False]
        meridians = np.arange(10.,351.,20.)
        self.m.drawmeridians(meridians,labels=[False,False,False,False],linewidth=0.2,color=COLOR_C) #labels=[True,False,False,True]

        # Shade the night areas, with alpha transparency so the
        # map shows through. Use current time in UTC.
        date = datetime.utcnow()
        self.m.nightshade(date, color=COLOR_D)

        # self.m_orig = Basemap(self.m)

        # $ traceroute google.fr
        # traceroute to google.fr (173.194.34.56), 30 hops max, 60 byte packets
        # 2   (88.160.129.254)  28.646 ms  28.727 ms  29.265 ms
        # 3   (213.228.19.254)  29.418 ms  35.948 ms *
        # 4  th2-crs16-1-be1004.intf.routers.proxad.net (212.27.57.10)  36.599 ms  37.313 ms  38.176 ms
        # 5   ()  38.210 ms  38.339 ms  38.743 ms
        # 6   ()  136.876 ms  133.760 ms 74.125.50.116 (74.125.50.116)  135.239 ms
        # 7  * 72.14.238.234 (72.14.238.234)  34.053 ms  34.070 ms
        # 8  209.85.242.47 (209.85.242.47)  33.819 ms  34.928 ms  34.939 ms
        # 9  par03s03-in-f24.1e100.net (173.194.34.56)  35.522 ms  35.538 ms  36.275 m

        # Set the legend
        p1, = plt.plot(-10, -10, 'o', color=COLOR_LOW_RISK, label="you", markersize=10)
        p2, = plt.plot(-10, -10, 'k', color=COLOR_WARN_RISK, label="connection")
        p3, = plt.plot(-10, -10, 'o', color=COLOR_HIGH_RISK, label="geoloc < country")
        p4, = plt.plot(-10, -10, '*', color=COLOR_HIGH_RISK, label="geoloc = country", markersize=12)
        plt.plot(0, 'o', color="black", markersize=15)
        plt.legend([p1, p2, p3, p4], [p1.get_label(), p2.get_label(), p3.get_label(), p4.get_label()], loc=3, borderaxespad=0.5, shadow=True, fancybox=True, numpoints=1)
        # set some legend properties.  All the code below is optional.  The
        # defaults are usually sensible but if you need more control, this
        # shows you how
        leg = plt.gca().get_legend()
        ltext  = leg.get_texts() # all the text.Text instance in the legend
        llines = leg.get_lines() # all the lines.Line2D instance in the legend
        frame  = leg.get_frame() # the patch.Rectangle instance surrounding the legend
        # see text.Text, lines.Line2D, and patches.Rectangle for more info on
        # the settable properties of lines, text, and rectangles
        frame.set_edgecolor(COLOR_D) # set the edge face color to white
        frame.set_facecolor(COLOR_E) # set the frame face color to light gray
        plt.setp(ltext, fontproperties=FONT)
        plt.setp(ltext, fontsize=8) # the legend text fontsize
        plt.setp(ltext, color=COLOR_A) # the legend text fontsize
        plt.setp(llines, linewidth=1.5) # the legend linewidth
        # leg.draw_frame(False) # don't draw the legend frame

        # Set a title
        #plt.title('Day/Night Network activities Map (%s UTC)' % date.strftime("%d-%m-%Y %H:%M:%S"))

        # Create the widget, a FigureCanvas containing our Figure
        self.canvas = FigureCanvas(fig) # a gtk.DrawingArea
        # self.canvas.set_size_request(self.canvas.size_request()[0],int(self.canvas.size_request()[0]*1.2))
        toolbar = NavigationToolbar(self.canvas, self.win)
        vbox2.pack_start(toolbar, False, False)
        vbox2.pack_start(self.canvas)

        # instNetstat = Netstat()
        instWhois   = Whois()
        instTrace   = Trace()

        # self.btn_monitor
        self.btn_monitor = gtk.ToolButton(gtk.STOCK_MEDIA_PLAY)
        self.btn_monitor.set_tooltip_text("Monitor Connections")
        # self.btn_monitor.connect('clicked', lambda e: thread.start_new_thread(self.geoloc, ()))

        self.toggle_netstat_loop_stopped = Event()
        self.toggle_netstat_loop_state = False

        self.btn_monitor.connect('clicked', lambda e: self.toggle_netstat_loop())
        # self.btn_monitor.connect('clicked', lambda e: thread.start_new_thread(Netstat.netstat, (instNetstat, self)))
        # self.btn_monitor.connect('clicked', lambda e: thread.start_new_thread(Netstat.netstat, (instNetstat, self)))
        toolbar.insert(self.btn_monitor, -1)
        # toolbar.remove(toolbar.get_children()[6])
        # toolbar.remove(toolbar.get_children()[8])

        #TODO
        # gtk.STOCK_MEDIA_NEXT
        # gtk.STOCK_MEDIA_PREVIOUS
        # gtk.STOCK_MEDIA_STOP
        # gtk.STOCK_MEDIA_PAUSE
        # gtk.STOCK_MEDIA_PLAY
        # gtk.STOCK_MEDIA_RECORD

        toolbar.show_all()

        vb_expanders = gtk.VBox(False, 5)

        # Netstat
        ex_netstat = gtk.Expander("<b>CONNECTIONS</b>")
        ex_netstat.set_expanded(True)
        ex_netstat.props.use_markup = True

        vb_netstat = gtk.VBox(False, 5)
        ex_netstat.add(vb_netstat)
        ex_netstat.connect('notify::expanded', self.fct_rappel_expanse, vb_expanders)
        vb_expanders.pack_start(ex_netstat, expand=True, fill=True) ###

        hb_netstat = gtk.HBox(False, 0)

        # self.liststore_netstat
        self.liststore_netstat = gtk.ListStore(str, str, str, str, str, str, str)
        # scrollbar_sortie_monitor
        scrolled_netstat = gtk.ScrolledWindow()
        hb_netstat.pack_start(scrolled_netstat, True, True, 0)
        scrolled_netstat.show()
        # treeasview_sortie_monitor
        self.treeview_netstat = gtk.TreeView(self.liststore_netstat)
        self.treeview_netstat.connect('button-press-event', self.on_bpress_netstat, self)

        self.treeview_netstat.set_rules_hint(True)
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Status", gtk.CellRendererText(), text=0))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Src IP", gtk.CellRendererText(), text=1))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Src Port", gtk.CellRendererText(), text=2))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Dst IP", gtk.CellRendererText(), text=3))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Dst Port", gtk.CellRendererText(), text=4))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("PID", gtk.CellRendererText(), text=5))
        self.treeview_netstat.append_column(gtk.TreeViewColumn("Command", gtk.CellRendererText(), text=6))
        # ip_src, port_src, ip_dst, port_dst, 'TCP/UDP'
        self.treeview_netstat.set_headers_visible(True)
        # self.treeview_netstat.connect("cursor-changed", locHistory)
        scrolled_netstat.add(self.treeview_netstat)
        scrolled_netstat.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.treeview_netstat.show()

        vb_netstat.pack_start(hb_netstat, True)
        vb_netstat.set_size_request(350, self.canvas.size_request()[0])

        # Traceroute
        self.ex_traceroute = gtk.Expander("<b>TRACEROUTE</b>")
        # self.ex_traceroute.connect('notify::expanded', self.fct_rappel_expanse)
        self.ex_traceroute.set_expanded(False) # expand=False with that
        self.ex_traceroute.props.use_markup = True

        vb_traceroute = gtk.VBox(False, 5)
        self.ex_traceroute.add(vb_traceroute)
        self.ex_traceroute.connect('notify::expanded', self.fct_rappel_expanse, vb_expanders)
        vb_expanders.pack_start(self.ex_traceroute, expand=False, fill=True) ###

        # hb_traceroute = gtk.HBox(True, 0)
        paned_traceroute = gtk.HPaned()

        # self.liststore_traceroute
        self.liststore_traceroute = gtk.ListStore(str, str, str, str, str, str, str, str)
        scrolled_traceroute = gtk.ScrolledWindow()
        # hb_traceroute.pack_start(scrolled_traceroute, True, True, 0)
        paned_traceroute.pack1(scrolled_traceroute, resize=True, shrink=True) # TODO
        scrolled_traceroute.show()
        # treeasview_traceroute
        treeview_traceroute = gtk.TreeView(self.liststore_traceroute)
        treeview_traceroute.set_rules_hint(True)
        # [str(hop['ttl']),
        #  hop['ipaddr'],
        #  hop['hostname'] if hop['hostname'] is not None and hop['hostname'] is not hop['ipaddr'] else "unavailable",
        #  hop['country'] if hop['country'] is not None else "unavailable",
        #  hop['region'] if hop['region'] is not None else "unavailable",
        #  hop['city'] if hop['city'] is not None else "unavailable",
        #  str(hop['loc'][0]),
        #  str(hop['loc'][1])]
        treeview_traceroute.append_column(gtk.TreeViewColumn("TTL", gtk.CellRendererText(), text=0))
        treeview_traceroute.append_column(gtk.TreeViewColumn("IP", gtk.CellRendererText(), text=1))
        treeview_traceroute.append_column(gtk.TreeViewColumn("Hostname", gtk.CellRendererText(), text=2))
        treeview_traceroute.append_column(gtk.TreeViewColumn("Country", gtk.CellRendererText(), text=3))
        treeview_traceroute.append_column(gtk.TreeViewColumn("Region", gtk.CellRendererText(), text=4))
        treeview_traceroute.append_column(gtk.TreeViewColumn("City", gtk.CellRendererText(), text=5))
        treeview_traceroute.append_column(gtk.TreeViewColumn("Latitude0", gtk.CellRendererText(), text=6))
        treeview_traceroute.append_column(gtk.TreeViewColumn("Longitude", gtk.CellRendererText(), text=7))
        treeview_traceroute.set_headers_visible(True)
        # treeview_traceroute.connect("cursor-changed", locHistory)
        scrolled_traceroute.add(treeview_traceroute)
        scrolled_traceroute.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        treeview_traceroute.show()

        # self.liststore_dest_conn
        self.liststore_dest_conn = gtk.ListStore(str)#, str)
        scrolled_dest_conn = gtk.ScrolledWindow()
        # hb_traceroute.pack_start(scrolled_dest_conn, True, True, 0)
        paned_traceroute.pack2(scrolled_dest_conn, resize=False, shrink=True) # TODO paned.pack2(vb_expanders, resize=False, shrink=True)
        scrolled_dest_conn.show()
        # treeasview_dest_conn
        self.treeview_dest_conn = gtk.TreeView(self.liststore_dest_conn)
        self.treeview_dest_conn.set_rules_hint(True)
        # [str(hop['ttl']),
        #  hop['ipaddr'],
        #  hop['hostname'] if hop['hostname'] is not None and hop['hostname'] is not hop['ipaddr'] else "unavailable",
        #  hop['country'] if hop['country'] is not None else "unavailable",
        #  hop['region'] if hop['region'] is not None else "unavailable",
        #  hop['city'] if hop['city'] is not None else "unavailable",
        #  str(hop['loc'][0]),
        #  str(hop['loc'][1])]
        self.treeview_dest_conn.append_column(gtk.TreeViewColumn("Dst IP", gtk.CellRendererText(), text=0))
        # self.treeview_dest_conn.append_column(gtk.TreeViewColumn("time", gtk.CellRendererText(), text=1))
        self.treeview_dest_conn.set_headers_visible(True)
        # self.treeview_dest_conn.connect("cursor-changed", locHistory)
        self.treeview_dest_conn.connect('cursor-changed', self.on_bpress_dst_conn, None)
        scrolled_dest_conn.add(self.treeview_dest_conn)
        scrolled_dest_conn.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_dest_conn.set_size_request(90, scrolled_dest_conn.size_request()[0])
        self.treeview_dest_conn.show()

        vb_traceroute.pack_start(paned_traceroute, True) # TODO hb_traceroute
        # vb_traceroute.set_size_request(500, 100)
        vb_traceroute.set_size_request(350, self.canvas.size_request()[0])

        # # HTTP Headers
        # ex_http_headers = gtk.Expander("<b>HTTP Headers</b>")
        # ex_http_headers.set_expanded(False)
        # ex_http_headers.props.use_markup = True
        #
        # vb_http_headers = gtk.VBox(False, 5)
        # ex_http_headers.add(vb_http_headers)
        # vb_expanders.pack_start(ex_http_headers, False, True)
        #
        # hb_http_headers = gtk.HBox(False, 0)
        #
        # # liststore_http_headers
        # liststore_http_headers = gtk.ListStore(str, str, str, str, str)
        # # scrollbar_sortie_monitor
        # scrolled_http_headers = gtk.ScrolledWindow()
        # hb_http_headers.pack_start(scrolled_http_headers, True, True, 0)
        # scrolled_http_headers.show()
        # # treeasview_http_headers
        # treeview_http_headers = gtk.TreeView(liststore_http_headers)
        # treeview_http_headers.set_rules_hint(True)
        # treeview_http_headers.append_column(gtk.TreeViewColumn("@IP Src", gtk.CellRendererText(), text=0))
        # treeview_http_headers.append_column(gtk.TreeViewColumn("Port Src", gtk.CellRendererText(), text=1))
        # treeview_http_headers.append_column(gtk.TreeViewColumn("@IP Dst", gtk.CellRendererText(), text=2))
        # treeview_http_headers.append_column(gtk.TreeViewColumn("Port Dst", gtk.CellRendererText(), text=3))
        # treeview_http_headers.append_column(gtk.TreeViewColumn("Proto", gtk.CellRendererText(), text=4))
        # # ip_src, port_src, ip_dst, port_dst, 'TCP/UDP'
        # treeview_http_headers.set_headers_visible(True)
        # # treeview_http_headers.connect("cursor-changed", locHistory)
        # scrolled_http_headers.add(treeview_http_headers)
        # scrolled_http_headers.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        # treeview_http_headers.show()
        #
        # vb_http_headers.pack_start(hb_http_headers, True)
        # vb_http_headers.set_size_request(350, vb_http_headers.size_request()[1])

        # Config
        self.ex_config = gtk.Expander("<b>CONFIG</b>")
        self.ex_config.set_expanded(False) # expand=False with that
        self.ex_config.props.use_markup = True

        vb_config = gtk.VBox(False, 5)
        self.ex_config.add(vb_config)
        self.ex_config.connect('notify::expanded', self.fct_rappel_expanse, vb_expanders)
        vb_expanders.pack_start(self.ex_config, expand=False, fill=True) ###

        hb_config = gtk.HBox(True, 0)

        # self.liststore_config
        self.liststore_config = gtk.ListStore(str, str)
        # scrollbar_sortie_monitor
        scrolled_config = gtk.ScrolledWindow()
        hb_config.pack_start(scrolled_config, True, True, 0)
        scrolled_config.show()
        # treeasview_config
        treeview_config = gtk.TreeView(self.liststore_config)
        treeview_config.set_rules_hint(True)
        # [str(hop['ttl']),
        #  hop['ipaddr'],
        #  hop['hostname'] if hop['hostname'] is not None and hop['hostname'] is not hop['ipaddr'] else "unavailable",
        #  hop['country'] if hop['country'] is not None else "unavailable",
        #  hop['region'] if hop['region'] is not None else "unavailable",
        #  hop['city'] if hop['city'] is not None else "unavailable",
        #  str(hop['loc'][0]),
        #  str(hop['loc'][1])]
        treeview_config.append_column(gtk.TreeViewColumn("option", gtk.CellRendererText(), text=0))
        self.renderer = gtk.CellRendererText()
        self.renderer.set_property('editable', True)
        self.renderer.connect('edited', self.config_edited, self.liststore_config)
        treeview_config.append_column(gtk.TreeViewColumn("value", self.renderer, text=1))
        treeview_config.set_headers_visible(True)
        # treeview_config.connect("cursor-changed", locHistory)
        scrolled_config.add(treeview_config)
        scrolled_config.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        treeview_config.show()

        vb_config.pack_start(hb_config, True)
        # vb_config.set_size_request(500, 100)
        vb_config.set_size_request(350, self.canvas.size_request()[0])

        self.liststore_config.append(["Start hop", "1"])
        self.liststore_config.append(["End hop", "30"])
        # self.liststore_config.append(["Pkt. size", "32"])
        self.liststore_config.append(["Timeout (sec)", "10"])
        self.liststore_config.append(["Retry", "2"])
        self.liststore_config.append(["DNS resolving", "True"])
        # self.liststore_config.append(["Don't fragment", "True"])
        self.liststore_config.append(["Fast geoloc (without route nodes)", "True"])
        self.liststore_config.append(["Period between each monitor loop (in seconds)", "10"])

        treeview_config.set_sensitive(True) #TODO BACK TO WORK HERE

        paned.pack2(vb_expanders, resize=False, shrink=True)
        hbox.pack_start(paned, True, True, 0)

    def config_edited(self, cell, path, new_text, model):
        if model[path][1] == new_text:
            print "Option '%s' no change: '%s'" % (model[path][0], model[path][1])
        else:
            if model[path][0] in ["DNS resolving", "Don't fragment", "Fast geoloc (without route nodes)"]:
                if new_text[0].lower() == 't':
                    new_text = 'True'
                elif new_text[0].lower() == 'f':
                    new_text = 'False'
                else:
                    new_text = model[path][1]
                if model[path][1] == new_text:
                    print "Option '%s' no change: '%s'" % (model[path][0], model[path][1])
                else:
                    print "Option '%s' change: '%s' to '%s'" % (model[path][0], model[path][1], new_text)
            else:
                if unicode(new_text).isnumeric():
                    print "Option '%s' change: '%s' to '%s'" % (model[path][0], model[path][1], new_text)
                else:
                    print "Option '%s' no change: '%s'" % (model[path][0], model[path][1])
                    new_text = model[path][1]

        model[path][1] = new_text

    def toggle_fullscreen(self):
        if self.fullscreen:
            self.win.unfullscreen()
            self.fullscreen+=1
        else:
            self.win.fullscreen()
            self.fullscreen-=1

    def toggle_netstat_loop(self):
        if self.toggle_netstat_loop_state:
            self.toggle_netstat_loop_state = False
            self.btn_monitor.set_stock_id(gtk.STOCK_MEDIA_PLAY)
            self.toggle_netstat_loop_stopped.set()
        else:
            self.toggle_netstat_loop_state = True
            self.btn_monitor.set_stock_id(gtk.STOCK_MEDIA_PAUSE)
            netstat = Netstat(self.toggle_netstat_loop_stopped, self)
            netstat.thread.start()
        # print self.toggle_netstat_loop_state

def delete():
    """Gestion des evenements de fermeture"""
    exit() # but gtk.main_quit() fail with KeyboardInterrupt ...

def main():
    # Exécution
    try:
        u = UI()
        u.win.show_all()
        if os.name == "nt":
            gtk.gdk.threads_enter()
        gtk.main()
        if os.name == "nt":
            gtk.gdk.threads_leave()
    except (KeyboardInterrupt, SystemExit):
        u.toggle_netstat_loop_stopped.set()
        delete()
