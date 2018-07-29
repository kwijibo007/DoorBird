#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################
# Copyright (c) 2018, Peter Dowles
# https://aushomeautomator.wordpress.com/Doorbird/


import logging
import socket
import pysodium
import datetime
import doorbirdpy
import time
import thread
import threading



################################################################################
class Plugin(indigo.PluginBase):
    ########################################
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
        self.debug = True

        # Configure logging
        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s',
                                 datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)

        try:
            self.logLevel = int(self.pluginPrefs[u"logLevel"])
        except:
            self.logLevel = logging.INFO
        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(u"logLevel = " + str(self.logLevel))
   
        
    ########################################
    def startup(self):
        
        doorbird = dict()
        motion = dict()
        doorbell = dict()
        
        
        for dev in indigo.devices.iter("self"):
            
            if dev.deviceTypeId == "doorbird":
                doorbird[dev.id] = dev
            elif dev.deviceTypeId == "motion":
                motion[dev.id] = dev
                dev.updateStateOnServer('onOffState',False)
            elif dev.deviceTypeId == "doorbell":
                doorbell[dev.id] = dev
                dev.updateStateOnServer('onOffState',False)
            else:
                pass
                
        for key, dev in doorbird.iteritems():   
            id = dev.id
            ip = dev.pluginProps["ip"]
            user = dev.pluginProps["user"]
            password = dev.pluginProps["password"]
            
            motionID = None
            for key, motionDev in motion.iteritems():
                if motionDev.pluginProps["motionDeviceID"] == str(id):
                    motionID = motionDev.id
            doorbellID = None
            for key, doorbellDev in doorbell.iteritems():
                if doorbellDev.pluginProps["doorbellDeviceID"] == str(id):
                    doorbellID = doorbellDev.id
                      
            self.doorbird(id, ip, user, password, self.logger, motionID, doorbellID)
    
    
    ########################################
    def __del__(self):
        indigo.PluginBase.__del__(self)

    ########################################
    def runConcurrentThread(self):
        
        enable6524 = self.pluginPrefs[u"port6524"]
        enable35344 = self.pluginPrefs[u"port35344"]
        
        
        UDP_IP = "0.0.0.0"
        
        if enable6524:
            sock_6524 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            UDP_PORT_6524 = 6524
        if enable35344:
            sock_35344 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            UDP_PORT_35344 = 35344
        
        try:
            sockets = []
            
            if enable6524:
                sock_6524.bind((UDP_IP, UDP_PORT_6524))
                sockets.append(sock_6524)
            if enable35344:
                sock_35344.bind((UDP_IP, UDP_PORT_35344))
                sockets.append(sock_35344)
            
            while True:
                for sock in sockets:
                    data, addr = sock.recvfrom(1024)
                    srcIP = addr[0]
                    
                    if srcIP in self.doorbird.instances:
                        self.doorbird.instances[srcIP].udp_message(data)
                
                self.sleep(0.1)
                
        except self.StopThread: 
            if enable6524:
                sock_6524.close()
            if enable35344:
                sock_35344.close()

    
    ########################################
    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        
        errorDict = indigo.Dict()
        
        if typeId == "doorbird":
        
            # Check IP is not already in use by another doorbird
            ip = valuesDict["ip"]
            if ip in self.doorbird.instances:
                assignedID = self.doorbird.instances[ip].indigoID
                
                if assignedID != devId:
                    name = indigo.devices[assignedID].name
                    errorDict["ip"] = "IP address is already assigned to device: " + name

            # Check that the keep alive value is a valid number
            if valuesDict["keepalive"].isdigit() == False:
                errorDict["keepalive"] = "Keep Alive Timeout must be a number"
        if typeId == "motion":
            if valuesDict["motionPause"].isdigit() == False:
                errorDict["motionPause"] = "Pause between alarms must be a number"

        if len(errorDict) > 0:
            return (False, valuesDict, errorDict)
        else:
            return (True, valuesDict)

        return (True, valuesDict)
        
    ########################################    
    def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
        self.debugLog("closedDeviceConfigUI() called")
        if userCancelled:
            pass
        else:
            if typeId == "doorbird":
            
                dev = indigo.devices[devId]
                ip = valuesDict["ip"]
                user = valuesDict["user"]
                password = valuesDict["password"]
            
                if devId in self.doorbird.instancesID:
                
                    self.doorbird.instancesID[devId].update_credintials(user,password)
              
                    if ip not in self.doorbird.instances:
                        # Remove old IP instance
                        oldIP = self.doorbird.instancesID[devId].ip
                        self.doorbird.instances.pop(oldIP, None)
                        
                        # Add new IP instance
                        self.doorbird.instancesID[devId].ip = ip
                        self.doorbird.instances[ip] = self.doorbird.instancesID[devId]
              
                else:
                    self.doorbird(devId, ip, user, password, self.logger, None, None)
            if typeId == "motion":
                doorbirdID = valuesDict["motionDeviceID"]
                if doorbirdID != "None":
                    self.doorbird.instancesID[int(doorbirdID)].motionDeviceID = devId
                else:
                    #Check if this device was assigned to a Doorbird. If so unassign it.
                    for dev in indigo.devices.iter("self"):
                        if dev.deviceTypeId == "doorbird":
                            if self.doorbird.instancesID[dev.id].motionDeviceID == devId:
                                self.doorbird.instancesID[dev.id].motionDeviceID = None
            if typeId == "doorbell":
                doorbirdID = valuesDict["doorbellDeviceID"]
                if doorbirdID != "None":
                    self.doorbird.instancesID[int(doorbirdID)].doorbellDeviceID = devId
                else:
                    #Check if this device was assigned to a Doorbird. If so unassign it.
                    for dev in indigo.devices.iter("self"):
                        if dev.deviceTypeId == "doorbird":
                            if self.doorbird.instancesID[dev.id].doorbellDeviceID == devId:
                                self.doorbird.instancesID[dev.id].doorbellDeviceID = None
            
    
    ########################################
    def deviceCreated(self, dev):
        self.debugLog("deviceCreated() called")
        
        # Give the motion device the correct icon
        if dev.deviceTypeId == "motion":
            dev.updateStateImageOnServer(indigo.kStateImageSel.MotionSensor)
            
    ########################################
    def deviceDeleted(self, dev):
        self.debugLog("deviceDeleted() called")
        
        # Clean-up Doorbird 
        if dev.deviceTypeId == "doorbird":
            # Try as this fails if the device was created and config was cancelled... the ip instance never gets created
            try:
                ip = dev.pluginProps["ip"]
                self.doorbird.instances.pop(ip, None)
                self.doorbird.instancesID.pop(dev.id, None)
            except:
                pass
                
        
        # Unassign motion device from Dorrbird
        if dev.deviceTypeId == "motion":
            for dev2 in indigo.devices.iter("self"):
                if dev2.deviceTypeId == "doorbird":
                    if self.doorbird.instancesID[dev2.id].motionDeviceID == dev.id:
                        self.doorbird.instancesID[dev2.id].motionDeviceID = None
                        
        # Unassign doorbell device from Dorrbird
        if dev.deviceTypeId == "doorbell":
            for dev2 in indigo.devices.iter("self"):
                if dev2.deviceTypeId == "doorbird":
                    if self.doorbird.instancesID[dev2.id].doorbellDeviceID == dev.id:
                        self.doorbird.instancesID[dev2.id].doorbellDeviceID = None
                  
    
    ########################################
    def validateActionConfigUi(self, valuesDict, typeId, devId):
        return (True, valuesDict)
     
    ########################################
    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        self.debugLog("closedPrefsConfigUI() called")
        if userCancelled:
            pass
        else:
            #Configure logging
            try:
                self.logLevel = int(valuesDict[u"logLevel"])
            except:
                self.logLevel = logging.INFO
            self.indigo_log_handler.setLevel(self.logLevel)
            self.logger.debug(u"logLevel = " + str(self.logLevel))	            
    
    ########################################
    # Generates a list of available Doorbirds for secondary devices
    def getServerList(self, filter="", valuesDict=None, typeId="", devId=None):
        self.debugLog("getServerList called")
        
        
        return_list = [("None","Not assigned")]
        
        
        
        for dev in indigo.devices.iter("self"):  
            if dev.deviceTypeId == "doorbird":
                if typeId == "motion":
                    # Only add Doorbirds that have no motion device assigned 
                    if self.doorbird.instancesID[dev.id].motionDeviceID == None or self.doorbird.instancesID[dev.id].motionDeviceID == int(devId):
                        return_list.append((str(dev.id),dev.name))
                if typeId == "doorbell":
                    # Only add Doorbirds that have no motion device assigned 
                    if self.doorbird.instancesID[dev.id].doorbellDeviceID == None or self.doorbird.instancesID[dev.id].doorbellDeviceID == int(devId):
                        return_list.append((str(dev.id),dev.name))
               
        
        return return_list



    def turnOnLight(self, action, dev):
        self.logger.debug("turnOnLight called")
        self.doorbird.instancesID[dev.id].turn_light_on()
        
    def energizeRelay(self, action, dev):
        self.logger.debug("energizeRelay called")
        if action.pluginTypeId == "strike1":
            relay = 1
        else:
            relay = 2
        
        self.doorbird.instancesID[dev.id].energize_relay(relay)
        

 
	########################################
    def actionControlGeneral(self, action, dev):
	#General Action callback
		###### BEEP ######
		if action.deviceAction == indigo.kDeviceGeneralAction.Beep:
			# Beep the hardware module (dev) here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "beep request"))

		###### ENERGY UPDATE ######
		elif action.deviceAction == indigo.kDeviceGeneralAction.EnergyUpdate:
			# Request hardware module (dev) for its most recent meter data here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "energy update request"))

		###### ENERGY RESET ######
		elif action.deviceAction == indigo.kDeviceGeneralAction.EnergyReset:
			# Request that the hardware module (dev) reset its accumulative energy usage data here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "energy reset request"))

		###### STATUS REQUEST ######
		elif action.deviceAction == indigo.kDeviceGeneralAction.RequestStatus:
			# Query hardware module (dev) for its current status here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "status request"))
			
	########################################			
    class doorbird(object):
        instances = dict()
        instancesID = dict()

        def __init__(self, indigoID=None, ip=None, user=None, password=None, logger=None, motionDeviceID=None, doorbellDeviceID=None):
            self.logger = logger
            self.indigoID = indigoID
            self.ip = ip
            self.user = None
            self.password = None
            self.doorbird = None
            self.update_credintials(user,password)
              
            self.instances[self.ip] = self
            self.instancesID[self.indigoID] = self
            
            self.keepAlive = int((datetime.datetime.now() - datetime.timedelta(seconds = 31)).strftime('%s')) #now minus 31 seconds
            self.motionDeviceID = motionDeviceID
            self.doorbellDeviceID = doorbellDeviceID
            
            self.motionTimer = None
            self.doorbellTimer = None
            
            self.lastEvent = datetime.datetime.now()
            
            
            
            # Start monitoring if the doorbirds is sending keep alive packets
            thread.start_new_thread(self.keep_alive_monitor, ())

        
        def update_credintials(self, usr ,pwd):
            self.logger.debug("doorbird.update_credintials() called")
            self.user = str(usr)
            self.password = str(pwd)
            # Create a doorbirdpy object
            self.doorbird = doorbirdpy.DoorBird(self.ip,self.user,self.password)
            
            self.check_status()
            
        def check_status(self):
            response = self.doorbird.ready()

            if response[0] == False and response[1] == 401:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Invalid credintials. Check username and password")
                status = False
            elif response[0] == True:
                status = True
            else:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to connect to Doorbird. HTML status code: " + str(response[1]))
                status = False
                
            return status
        
        # Monitors the last keep alive packet time and sets the sensor to off if more than 30 seconds has passed    
        def keep_alive_monitor(self):            
            while True:      
                try:
                    dev = indigo.devices[self.indigoID]
                    now = time.time()
                    diff = now - self.keepAlive
                    
                    alive = False
                    
                    # It seems that this object can be created before the Indigo devices property is available
                    try:
                        deviceKeepAlive = int(dev.pluginProps["keepalive"])
                    except:
                        deviceKeepAlive = 30
                    
                    if diff < deviceKeepAlive:
                        alive = True
                        
                    if dev.states["onOffState"] != alive:
                        
                        if alive == True:
                        
                            dev.updateStateOnServer('onOffState',True)
                            self.logger.info(indigo.devices[self.indigoID].name +  ": Online")
                        
                            try:    
                                info = self.doorbird.info()
                                
                                keyValueList = [
                                    {'key': 'firmware', 'value': info['FIRMWARE']},
                                    {'key': 'build_number', 'value': info['BUILD_NUMBER']},
                                    {'key': 'mac_address', 'value': info['WIFI_MAC_ADDR']},
                                    {'key': 'model', 'value': info['DEVICE-TYPE']}
                                ]
                                dev.updateStatesOnServer(keyValueList)
                            except:
                                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to update Doorbird details")
                                
                        else:
                            dev.updateStateOnServer('onOffState',False)
                            self.logger.info(indigo.devices[self.indigoID].name +  ": Offline")
                                                               
                except:
                    self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to read keep alive time")
                
                time.sleep(1)
        
        
        
        def motion_event(self):
            self.logger.debug("doorbird.motion_event() called")
        
            if self.motionDeviceID == None:
                self.logger.debug(indigo.devices[self.motionDeviceID].name + ": Motion event triggered but no Doorbird Motion device has been created")
            else:
            
                dev = indigo.devices[self.motionDeviceID]
                dev.updateStateOnServer('onOffState',True)
                #dev.updateStateImageOnServer(indigo.kStateImageSel.MotionSensorTripped)
                self.logger.info(indigo.devices[self.motionDeviceID].name +  ": Motion detected")
                
                try:
                    self.motionTimer.cancel()
                except:
                    pass
                
                self.motionTimer = threading.Timer(int(dev.pluginProps["motionPause"]),dev.updateStateOnServer,['onOffState',False])
                self.motionTimer.start()
                
        def doorbell_event(self):
            self.logger.debug("doorbird.doorbell_event() called")
        
            if self.doorbellDeviceID == None:
                self.logger.debug(indigo.devices[self.doorbellDeviceID].name + ": Doorbell event triggered but no Doorbird Doorbell device has been created")
            else:
                dev = indigo.devices[self.doorbellDeviceID]
                dev.updateStateOnServer('onOffState',True)
                self.logger.info(indigo.devices[self.doorbellDeviceID].name +  ": Doorbell pressed")
                
                try:
                    self.doorbellTimer.cancel()
                except:
                    pass
                
                self.doorbellTimer = threading.Timer(1,dev.updateStateOnServer,['onOffState',False])
                self.doorbellTimer.start()
        
    
        def turn_light_on(self):
            self.logger.debug("doorbird.turn_light_on called")
            
            if self.check_status() == True:
            
                try:
                    response = self.doorbird.turn_light_on()
                    self.logger.info(indigo.devices[self.indigoID].name +  ": Turn IR Light on command sent")
                except:
                    self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to turn on IR light")
            else:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Turn IR Light on command not sent")
                
        def energize_relay(self,relayID):
        
            if self.check_status() == True:
                self.logger.debug("doorbird.energize_relay called")
                try:
                    response = self.doorbird.energize_relay(relayID)
                    self.logger.info(indigo.devices[self.indigoID].name +  ": Relay " + str(relayID) + " energize command sent")
                except:
                    self.logger.error(indigo.devices[self.indigoID].name +  ": Unable energize relay " + str(relayID))
            else:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Relay " + str(relayID) + " energize command not sent")
        
        
        def udp_message(self, data):
      
            pw = self.password[:5]   
                            
        
            if ":" + self.user[:-4] + ":" not in data:
                packet = list() 
                for i in data:
                    packet.append(hex(ord(i)))
                
                IDENT = self.hex_convert(packet[0:3],"i")
                
                # 14593470 is the first 3 bytes (0xDE 0xAD 0xBE) which identifies this type of packet
                if IDENT == 14593470:
                   
                
                    OPSLIMIT = self.hex_convert(packet[4:8],"i")
                    MEMLIMIT = self.hex_convert(packet[8:12],"i")
                    SALT = self.hex_convert(packet[12:28],"s")
                    NONCE = self.hex_convert(packet[28:36],"s")
                    CIPHERTEXT = self.hex_convert(packet[36:70],"s")
                   
                    key = pysodium.crypto_pwhash(pysodium.crypto_auth_KEYBYTES, pw, SALT, OPSLIMIT, MEMLIMIT, pysodium.crypto_pwhash_ALG_ARGON2I13)
                        
                    try:
                        
                        output = pysodium.crypto_aead_chacha20poly1305_decrypt(CIPHERTEXT, None, NONCE, key)
                    
                        outputHex = list()
                   
                        for i in output:
                            outputHex.append(hex(ord(i)))
                        
                        INTERCOM_ID = self.hex_convert(outputHex[0:6],"s")
                        EVENT = self.hex_convert(outputHex[6:14],"s")
                        TIMESTAMP = self.hex_convert(outputHex[14:18],"i")                                
                        #strTimeStamp = datetime.datetime.fromtimestamp(int(TIMESTAMP)).strftime('%Y-%m-%d %H:%M:%S')

                        
                        if TIMESTAMP != self.lastEvent: #Multiple duplicate UDP packets sent by Doorbird. This removes the duplicates
                            if str(EVENT).rstrip() == "motion":
                                self.motion_event()
                            elif str(EVENT).rstrip() == "1":
                                self.doorbell_event()
                            else:
                                self.logger.debug(indigo.devices[self.indigoID].name + ": Unknown event (" + EVENT + ")") 
                                
                            self.lastEvent = TIMESTAMP
                    except:
                        pass # Just keep going as multiple packets are sent with different passwords. Some will always fail here as wrong password
                else:
                    self.logger.debug(indigo.devices[self.indigoID].name + ": Unknown packet identifier (" + IDENT + ")")             
            else:
                # This is a keep alive packet. Extract the time and update keepAlive variable
                strTime = data.split(":")[2]
                try:
                    self.keepAlive = int(strTime)
                except:
                    self.logger.error(indigo.devices[self.indigoID].name + ": Corrupt Keep Alive Packet")
                              


        # For converting packets back to hex
        def hex_convert(self,subPacket,type): 
        
            hexString = ""
            for x in subPacket:
            
                y = x[2:]
                if len(y) == 1:
                    y = "0" + y
            
                hexString = hexString + y
        
            if type == "i":
                return int(hexString, 16)
            elif type == "s":
                return hexString.decode("hex")
            else:
                self.logger.error("unknown type")
                return None
			
			
			
			
			