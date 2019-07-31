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
import re
from pygtail import Pygtail
import os.path



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
        
        self.isSubscribingToDeviceChanges = False
   
        
    ########################################
    def startup(self):
        self.logger.debug(u"Startup Called")
     
    
    ########################################
    def deviceStartComm(self, dev):
        self.logger.debug(u"deviceStartComm Called")
        dev.stateListOrDisplayStateIdChanged()
        
        
        # Build Doorbird objects and turn all sates to "Off"
        if dev.deviceTypeId == "doorbird":       
        
            if dev.id not in Doorbird.instancesID:
            
                id = dev.id
                ip = dev.pluginProps["ip"]
                user = dev.pluginProps["user"]
                password = dev.pluginProps["password"]
                
                motionID = None
                doorbellID = None
                lock1ID = None
                lock2ID = None
                lockDeviceIDs = list()
                
                for xDev in indigo.devices.iter("self"):
                    if xDev.deviceTypeId == "motion":
                        if xDev.pluginProps["motionDeviceID"] == str(id):
                            motionID = xDev.id
                    if xDev.deviceTypeId == "doorbell":
                        if xDev.pluginProps["doorbellDeviceID"] == str(id):
                            doorbellID = xDev.id
                    if xDev.deviceTypeId == "lock":
                        
                        xList = xDev.pluginProps["lockDeviceID"].split("_")  
                        xID = xList[0]
                        #xRelay = xList[1]
                        
                        if xID == str(id):
                            lockDeviceIDs.append(xDev.id)
                          
                db = Doorbird(id, ip, user, password, motionID, doorbellID, lockDeviceIDs)
                
                stateBinding = dev.pluginProps["stateBinding"]            
                db.primary_device_state_update(stateBinding,False)
                
                dev.updateStateOnServer('doorbirdOnOffState',False)
                dev.updateStateOnServer('motionOnOffState',False)
                dev.updateStateOnServer('doorbellOnOffState',False)
                dev.updateStateOnServer('doorbellOnOffState',False)
                dev.updateStateOnServer('continuousIRMode',False)
                
            
            stateBinding = dev.pluginProps["stateBinding"]
            currentState = dev.states[stateBinding + "OnOffState"]
            
            Doorbird.instancesID[dev.id].primary_device_state_update(stateBinding,currentState)
        elif dev.deviceTypeId == "lock":
            dev.updateStateOnServer('onOffState',True)
            
            #Subscribe to indigo device changes if required
            if dev.pluginProps["enableSensorControl"] == True:
                
                # Update the current state of the lock 
                try:
                    sensorDev = indigo.devices[int(dev.pluginProps["indigoSensors"])]
                    dev.updateStateOnServer('onOffState',sensorDev.states["onOffState"])
                except:
                    pass
            
                if self.isSubscribingToDeviceChanges == False:
                    indigo.devices.subscribeToChanges()
                    self.isSubscribingToDeviceChanges == True
                    
        else:
            #Turn all devices off at startup
            dev.updateStateOnServer('onOffState',False)
            
        return


    ########################################
    def actionControlDevice(self, action, dev):
        self.logger.debug(u"actionControlDevice Called")
                
        isSensorControl = dev.pluginProps["enableSensorControl"]
        
        if action.deviceAction in (indigo.kDeviceAction.Lock,indigo.kDeviceAction.TurnOff):
            if isSensorControl == False:
                dev.updateStateOnServer('onOffState',True)
        elif action.deviceAction in (indigo.kDeviceAction.Unlock,indigo.kDeviceAction.TurnOff):
            if isSensorControl == False:
                dev.updateStateOnServer('onOffState',False)
            
            doorbirdID = dev.pluginProps["lockDeviceID"]
                
            if doorbirdID != "None":
                xList = doorbirdID.split("_")  
                xID = xList[0]
                xRelay = xList[1]
        
                Doorbird.instancesID[int(xID)].energize_relay(xRelay)
            
                if isSensorControl == False:
                    lockTimer = threading.Timer(int(dev.pluginProps["autoOff"]),dev.updateStateOnServer,['onOffState',True])
                    lockTimer.start()
            else:
                self.logger.error(dev.name + ": No Doorbird relays have been assigned to this device")
            
 
    
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
                    
                    if srcIP in Doorbird.instances:
                        Doorbird.instances[srcIP].udp_message(data)
                
                self.sleep(0.1)
                
        except self.StopThread: 
            if enable6524:
                sock_6524.close()
            if enable35344:
                sock_35344.close()

    
    ########################################
    def validateDeviceConfigUi(self, valuesDict, typeId, devId):
        self.debugLog("validateDeviceConfigUi() called")
        
        errorDict = indigo.Dict()
        
        if typeId == "doorbird":
        
            # Check IP is not already in use by another doorbird
            ip = valuesDict["ip"]
            if ip in Doorbird.instances:
                assignedID = Doorbird.instances[ip].indigoID
                
                if assignedID != devId:
                    name = indigo.devices[assignedID].name
                    errorDict["ip"] = "IP address is already assigned to device: " + name

            isIP=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
            if not isIP:    
                errorDict["ip"] = "Not a valid ip address"
            
            
            # Check that the keep alive value is a valid number
            if valuesDict["keepalive"].isdigit() == False:
                errorDict["keepalive"] = "Keep Alive Timeout must be a number"
            
            if valuesDict["motionPause"].isdigit() == False:
                errorDict["motionPause"] = "Pause between alarms must be a number"
                
            if valuesDict["enableSSIRActivation"]:
                if os.path.isfile(valuesDict["ssWebLogPath"]) == False:
                    errorDict["ssWebLogPath"] = "Invalid web log path. Have you enabled the web log in Security Spy?"
                    
                if valuesDict["ssCameraNum"].isdigit() == False:
                     errorDict["ssCameraNum"] = "Security Spy camera number must be a number. Look in Security Spy to find the camera number corresponding to this Doorbird."
                
            if valuesDict["continuousMode"].isdigit() == False:
                errorDict["continuousMode"] = "Continuous mode frequency must be a number"
            
        if typeId == "lock":
            if valuesDict["autoOff"].isdigit() == False:
                errorDict["autoOff"] = "Auto lock must be a number"
        
        
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
            
                if devId in Doorbird.instancesID:
                
                    Doorbird.instancesID[devId].update_credintials(user,password)
              
                    if ip not in Doorbird.instances:
                        # Remove old IP instance
                        oldIP = Doorbird.instancesID[devId].ip
                        Doorbird.instances.pop(oldIP, None)
                        
                        # Add new IP instance
                        Doorbird.instancesID[devId].ip = ip
                        Doorbird.instances[ip] = Doorbird.instancesID[devId]
                                               
                    # monitoring of Security Spy web logs for auto IR                        
                    if valuesDict["enableSSIRActivation"]:
                        Doorbird.instancesID[devId].start_ss_web_log_monitor()
                    else:
                        Doorbird.instancesID[devId].stop_ss_web_log_monitor()
              
                else:
                    self.debugLog("New Doorbird device")
                    Doorbird(devId, ip, user, password, None, None)
                    
                
            if typeId == "motion":
                doorbirdID = valuesDict["motionDeviceID"]
                if doorbirdID != "None":
                    Doorbird.instancesID[int(doorbirdID)].motionDeviceID = devId
                else:
                    #Check if this device was assigned to a Doorbird. If so unassign it.
                    for dev in indigo.devices.iter("self"):
                        if dev.deviceTypeId == "doorbird":
                            if Doorbird.instancesID[dev.id].motionDeviceID == devId:
                                Doorbird.instancesID[dev.id].motionDeviceID = None
            if typeId == "doorbell":
                doorbirdID = valuesDict["doorbellDeviceID"]
                if doorbirdID != "None":
                    Doorbird.instancesID[int(doorbirdID)].doorbellDeviceID = devId
                else:
                    #Check if this device was assigned to a Doorbird. If so unassign it.
                    for dev in indigo.devices.iter("self"):
                        if dev.deviceTypeId == "doorbird":
                            if Doorbird.instancesID[dev.id].doorbellDeviceID == devId:
                                Doorbird.instancesID[dev.id].doorbellDeviceID = None
            if typeId == "lock":
                doorbirdID = valuesDict["lockDeviceID"]
                
                if doorbirdID != "None":
                
                    dev = indigo.devices[devId]
                    xList = doorbirdID.split("_")  
                    xID = xList[0]
                    
                    
                    if devId not in Doorbird.instancesID[int(xID)].lockDevices:
                        Doorbird.instancesID[int(xID)].lockDevices.append(devId)
                    else:
                        self.debugLog("lll")
                    
                    self.debugLog(len(Doorbird.instancesID[int(xID)].lockDevices))
                    
                else:
                    #Check if this device was assigned to a Doorbird. If so unassign it.
                    for dev in indigo.devices.iter("self"):
                        if dev.deviceTypeId == "doorbird":
                            
                            for lockDevice in list(Doorbird.instancesID[dev.id].lockDevices):
                                if lockDevice == devId:
                                    Doorbird.instancesID[dev.id].lockDevices.remove(lockDevice)
      
    
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
                Doorbird.instances.pop(ip, None)
                Doorbird.instancesID.pop(dev.id, None)
            except:
                pass
                
        
        # Unassign motion device from Doorbird
        if dev.deviceTypeId == "motion":
            for dev2 in indigo.devices.iter("self"):
                if dev2.deviceTypeId == "doorbird":
                    if Doorbird.instancesID[dev2.id].motionDeviceID == dev.id:
                        Doorbird.instancesID[dev2.id].motionDeviceID = None
                        
        # Unassign doorbell device from Doorbird
        if dev.deviceTypeId == "doorbell":
            for dev2 in indigo.devices.iter("self"):
                if dev2.deviceTypeId == "doorbird":
                    if Doorbird.instancesID[dev2.id].doorbellDeviceID == dev.id:
                        Doorbird.instancesID[dev2.id].doorbellDeviceID = None
        
        # Unassign lock device from Doorbird
        if dev.deviceTypeId == "lock":
            for dev2 in indigo.devices.iter("self"):
                if dev2.deviceTypeId == "doorbird":
                
                    for lockDevice in list(Doorbird.instancesID[dev2.id].lockDevices):
                        if lockDevice == dev.id:
                            Doorbird.instancesID[dev2.id].lockDevices.remove(lockDevice)
                
    
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
                    # Only present Doorbirds that have no motion device assigned 
                    if Doorbird.instancesID[dev.id].motionDeviceID == None or Doorbird.instancesID[dev.id].motionDeviceID == int(devId):
                        return_list.append((str(dev.id),dev.name))
                if typeId == "doorbell":
                    # Only present Doorbirds that have no motion device assigned 
                    if Doorbird.instancesID[dev.id].doorbellDeviceID == None or Doorbird.instancesID[dev.id].doorbellDeviceID == int(devId):
                        return_list.append((str(dev.id),dev.name))
                        
        return return_list
                 
        
    ########################################
    # Generates a list of all available relays for all Doorbirds       
    def getRelayList(self, filter="", valuesDict=None, typeId="", devId=None):
        self.debugLog("getRelayList called")
        
        return_list = [("None","Not assigned")]
        
        existingID = None
        if "lockDeviceID" in valuesDict:
            existingID = valuesDict["lockDeviceID"]
        
         
        for dev in indigo.devices.iter("self"):
            if dev.deviceTypeId == "doorbird":
        
                relays = Doorbird.instancesID[dev.id].get_relays()
                
                for relay in relays:
                    available = True
                    
                    for dev2 in indigo.devices.iter("self"):
                        if dev2.deviceTypeId == "lock":
        
                            relayID = dev2.pluginProps["lockDeviceID"]
                                   
                            if relayID == (str(dev.id) + "_" + relay) and relayID != existingID:
                                available = False
                
                
                    if available == True:
                        return_list.append((str(dev.id) + "_" + relay,dev.name + " - Relay " + relay))
        
        return return_list

    def getFullRelayList(self, filter="", valuesDict=None, typeId="", devId=None):
        return_list = list()
        
        for dev in indigo.devices.iter("self"):
            if dev.deviceTypeId == "doorbird":
        
                relays = Doorbird.instancesID[dev.id].get_relays()
                
                for relay in relays:
                    return_list.append(relay)
        return return_list


    def turnOnLight(self, action, dev):
        self.logger.debug("turnOnLight called")
        Doorbird.instancesID[dev.id].turn_light_on()

    def restartDoorbird(self, action, dev):
        self.logger.debug("restartDoorbird called")
        Doorbird.instancesID[dev.id].restart_doorbird()
        
    def energizeRelay(self, action, dev):
        self.logger.debug("energizeRelay called")
     
        Doorbird.instancesID[dev.id].energize_relay(action.props["relay"])
        
    def continuousIR(self, action, dev):
        self.logger.debug("continuousIR called")
        
        if dev.pluginProps["enableContinuousMode"] == True:
        
            if action.pluginTypeId == "startContIR":
                irAction = True
            else:
                irAction = False
        
            Doorbird.instancesID[dev.id].continuous_IR(irAction)
            
        else:
            self.logger.warning("To use continuous IR mode please enable it in the Doorbird device's advanced opions.")      
        
    def deviceUpdated(self, origDev, newDev):
        for dev in indigo.devices.iter("self"):  
            if dev.deviceTypeId == "lock":
                if dev.pluginProps["enableSensorControl"] == True:
                    if dev.pluginProps["indigoSensors"] == str(newDev.id):
                         
                        sensorControl = True
                        if dev.pluginProps["reverseSensorControl"] == True:
                            sensorControl = False
                        
                        if newDev.states["onOffState"] == sensorControl:
                            dev.updateStateOnServer('onOffState',False)
                        else:
                            dev.updateStateOnServer('onOffState',True)
        

 
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
			
			if dev.deviceTypeId == "doorbird":
			    Doorbird.instancesID[dev.id].update_status_fields(True)
			
			elif dev.deviceTypeId == "lock" and dev.pluginProps["enableSensorControl"] == True:
			    # Update the current state of the lock 
			    try:
			        sensorDev = indigo.devices[int(dev.pluginProps["indigoSensors"])]
			        dev.updateStateOnServer('onOffState',sensorDev.states["onOffState"])
			    except:
			        pass
			
			else:
			    indigo.server.log(u"sent \"%s\" %s" % (dev.name, ": This device does not support status requests"))
			
			
			
########################################			
class Doorbird(object):
    instances = dict()
    instancesID = dict()

    def __init__(self, indigoID=None, ip=None, user=None, password=None, motionDeviceID=None, doorbellDeviceID=None, lockDevices=None):
        self.logger = logging.getLogger("Plugin")
        self.indigoID = indigoID
        self.ip = ip
        self.user = None
        self.password = None
        self.doorbirdPy = None
        self.update_credintials(user,password)
          
        self.instances[self.ip] = self
        self.instancesID[self.indigoID] = self
        
        self.keepAlive = int((datetime.datetime.now() - datetime.timedelta(seconds = 31)).strftime('%s')) #now minus 31 seconds
        self.motionDeviceID = motionDeviceID
        self.doorbellDeviceID = doorbellDeviceID
        
        self.lockDevices = lockDevices
        
        self.motionTimer = None
        self.doorbellTimer = None
        
        self.lastEvent = datetime.datetime.now()
        self.continuousIR = False
        
        # Start monitoring if the doorbird is sending keep alive packets
        thread.start_new_thread(self.keep_alive_monitor, ())
        
        self.monitorSSWeblogs = False
        if "enableSSIRActivation" in indigo.devices[self.indigoID].pluginProps: #required to prevent error when upgrading the plugin.
            if indigo.devices[self.indigoID].pluginProps["enableSSIRActivation"]:
                # Start monitoring Security Spy web logs for auto IR
                self.start_ss_web_log_monitor()
        
    
    def update_credintials(self, usr ,pwd):
        self.logger.debug("Doorbird.update_credintials() called")
        self.user = str(usr)
        self.password = str(pwd)
        # Create a doorbirdpy object
        self.doorbirdPy = doorbirdpy.DoorBird(self.ip,self.user,self.password)
        
        self.check_status()
        
    def check_status(self):
        self.logger.debug("Doorbird.check_status() called")
        response = self.doorbirdPy.ready()

        if response[0] == False and response[1] == 401:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Invalid credintials. Check username and password")
            status = False
        elif response[0] == True:
            status = True
        else:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to connect to Doorbird. HTML status code: " + str(response[1]))
            status = False
            
        return status
        
    def update_status_fields(self,printLog):
        self.logger.debug("Doorbird.update_status_fields() called")
        
        try:      
            if self.check_status() == True:
                info = self.doorbirdPy.info()
                
                keyValueList = [
                    {'key': 'doorbird_firmware', 'value': info['FIRMWARE']},
                    {'key': 'doorbird_build_number', 'value': info['BUILD_NUMBER']},
                    {'key': 'doorbird_mac_address', 'value': info['WIFI_MAC_ADDR']},
                    {'key': 'doorbird_model', 'value': info['DEVICE-TYPE']}
                ]    
                
                dev = indigo.devices[self.indigoID]
                
                if printLog == True:
                    self.logger.info(dev.name + ": Connected")
                    self.logger.info("    Firmware    : " + info['FIRMWARE'])
                    self.logger.info("    Build Number: " + info['BUILD_NUMBER'])
                    self.logger.info("    MAC Address : " + info['WIFI_MAC_ADDR'])
                    self.logger.info("    Model       : " + info['DEVICE-TYPE'])
                
                dev.updateStatesOnServer(keyValueList)
        except:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to update Doorbird details")
        
    # Returns available relays as reported by the Doorbird
    def get_relays(self):
        if self.check_status() == True:
            info = self.doorbirdPy.info()
            return info['RELAYS']
        else:
            return False
        
    
    # Monitors the last keep alive packet time and sets the sensor to off if more than 30 seconds has passed    
    def keep_alive_monitor(self):
        while True:    
            try:
            
            
                dev = indigo.devices[self.indigoID]
                now = time.time()
                diff = now - self.keepAlive
                
                #self.logger.debug(indigo.devices[self.indigoID].name +  " - Current time: " + str(now))
                #self.logger.debug(indigo.devices[self.indigoID].name +  " - Keep alive: " + str(self.keepAlive))
                #self.logger.debug(indigo.devices[self.indigoID].name +  " - Diff: " + str(diff))
                

                deviceKeepAlive = int(dev.pluginProps["keepalive"])
                
                alive = False
                if diff < deviceKeepAlive:
                    alive = True
                    
                onOffState = dev.states["doorbirdOnOffState"]
                
                if onOffState != alive:
                
                    self.primary_device_state_update("doorbird",alive)
                    
                    if alive == True:
                    
                        dev.updateStateOnServer('doorbirdOnOffState',True)
                        dev.updateStateOnServer('doorbirdLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        
                        self.logger.info(indigo.devices[self.indigoID].name +  ": Online")
                    
                        self.update_status_fields(False)
                            
                    else:
                        dev.updateStateOnServer('doorbirdOnOffState',False)
                        dev.updateStateOnServer('doorbirdLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        self.logger.info(indigo.devices[self.indigoID].name +  ": Offline")
                                                           
            except:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to read keep alive time")
            
            time.sleep(1)
    
    def start_ss_web_log_monitor(self):
        if self.monitorSSWeblogs == False:
            self.monitorSSWeblogs = True
            thread.start_new_thread(self.ss_web_log_monitor, ())
    
    def stop_ss_web_log_monitor(self):
        self.monitorSSWeblogs = False
    
    def ss_web_log_monitor(self):
        self.logger.debug("Doorbird.ss_web_log_monitor() called")
        
        #Get isDaylight variable ID
        isDaylightId = None
        for var in indigo.variables:
            if var.name == "isDaylight":
                isDaylightId = var.id
        
        lastTriggered = None
        lastError = None
        
        self.logger.info(indigo.devices[self.indigoID].name + ": Monitoring of the Security Spy web log has started")
        while self.monitorSSWeblogs:    
            try:
                if os.path.isfile(indigo.devices[self.indigoID].pluginProps["ssWebLogPath"]):
                    if indigo.variables[isDaylightId].value == "false":
                        for line in Pygtail(indigo.devices[self.indigoID].pluginProps["ssWebLogPath"]):
                            if (("cameraNum=" + indigo.devices[self.indigoID].pluginProps["ssCameraNum"]) in line) and (indigo.devices[self.indigoID].states["doorbirdOnOffState"] == True):
                                if (lastTriggered == None) or (time.time() - lastTriggered > 30):
                                    self.logger.debug(indigo.devices[self.indigoID].name +  ": Security Spy web log criteria detected")
                                    self.turn_light_on()
                                    lastTriggered = time.time()
                else:
                    if (lastError == None) or (time.time() - lastError > 300): # only send error messages every 5 minutes so as not to spam the log
                        lastError = time.time()
                        self.logger.error(indigo.devices[self.indigoID].name +  ": Invalid Security Spy web log path: " + indigo.devices[self.indigoID].pluginProps["ssWebLogPath"])
            except:
                if (lastError == None) or (time.time() - lastError > 300): # only send error messages every 5 minutes so as not to spam the log
                    lastError = time.time()
                    self.logger.error(indigo.devices[self.indigoID].name +  ": Error reading Security Spy web log")
            
            time.sleep(.5)
            
        self.logger.info(indigo.devices[self.indigoID].name + ": Monitoring of the Security Spy web log has stopped")
    
    
    def motion_event(self):
        self.logger.debug("Doorbird.motion_event() called")
    
        priDev = indigo.devices[self.indigoID]
        priDev.updateStateOnServer('motionOnOffState',True)
        priDev.updateStateOnServer('motionLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.primary_device_state_update("motion",True)
        
        
        if self.motionDeviceID == None:
            self.logger.info(priDev.name +  ": Motion On")
        else:
        
            dev = indigo.devices[self.motionDeviceID]
            dev.updateStateOnServer('onOffState',True)
            self.logger.info(indigo.devices[self.motionDeviceID].name +  ": On")
            
        try:
            self.motionTimer.cancel()
        except:
            pass
            
        self.motionTimer = threading.Timer(int(priDev.pluginProps["motionPause"]),self.motion_off)
        self.motionTimer.start()
            
            
    def motion_off(self):
        self.logger.debug("Doorbird.motion_off() called")
        
        priDev = indigo.devices[self.indigoID]
        priDev.updateStateOnServer('motionOnOffState',False)
        priDev.updateStateOnServer('motionLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.primary_device_state_update("motion",False)
        
        if self.motionDeviceID == None:
            self.logger.info(priDev.name +  ": Motion Off")
        else:
            dev = indigo.devices[self.motionDeviceID]
            dev.updateStateOnServer('onOffState',False)
            self.logger.info(indigo.devices[self.motionDeviceID].name +  ": Off")
            
    def doorbell_event(self):
        self.logger.debug("Doorbird.doorbell_event() called")
        
        priDev = indigo.devices[self.indigoID]
        priDev.updateStateOnServer('doorbellOnOffState',True)
        priDev.updateStateOnServer('doorbellLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.primary_device_state_update("doorbell",True)
    
        if self.doorbellDeviceID == None:
            self.logger.info(priDev.name +  ": Doorbell On")
        else:
            dev = indigo.devices[self.doorbellDeviceID]
            dev.updateStateOnServer('onOffState',True)
            self.logger.info(indigo.devices[self.doorbellDeviceID].name +  ": On")
            
        try:
            self.doorbellTimer.cancel()
        except:
            pass
            
        self.doorbellTimer = threading.Timer(1,self.doorbell_off)
        self.doorbellTimer.start()
            
    def doorbell_off(self):
        self.logger.debug("Doorbird.doorbell_off() called")
        
        priDev = indigo.devices[self.indigoID]
        priDev.updateStateOnServer('doorbellOnOffState',False)
        self.primary_device_state_update("doorbell",False)
        
        if self.doorbellDeviceID == None:
            self.logger.info(priDev.name +  ": Doorbell Off")
        else:
            dev = indigo.devices[self.doorbellDeviceID]
            dev.updateStateOnServer('onOffState',False)
            self.logger.info(indigo.devices[self.doorbellDeviceID].name +  ": Off")
            
    def primary_device_state_update(self,deviceType,state):
        self.logger.debug("Doorbird.primary_device_state_update() called")
        
        dev = indigo.devices[self.indigoID]
        stateBinding = dev.pluginProps["stateBinding"]
       
        if deviceType == stateBinding:
            
            if deviceType == "motion":
                if state == True:
                    dev.updateStateImageOnServer(indigo.kStateImageSel.MotionSensorTripped)
                else:
                    dev.updateStateImageOnServer(indigo.kStateImageSel.MotionSensor)
            else:
                if state == True:
                    dev.updateStateImageOnServer(indigo.kStateImageSel.SensorOn)
                else:
                    dev.updateStateImageOnServer(indigo.kStateImageSel.SensorOff)
            
            dev.updateStateOnServer('onOffState',state)
            
    

    def turn_light_on(self):
        self.logger.debug("Doorbird.turn_light_on called")
        
        if self.check_status() == True:
        
            try:
                response = self.doorbirdPy.turn_light_on()
                self.logger.info(indigo.devices[self.indigoID].name +  ": Turn IR Light on command sent")
            except:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to turn on IR light")
        else:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Turn IR Light on command not sent")
            
    def restart_doorbird(self):
        self.logger.debug("Doorbird.restart_doorbird called")
        
        if self.check_status() == True:
        
            try:
                response = self.doorbirdPy.restart_doorbird()
                self.logger.info(indigo.devices[self.indigoID].name +  ": Restart Doorbird command sent")
            except:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable to restart Doorbird")
        else:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Restart Doorbird command not sent")
            
    def energize_relay(self,relayID):
    
        if self.check_status() == True:
            self.logger.debug("Doorbird.energize_relay called")
            try:
                response = self.doorbirdPy.energize_relay(relayID)
                self.logger.info(indigo.devices[self.indigoID].name +  ": Relay " + str(relayID) + " energize command sent")
            except:
                self.logger.error(indigo.devices[self.indigoID].name +  ": Unable energize relay " + str(relayID))
        else:
            self.logger.error(indigo.devices[self.indigoID].name +  ": Relay " + str(relayID) + " energize command not sent")
    
    def continuous_IR(self,keepOn):
        self.logger.debug("Doorbird.continuous_IR called")
        if keepOn == True:
            self.logger.info(indigo.devices[self.indigoID].name +  ": Continuous IR mode enabled")
            if self.continuousIR == False:
                self.continuousIR = True
                thread.start_new_thread(self.continuous_IR_worker, ())
        else:
            self.logger.info(indigo.devices[self.indigoID].name +  ": Continuous IR mode disabled")
            self.continuousIR = False
            
        dev = indigo.devices[self.indigoID]
        dev.updateStateOnServer('continuousIRMode',keepOn)
        dev.updateStateOnServer('continuousIRLastUpdate',datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    
    def continuous_IR_worker(self):
        self.logger.debug("Doorbird.continuous_IR_worker called")
        while self.continuousIR == True:
            self.logger.debug(indigo.devices[self.indigoID].name +  ": Continuous IR Light command sent")
            response = self.doorbirdPy.turn_light_on()
            
            dev = indigo.devices[self.indigoID]
            time.sleep(int(dev.pluginProps["continuousMode"]))
            
              
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
                    

                    self.logger.debug("------------------------------")
                    self.logger.debug(indigo.devices[self.indigoID].name + ": Decrypted UDP packet details")
                    self.logger.debug("    Intercom_ID: " +  str(INTERCOM_ID))
                    self.logger.debug("    Event: " +  str(EVENT))
                    self.logger.debug("    Timestamp: " +  str(TIMESTAMP))
                    self.logger.debug("------------------------------")
                                                       
                    
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
            
            #11189196 is the first 3 bytes (0xAA 0xBB 0xCC) which occurs when an IP Chime is connected to the Doorbird
            elif IDENT == 11189196:
                pass # For now do nothing. Maybe useful later when we work out what to do with this type of packet?
            else:
                self.logger.debug(indigo.devices[self.indigoID].name + ": Unknown packet identifier (" + str(IDENT) + ")")             
        else:
            self.keepAlive = time.time()
            

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
			
			
			
			
			