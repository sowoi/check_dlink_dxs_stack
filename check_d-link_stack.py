#!/usr/bin/python3
# Developer Massoud Ahemd
# Fork of https://github.com/stdevel by Christian Stankowic
# D-Link DGS managed switches
#

import logging
import pysnmp

import os
from optparse import OptionParser, OptionGroup
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen



LOGGER = logging.getLogger('check_dlink_dgs')
my_ports={}


# OIDs
portOid = "1.3.6.1.2.1.2.2.1.1"  
typeOid = "1.3.6.1.2.1.2.2.1.3"
descOid = "1.3.6.1.2.1.31.1.1.1.1"
perfOid = "1.3.6.1.2.1.2.2.1.5"
stateOid = "1.3.6.1.2.1.2.2.1.8"
systemOid = "1.3.6.1.2.1.1.1.0"
lacpOidGrouped = "1.3.6.1.4.1.171.14.4.1.2.1.4"
lacpOidActive = "1.3.6.1.4.1.171.14.4.1.2.1.5"
lacpOidIfNumber = "1.3.6.1.4.1.171.14.4.1.2.1.2"
stackOidTopology = "1.3.6.1.4.1.171.14.9.1.1.1"
stackOidDevices = "1.3.6.1.4.1.171.14.9.1.1.3"

my_portinfo={}                                  #dict with gathered information
perfdata=" |"
#I like dirty coding
curr_query=""
curr_port=1


def get_all_ports(snmp_community,snmp_version,snmp_port):
        #get all ports
        
        global my_ports
        i = 0
        ethernetCount = 0
        lacpCount = 0

        portsTotal = (os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+portOid).readlines())
        
        for line in portsTotal:
                
                if "INTEGER" in line:
                        line = line.split("INTEGER:")
                        line = line[1].strip()
                        
                        portType = (os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+typeOid+"."+(line)).read())
                        
                        portType = portType.split("INTEGER:")
                        portType = portType[1].strip()
                        #print(portType)
                        if "Lag" in portType or "161" in portType:
                                #print(portType)
                                portType = "LACP"
                                lacpCount+=1
                                #print("gefunden")
                        elif "ethernet"in portType or "6" in portType:
                                portType = "ethernet"
                                ethernetCount+=1
                        elif "vlan" in portType or "135" in portType:
                                portType = "vlan"
                        #print(portType)
                        portDesc = (os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+descOid+"."+(line)).read())
                        #print(portDesc)
                        portDesc = portDesc.split("STRING:")
                        portDesc = portDesc[1].strip()

                        if portType == "ethernet" or portType == "LACP":
                                        my_ports[i] = line, portDesc, portType
                                        i+=1
                        else:
                                continue


        LOGGER.debug("Found ", str(ethernetCount), " ethernet ports and " , str(lacpCount) , " lacp ports")
        return(my_ports)

def get_specific_ports(port):

        systemSwitch = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+systemOid).read()
        systemSwitch = systemSwitch.split("STRING: ")
        systemSwitch = systemSwitch[1].split("Port")
        systemSwitch = str(systemSwitch[0]).split()
        systemSwitch = ' '.join(map(str, systemSwitch))
        
        ethernetStatusUp = []
        lacpStatusUp = []
        ethernetStatusDown = []
        lacpStatusDown = []
        try:
                port = str(port).split(",")
        except:
                pass
        portsSearch = (os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+descOid).readlines())
        
        port_length = len(port)-1
        #print(port)
        for specificPorts in port:
                 mon = 0
                 for line in portsSearch:
                        
                        portName = line.split("STRING:")
                        portName = portName[1].strip()
                        portName = portName.replace('"','')
                        
                        if "ifName" in line:
                          portID = line.split("ifName.")
                          
                          portID = portID[1].strip()
                          portID = portID.split(" =")
                          portID = portID[0].strip()
                        else:
                          portID = line.split("1.1.1.1.1.")
                          
                          portID = portID[1]
                          portID = portID.split(" =")
                          portID = portID[0]
                          
                        #print(specificPorts)
                        

                        
                        if str(specificPorts).strip() == portName.strip():
                                
                                mon = 1
                                degradedGlobal = 0
                                degraded = 0
                                
                                if int(portID) >= 850:
                                        

                                        searchLACP = (os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" " +lacpOidIfNumber)).readlines()
                                        for ifNumbers in searchLACP:
                                                if portID in ifNumbers.strip():
                                                        
                                                        #print(ifNumbers)
                                                        ifNumbers = ifNumbers.split(" = ")
                                                        ifNumbers = ifNumbers[0]
                                                        ifNumbers = ifNumbers.split(".")
                                                        ifNumbers = ifNumbers[-1]
                                                        lacpstatusGrouped = ((os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+lacpOidGrouped+"."+(ifNumbers)).read()))
                                                        lacpstatusGrouped = lacpstatusGrouped.split("Hex-STRING: ")
                                                        lacpstatusGrouped = lacpstatusGrouped[1]
                                                        lacpstatusActive = ((os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+lacpOidActive+"."+(ifNumbers)).read()))
                                                        lacpstatusActive = lacpstatusActive.split("Hex-STRING: ")
                                                        lacpstatusActive = lacpstatusActive[1]
                                                        #print(lacpstatusGrouped)
                                                        #print(lacpstatusActive)

                                                        if lacpstatusGrouped == lacpstatusActive:
                                                                degraded = 0
                                                        else:
                                                                
                                                                degraded = 1
                                                                degradedGlobal = 1

                                                       
                                        
                                status = ((os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+stateOid+"."+(portID)).read()))
                                status = status.split("INTEGER:")
                                status = status[1].strip()
                                #print(degraded)
                                if port.index(specificPorts) != port_length:
                                  if "up" in status or "1" in status:
                                        if degraded == 1:
                                         ethernetStatusUp.append(str(specificPorts).strip()+ " is up but degraded, ")
                                        else:
                                         ethernetStatusUp.append(str(specificPorts).strip()+ " is up, ")
                                  elif "down" in status or "2" in status:
                                        ethernetStatusDown.append(str(specificPorts).strip()+ " is down, ")
                                else:
                                  if "up" in status or "1" in status:
                                        if degraded == 1: 
                                         ethernetStatusUp.append(str(specificPorts).strip()+ " is up but degraded ")
                                        else:
                                         ethernetStatusUp.append(str(specificPorts).strip()+ " is up ")
                                  elif "down" in status or "2" in status:
                                         ethernetStatusDown.append(str(specificPorts).strip()+ " is down ")
                 if mon == 0:
                       print("UNKOWN: Port", systemSwitch, " ", str(specificPorts).strip()+ " not found. Use -s or --show to see all accessible ports")
                       exit(-1)

        if len(ethernetStatusDown) > 0:
                ethernetStatusDown = ' '.join(map(str, ethernetStatusDown))
                print("CRITICAL: ", systemSwitch, ": ", str(ethernetStatusDown).strip())
                exit(2)
        elif degradedGlobal != 0:
                ethernetStatusUp = ' '.join(map(str, ethernetStatusUp))
                print("WARNING: " , systemSwitch, ": ",str(ethernetStatusUp).strip())
                exit(1)
        else:
                ethernetStatusUp = ' '.join(map(str, ethernetStatusUp))
                print("OK: " , systemSwitch, ": ",str(ethernetStatusUp).strip())
                exit(0)


        return(my_ports)


def check_switch_ports(my_ports,state):
        ethernetStatusDown = []
        ethernetStatusActive = []

        systemSwitch = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+systemOid).read()
        systemSwitch = systemSwitch.split("STRING: ")
        systemSwitch = systemSwitch[1].split("Port")
        systemSwitch = str(systemSwitch[0]).split()
        systemSwitch = ' '.join(map(str, systemSwitch))
        if state == "show":
           showPorts = {v[1] for k,v in my_ports.items()}
           showPorts = sorted(showPorts)
           print("Found ", len(showPorts), " Ports:")
           print(", ".join(showPorts))
           exit(0)
           
        for port in my_ports.keys():
                dlinkPort = my_ports[port][0]
                status = ((os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+stateOid+"."+(dlinkPort)).read()))
                status = status.split("INTEGER:")
                status = status[1].strip()
                                                                                
                #print(status)
                if "up" in status or "1" in status:
                        upSpeed = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+perfOid+"."+(dlinkPort)).read()
                        upSpeed = upSpeed.split("Gauge32:")
                        upSpeed = upSpeed[1].strip()
                        ethernetStatusActive.append(str(my_ports[port][1]).strip()+" is up speed="+str(upSpeed).strip()+" | ")
                        #print(str(my_ports[port][1]).strip(), "is up | speed=", str(upSpeed).strip())
                elif "down" in status or "2" in status:
                        if str(my_ports[port][1]).strip() != "mgmt":
                         ethernetStatusDown.append(str(my_ports[port][1]).strip())
                         #print(str(my_ports[port][1]).strip(), "is down")
        if state == "down":
         if len(ethernetStatusDown) > 0:
                downCount = len(ethernetStatusDown)
                ethernetStatusDown = ' '.join(map(str, ethernetStatusDown)) 
                print("CRITICAL: Found ",str(downCount), " ports with state down: ", systemSwitch," | ", str(ethernetStatusDown).strip())
                exit(2)
         else:
                print("OK: " , systemSwitch, " All ports with state up.")
                exit(0)

        elif state == "active":
                ethernetStatusActive = ' '.join(map(str, ethernetStatusActive))
                print("OK: " , systemSwitch, "| All active ports with state up: ", str(ethernetStatusActive).strip())
                exit(0)


def check_stack(stack_id, device_number):
        
        systemSwitch = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+systemOid).read()
        systemSwitch = systemSwitch.split("STRING: ")
        systemSwitch = systemSwitch[1].split("Port")
        systemSwitch = str(systemSwitch[0]).split()
        systemSwitch = ' '.join(map(str, systemSwitch))        
        topStack = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+stackOidTopology).read()
        topStack = topStack.split("INTEGER:")
        topStack = topStack[1].strip()
        devStack = os.popen("snmpwalk -v"+snmp_version+" -c "+snmp_community+" "+host+" "+stackOidDevices).read()
        devStack = devStack.split("INTEGER:")
        devStack = devStack[1].strip()

        if topStack == "2":
                topo = "Chain"
        elif topStack == "3":
                topo = "Ring"
        else:
                topo = "StandAlone"
        
        if stack_id != "default" and device_number == "default":        
         if topStack == stack_id:
              print("OK: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices")
              exit(0)
         else:
              print("CRITICAL: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices, but not the defined topology.")
              exit(2)
        elif device_number != "default" and stack_id == "default":
         if devStack == device_number:
             print("OK: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices")
             exit(0)

         else:
             print("CRITICAL: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices. Number of devices expected does not correspond to the number found.")
             exit(2)

        else:
          if topStack == stack_id and  devStack == device_number:
                  print("OK: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices")
                  exit(0)
          elif topStack != stack_id:
                  print("CRITICAL: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices, but not the defined topology.")
                  exit(2)
          elif devStack != device_number:
                 print("WARNING: " , systemSwitch, " found stacking topology "+ topo + " with " + devStack + " devices, but number of devices expected does not correspond to the number found.")
                 exit(1)


if __name__ == "__main__":
        
        desc='''%prog is used to check D-Link DGS managed switch port states in a stack. It needs a fixed identifier for the ports in the current version. start the plugin with the option -s/--show to get the identifiers. Example inputs: %prog -H <Hostname> --ports=eth1/0/12,eth2/0/15 ; '''
        parser = OptionParser(description=desc)
        gen_opts = OptionGroup(parser, "Generic options")
        host_opts = OptionGroup(parser, "Host options")
        port_opts = OptionGroup(parser, "Port options")
        stack_opts = OptionGroup(parser, "Stack options")
        device_opts = OptionGroup(parser, "Device options")
        parser.add_option_group(gen_opts)
        parser.add_option_group(host_opts)
        parser.add_option_group(port_opts)
        parser.add_option_group(stack_opts)
        parser.add_option_group(device_opts)
        
        #-d / --debug
        gen_opts.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="enable debugging outputs (default: no)")
                
        #-H / --host
        host_opts.add_option("-H", "--host", dest="host", default="", action="store", metavar="HOST", help="defines the switch hostname or IP")
        
        #-c / --snmp-community
        host_opts.add_option("-c", "--snmp-community", dest="snmp_comm", default="public", action="store", metavar="COMMUNITY", help="defines the SNMP community (default: public)")
        
        #-V / --snmp-version
        host_opts.add_option("-V", "--snmp-version", dest="snmp_vers", default="2c", action="store", choices=["1","2c"], metavar="[1|2c]", help="defines the SNMP version (default: 2c)")
        
        #-p / --snmp-port
        host_opts.add_option("-p", "--snmp-port", dest="snmp_port", default=161, action="store", type=int, metavar="PORT", help="defines the SNMP port (default: 161)")
        
        #-P / --ports
        port_opts.add_option("-P", "--ports", dest="ports", action="store", metavar="PORT", type="string", help="defines one or more ports for monitoring. multiple ports must be comma separated!")
        
        #-a / --all-ports
        port_opts.add_option("-a", "--all-ports", dest="all_ports", default=False, action="store_true", help="monitors all ports (default: no)")
        
        #-A / --active-ports
        port_opts.add_option("-A", "--active-ports", dest="act_ports", default=False, action="store_true", help="monitors all active ports (default: no). This option will always return OK")

        #-s / --show
        port_opts.add_option("-s", "--show", dest="sh_ports", default=False, action="store_true", help="show all ports (default: no)")

        #-S / --stack-ID
        stack_opts.add_option("-S", "--stack-ID", dest="stack_id", action="store",  help="defines stack topology (allowed input: 1 for standAlone, 2 for duplexChain and 3 for duplexRing  (default: 1(standAlone))")

        #-D / --devices
        device_opts.add_option("-D", "--devices", dest="devices_number", default="default", action="store", help="set the number of devices in stack, useful i.e. when checking the stack and a device fails, since a chain topology with a failed device still corresponds to a chain  (default: 1)")
        
        #parse arguments
        (options, args) = parser.parse_args()

        snmp_community = options.snmp_comm
        snmp_version = options.snmp_vers
        snmp_port = options.snmp_port
        host = options.host
        #set loggin
        if options.debug:

          logging.basicConfig(level=logging.DEBUG)
          LOGGER.setLevel(logging.DEBUG)
        else:
          logging.basicConfig()
          LOGGER.setLevel(logging.INFO)
        
          #die in a fire if important information missing
          #if not options.ports and options.all_ports is False and options.act_ports is False:
          #LOGGER.error("Please specify ports to monitor! (see -h/--help)")
          #exit(2)

        if len(options.host) == 0:
                print("Please define host IP")

        elif (options.ports) == None   and  (options.stack_id) == None  and  (options.devices_number) == "default" and (options.all_ports) == "False" and (options.sh_ports) == "False" and (options.act_ports) == "False":
                print("Please specify at least one option. Type -h or --help for options")
        
        elif options.ports:
                get_specific_ports(options.ports)

        elif options.stack_id:
                        devices_number = options.devices_number
                        
                        if int(options.stack_id) > 3:
                           print("Stack ID is not valid. Type -h or --help for options")
                        else:
                           check_stack(options.stack_id, devices_number)


        elif options.devices_number:
                if options.stack_id:
                  pass
                elif options.devices_number == "default":
                  pass
                else:
                  check_stack(options.stack_id,options.devices_number)
        #debug outputs
        LOGGER.debug("OPTIONS: {0}".format(options))
        LOGGER.debug("PORTS: {0}".format(my_ports))
        LOGGER.debug("STACK: {0}".format(my_ports))
        LOGGER.debug("DEVICES: {0}".format(my_ports))
        
        #get number of ports
        if options.all_ports:
                portsCollected = get_all_ports(snmp_community,snmp_version,snmp_port)
                check_switch_ports(portsCollected,"down")


        elif options.act_ports:
                portsCollected = get_all_ports(snmp_community,snmp_version,snmp_port)
                check_switch_ports(portsCollected,"active")


        elif options.sh_ports:
                portsCollected = get_all_ports(snmp_community,snmp_version,snmp_port)
                check_switch_ports(portsCollected,"show")
                                                

