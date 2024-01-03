package net.floodlightcontroller.headerextract;

import java.util.Collection;
import java.util.Map;
import org.projectfloodlight.openflow.protocol.OFMatchType;

import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.projectfloodlight.openflow.protocol.OFMatchV1;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.util.HexString;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import java.util.Random;

public class HeaderExtract implements IOFMessageListener, IFloodlightModule {
	
	public final int DEFAULT_CACHE_SIZE = 10;
	protected IFloodlightProviderService floodlightProvider;
	 private IStaticFlowEntryPusherService flowPusher;
	 private static Map<IPv4Address, String> ipMacMap;
	 private Random random = new Random();
	 private Map<IPv4Address, Integer> connectionState = new HashMap<>();
	 private IPv4Address webServerMinRandom = null;
//	 String serverIPToBlock = "192.168.1.4"; // Replace with the IP address of the server you want to block
	 List<IPv4Address> allowedServers = new ArrayList<>();
	 private String server1Blocked=null;
	 private String server2Blocked=null;
	 
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "Names";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}
	
	

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		ipMacMap = new HashMap<>();
		allowedServers.clear();
		server1Blocked="";
		server2Blocked="";

		// TODO Auto-generated method stub

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		server1Blocked="";
		server2Blocked="";
		allowedServers.clear();
        if (msg.getType() == OFType.PACKET_IN) {
            OFPacketIn packetIn = (OFPacketIn) msg;
            Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx,
                    IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            // Check if the packet is an IPv4 packet
            if (ethPacket.getEtherType() == EthType.IPv4) {
                IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
                IPv4Address srcIP = ipv4Packet.getSourceAddress();
                IPv4Address dstIP = ipv4Packet.getDestinationAddress();
                String srcMac = HexString.toHexString(ethPacket.getSourceMACAddress().getLong());
             // Save IP and MAC address in the map
                ipMacMap.put(srcIP, srcMac);
                connectionState.put(IPv4Address.of("192.168.1.3"), random.nextInt(10) + 1);
                connectionState.put(IPv4Address.of("192.168.1.4"), random.nextInt(10) + 1);                
                connectionState.put(IPv4Address.of("192.168.1.5"), random.nextInt(10) + 1);              
                if (srcIP.equals(IPv4Address.of("192.168.1.3"))) {
                	if (!connectionState.containsKey(srcIP)) {
                		System.out.println("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
                	}
                    
                } else if (srcIP.equals(IPv4Address.of("192.168.1.4"))) {
                    // Generate a random number between 1 and 10 for the third server
                	if (!connectionState.containsKey(srcIP)) {
                        // Generate a random number between 1 and 10 for the second server
                		System.out.println("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
//                        }
                	}               
                } else if (srcIP.equals(IPv4Address.of("192.168.1.5"))) {
                    // Generate a random number between 1 and 10 for the third server
                	if (!connectionState.containsKey(srcIP)) {
                        // Generate a random number between 1 and 10 for the third server
                		System.out.println("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");               		
                        }
                	}                 
                else if (srcIP.equals(IPv4Address.of("192.168.1.8"))) {
                	int min=getMinimum(connectionState.get(IPv4Address.of("192.168.1.3")), connectionState.get(IPv4Address.of("192.168.1.4")), connectionState.get(IPv4Address.of("192.168.1.5")));
                	if(min==connectionState.get(IPv4Address.of("192.168.1.3"))){
                		webServerMinRandom = IPv4Address.of("192.168.1.3");
                		allowedServers.add(IPv4Address.of("192.168.1.3"));
//                		allowedServers.add(IPv4Address.of("192.168.1.4"));
//                		allowedServers.add(IPv4Address.of("192.168.1.5"));
                		server1Blocked="192.168.1.4";
                		server2Blocked="192.168.1.5";
                	}
                	else if(min==connectionState.get(IPv4Address.of("192.168.1.4"))){
                		webServerMinRandom = IPv4Address.of("192.168.1.4");
//                		allowedServers.add(IPv4Address.of("192.168.1.3"));
                		allowedServers.add(IPv4Address.of("192.168.1.4"));
//                		allowedServers.add(IPv4Address.of("192.168.1.5"));
                		server1Blocked="192.168.1.3";
                		server2Blocked="192.168.1.5";
                	}
                	else if(min==connectionState.get(IPv4Address.of("192.168.1.5"))){
                		webServerMinRandom = IPv4Address.of("192.168.1.5");
//                		allowedServers.add(IPv4Address.of("192.168.1.3"));
//                		allowedServers.add(IPv4Address.of("192.168.1.4"));
                		allowedServers.add(IPv4Address.of("192.168.1.5"));
                		server1Blocked="192.168.1.4";
                		server2Blocked="192.168.1.3";
                	}
                	System.out.println(connectionState.get(IPv4Address.of("192.168.1.3"))+"   "+
                			connectionState.get(IPv4Address.of("192.168.1.4"))+
                			"   "+connectionState.get(IPv4Address.of("192.168.1.5")));
                	System.out.println("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL");
            		
                	if (webServerMinRandom != null && !srcIP.equals(webServerMinRandom)) {
                		System.out.println("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK");
                		System.out.println("Forwarding request from host with IP 192.168.1.8 to web server with IP " + webServerMinRandom);
                        // Add your code here to forward requests to the web server with the minimum random number                		
                		System.out.println(webServerMinRandom);
                		String destMac = ipMacMap.get(webServerMinRandom);
                		System.out.println(destMac);
                		String modifiedStringDestMac = destMac.substring(6);
                		System.out.println(modifiedStringDestMac);
                		
                	    if (destMac != null) {
                	        Ethernet eth = new Ethernet();
                	        eth.setSourceMACAddress(ethPacket.getSourceMACAddress());
                	        eth.setDestinationMACAddress(MacAddress.of(modifiedStringDestMac));
                	        eth.setEtherType(EthType.IPv4);
                	        IPv4 ipPacket = new IPv4();
                	        ipPacket.setSourceAddress(srcIP);
                	        ipPacket.setDestinationAddress(webServerMinRandom);
                	        ipPacket.setPayload(ethPacket.getPayload());
                	        eth.setPayload(ipPacket);

                	        // Print the destination IP add19ress before forwarding
                	        System.out.println("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
                	        System.out.println("Forwarding packet to destination IP: " + ipPacket.getDestinationAddress());
                	        
                	        OFPacketOut po = sw.getOFFactory().buildPacketOut()
                	                .setData(eth.serialize())
                	                .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.NORMAL, 0xffFFffFF)))
                	                .setInPort(OFPort.CONTROLLER)
                	                .build();

                	        sw.write(po);
                	    }                	
                	}	
                	blockRule(server1Blocked, allowedServers,webServerMinRandom,dstIP);
                	blockRule(server2Blocked, allowedServers,webServerMinRandom,dstIP);
                	
                }
                printIpMacMap();
                System.out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                System.out.println("Destination IP Address: " + dstIP.toString());
                System.out.println("Source MAC Address: " + HexString.toHexString(ethPacket.getSourceMACAddress().getLong()));
                System.out.println("PacketIn ARRAY: " + ethPacket.toString());
            }
        }
        return Command.CONTINUE;
    }
	
	private void printIpMacMap() {
        System.out.println("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        for (Map.Entry<IPv4Address, String> entry : ipMacMap.entrySet()) {
            IPv4Address ip = entry.getKey();
            String mac = entry.getValue();
            System.out.println("IP: " + ip.toString() + ", MAC: " + mac);
        }
    }
	
	public static void blockRule(String serverIPToBlock,List<IPv4Address> allowedServers,IPv4Address srcIP,IPv4Address dstIP){
		
		  // Create a new OFFlowMod object for the block rule
        OFFlowMod.Builder builder = OFFactories.getFactory(OFVersion.OF_13).buildFlowAdd();
        builder.setIdleTimeout(3000) // Rule remains for 3000 milliseconds
                .setHardTimeout(0) // No hard timeout
                .setPriority(100) // Rule priority is 100
                .setFlags(new HashSet<>(Collections.singletonList(OFFlowModFlags.SEND_FLOW_REM))) // Send flow removed notification
                .setMatch(buildMatch(serverIPToBlock,srcIP,ipMacMap.get(srcIP),ipMacMap.get(dstIP))); // Set the match fields

        List<OFAction> actions = new ArrayList<>(); // List of actions
        // Add actions to the list (In this case, the list is empty for blocking)
        builder.setActions(actions);

        OFFlowMod blockRule = builder.build();

        // Send the block rule to the switch using the appropriate OpenFlow controller API

        // Example: Printing the block rule
        System.out.println("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        System.out.println("Block Rule:");
        System.out.println(blockRule.toString());

        // Example: Accessing the allowed servers
//        List<IPv4Address> allowedServers = new ArrayList<>();
//        if(serverIPToBlock)
//        allowedServers.add(IPv4Address.of("192.168.1.4"));
//        allowedServers.add(IPv4Address.of("192.168.1.5"));

        // Example: Verifying the validity of the rule
//        IPv4Address srcIP = IPv4Address.of("192.168.1.8");
        boolean isValid = !serverIPToBlock.equals(srcIP) && allowedServers.contains(srcIP);
        System.out.println(serverIPToBlock+"     "+(srcIP));
        System.out.println(allowedServers);
        System.out.println("Validity: " + isValid);
		

	}
	
	
	
	  private static Match buildMatch(String serverIP,IPv4Address srcIP,String srcMAC,String dstMAC) {
	        Match.Builder matchBuilder = OFFactories.getFactory(OFVersion.OF_13).buildMatch();

//	        String modifiedStringDestMac = destMac.substring(6);
	        // Set the match fields
	        matchBuilder.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
	        matchBuilder.setExact(MatchField.ETH_TYPE, EthType.IPv4);
	        matchBuilder.setExact(MatchField.IPV4_SRC, srcIP);
	        matchBuilder.setExact(MatchField.IPV4_DST, IPv4Address.of(serverIP));
	        matchBuilder.setExact(MatchField.ETH_SRC, MacAddress.of(HexString.fromHexString(srcMAC.substring(6))));
	        matchBuilder.setExact(MatchField.ETH_DST, MacAddress.of(HexString.fromHexString(dstMAC.substring(6))));

	        return matchBuilder.build();
	    }
	
	public static int getMinimum(int a, int b, int c) {
        return Math.min(Math.min(a, b), c);
    }

}
