# Router-Dataplane
Time:20h

For testing use:
  -sudo python3 topo.py
  -inside terminals: make run_router0, make run_router1
  
I created a structure of the package in which I added: the size, the content, the interface as well as the address for the next hop
I used the structure to add the package to the queue

For efficient LPM we used binary search:
      I sorted the table according to the prefix and then according to the mask, both descending
      in the binary search function, if we find a match, we iteratively search upwards for the largest mask with the largest prefix
             when I find a prefix greater than the prefix between the ip given as a parameter and the mask, I stop (the ip no longer belongs to the network)
             I used iterative because it was faster to find LPM Ul than to continue the binary search

I used a function to extract an entry from the ARP table (I search until I find an ip match between the ARP table and the searched address)


When I receive a packet I check what type it is (IP OR ARP)
     If it is of the IP type:
         If the package is for the router and is of the request type, I send an IMCP reply:
             I create a new buffer and put all the data from the old buffer into the new one
             I update the length and take a pointer for each individual structure
             for the ethernet structure, I reverse the source and destination address
             also for the ip structure, where I change the type (depending on what type I want the reply to be) and update the checksum
             I send the package back
              I used this format for ICMP reply even if ttl is less than 1 and if I don't find a next hop

         If the package needs to be forwarded:
             I check the checksum and drop it if it is wrong
             I check the ttl and drop it if it is less than 2
             I am looking for the address for the next hop (if not found, I send an ICMP reply)
             I use the function described above to extract the mac address for the next hop
             if the mac address was not found, I put the package in the queue and make an arp request
                  for arp request:
                     allocate two ethernet and arp header type structures
                     for both structures, I filled in the fields according to the statement of the theme
                     I used the function get_interface_mac to directly put the MAC address of the source in structures using the interface given by the LPM function
                     for the destination mac fields I put the broadcast address
                     I put the structures in buff and sent them on
             if there is a mac address for the next hop, I update the ethernet header and the interface
    
     If it is of ARP type:
         I take a pointer for each structure
         if it is reply type:
             I check if it is for the router, otherwise I drop it
             I add the mac address and the ip address in the ARP table
             reallocate the ARP table if needed
             as long as I have packets in the queue, I remove them and send them on the next hop
                  I use the function to extract the mac address of the next hop and update the ethernet structure
             if there is a package that does not yet have the mac address in the ARP table, I add it back to the queue and stop

         if it is of arp request type:
             if it is for the router, I create an arp reply
                 change the length of the package
                 I create a new buff in which I put the data from the old buff
                 I use get_interface_mac to put the requested mac address in the source fields
                 I reverse the destination fields with the old source ones
                 I send the package back
