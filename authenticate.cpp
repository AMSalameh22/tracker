  #include <iostream>
  #include <curl/curl.h>
  #include <stdio.h>
  #include <string.h>
  #include <unistd.h>          
  #include <errno.h>           
  #include <sys/types.h>       
  #include <sys/socket.h>      
  #include <sys/ioctl.h>  
  #include <sys/resource.h>    
  #include <sys/utsname.h>       
  #include <netdb.h>           
  #include <netinet/in.h>      
  #include <netinet/in_systm.h>                 
  #include <netinet/ip.h>      
  #include <netinet/ip_icmp.h> 
  #include <assert.h>
  #include <linux/if.h>    
  #include <linux/sockios.h>
  #include <sstream>
  #include "SHA256.h"
  using namespace std;
  const char* getMachineName() 
  { 
    static struct utsname u;  

    if ( uname( &u ) < 0 )    
    {       
        assert(0);             
        return "unknown";      
    }       

    return u.nodename;        
  }   


  //---------------------------------get MAC addresses ------------------------------------unsigned short-unsigned short----------        
  // we just need this for purposes of unique machine id. So any one or two mac's is fine.            
  unsigned short hashMacAddress( unsigned char* mac )                 
  { 
    unsigned short hash = 0;             

    for ( unsigned int i = 0; i < 6; i++ )              
    {       
        hash += ( mac[i] << (( i & 1 ) * 8 ));           
    }       
    return hash;              
  } 

  void getMacHash( unsigned short& mac1, unsigned short& mac2 )       
  { 
    mac1 = 0;                 
    mac2 = 0;                 

          

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP );                  
    if ( sock < 0 ) return;   

    // enumerate all IP addresses of the system         
    struct ifconf conf;       
    char ifconfbuf[ 128 * sizeof(struct ifreq)  ];      
    memset( ifconfbuf, 0, sizeof( ifconfbuf ));         
    conf.ifc_buf = ifconfbuf; 
    conf.ifc_len = sizeof( ifconfbuf );        
    if ( ioctl( sock, SIOCGIFCONF, &conf ))    
    {       
        assert(0);             
        return;                
    }       

    // get MAC address        
    bool foundMac1 = false;   
    struct ifreq* ifr;        
    for ( ifr = conf.ifc_req; (char*)ifr < (char*)conf.ifc_req + conf.ifc_len; ifr++ ) 
    {       
        if ( ifr->ifr_addr.sa_data == (ifr+1)->ifr_addr.sa_data )          
          continue;  // duplicate, skip it     

        if ( ioctl( sock, SIOCGIFFLAGS, ifr ))           
          continue;  // failed to get flags, skip it    
        if ( ioctl( sock, SIOCGIFHWADDR, ifr ) == 0 )    
        {    
          if ( !foundMac1 )   
          { 
              foundMac1 = true;                 
              mac1 = hashMacAddress( (unsigned char*)&(ifr->ifr_addr.sa_data));       
          } else {            
              mac2 = hashMacAddress( (unsigned char*)&(ifr->ifr_addr.sa_data));       
              break;           
          } 
        }    
    }       

    close( sock );            

    // sort the mac addresses. We don't want to invalidate                
    // both macs if they just change order.    
    if ( mac1 > mac2 )        
    {       
        unsigned short tmp = mac2;        
        mac2 = mac1;           
        mac1 = tmp;            
    }       
  } 

  unsigned short getVolumeHash()          
  { 
    // we don't have a 'volume serial number' like on windows. Lets hash the system name instead.    
    unsigned char* sysname = (unsigned char*)getMachineName();       
    unsigned short hash = 0;             

    for ( unsigned int i = 0; sysname[i]; i++ )         
        hash += ( sysname[i] << (( i & 1 ) * 8 ));       

    return hash;              
  } 

            

  static void getCpuid( unsigned int* p, unsigned int ax )       
  {         
      __asm __volatile         
      (   "movl %%ebx, %%esi\n\t"               
          "cpuid\n\t"          
          "xchgl %%ebx, %%esi" 
          : "=a" (p[0]), "=S" (p[1]),           
            "=c" (p[2]), "=d" (p[3])            
          : "0" (ax)           
      );     
  }         

  unsigned short getCpuHash()            
  {         
      unsigned int cpuinfo[4] = { 0, 0, 0, 0 };          
      getCpuid( cpuinfo, 0 );  
      unsigned short hash = 0;            
      unsigned int* ptr = (&cpuinfo[0]);                 
      for ( unsigned int i = 0; i < 4; i++ )             
        hash += (ptr[i] & 0xFFFF) + ( ptr[i] >> 16 );   

      return hash;             
  }                

  static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp){
      ((std::string*)userp)->append((char*)contents, size * nmemb);
      return size * nmemb;
  }
  std::string get_host_info(){
      CURL * curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
      curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.5.2:18080/");
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
      struct curl_slist *headers=NULL;
      headers = curl_slist_append(headers, "Auth: 123");
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      res = curl_easy_perform(curl);
      curl_easy_cleanup(curl);

      std::cout << readBuffer << std::endl;
    }
  }
  int main(){
    std::stringstream ss ;
    std::string str=getMachineName();
   char buffer [sizeof(unsigned int)*8+1];
    sprintf(buffer, "%u", getCpuHash());
    ss << str << buffer;
    sprintf(buffer, "%u", getVolumeHash());
    ss << buffer;
    //cout << ss.str() ;
    string s = ss.str();
SHA256 sha;
sha.update(s);
uint8_t * digest = sha.digest();

std::cout << SHA256::toString(digest) << std::endl;

get_host_info();
//delete[] digest; // Don't forget to free the digest!
    //cout <<  ss << endl;
  //printf("Machine: %s\n", getMachineName());
  //printf("CPU: %d\n", getCpuHash());
  //printf("Volume: %d\n", getVolumeHash());
    return 0;
  }