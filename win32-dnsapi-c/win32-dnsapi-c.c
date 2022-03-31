#include <winsock2.h> //winsock
#include <ws2tcpip.h>
#include <windns.h> //DNS api's
#include <stdio.h> //standard i/o

#define MAX_IP_STR_LEN 20
#define IP_SEC_LEN 4

//Usage of the program
void Usage(char* progname) {
    fprintf(stderr, "Usage\n%s -n [HostName|IP Address] -t [Type] -s [DnsServerIp]\n", progname);
    fprintf(stderr, "Where:\n\t\"HostName|IP Address\" is the name or IP address of the computer ");
    fprintf(stderr, "of the record set being queried\n");
    fprintf(stderr, "\t\"Type\" is the type of record set to be queried A or PTR\n");
    fprintf(stderr, "\t\"DnsServerIp\"is the IP address of DNS server (in dotted decimal notation)");
    fprintf(stderr, "to which the query should be sent\n");
    exit(1);
}

void ReverseIP(char* pIP)
{
    char seps[] = ".";
    char* token;
    char pIPSec[4][IP_SEC_LEN];
    int i = 0;
    char* token_context = NULL;
    token = strtok_s(pIP, seps, &token_context);
    while (token != NULL)
    {
        /* While there are "." characters in "string"*/
        sprintf_s(pIPSec[i], IP_SEC_LEN, "%s", token);
        /* Get next "." character: */
        token = strtok_s(NULL, seps, &token_context);
        i++;
    }
    sprintf_s(pIP, MAX_IP_STR_LEN, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], "IN-ADDR.ARPA");
}

// the main function 
void main(int argc, char* argv[])
{
    DNS_STATUS status; //Return value of DnsQuery_A() function.
    PDNS_RECORD pDnsRecord; //Pointer to DNS_RECORD structure.
    IP4_ARRAY* pSrvList = NULL; //Pointer to IP4_ARRAY structure.
    WORD wType; //Type of the record to be queried.
    char* pOwnerName = NULL; //Owner name to be queried.
    char pReversedIP[MAX_IP_STR_LEN];//Reversed IP address.
    char DnsServIp[MAX_IP_STR_LEN]; //DNS server ip address.
    DNS_FREE_TYPE freetype;
    freetype = DnsFreeRecordListDeep;
    //IN_ADDR ipaddr;

    if (argc > 4)
    {
        for (int i = 1; i < argc; i++)
        {
            if ((argv[i][0] == '-') || (argv[i][0] == '/'))
            {
                switch (tolower(argv[i][1]))
                {
                case 'n':
                    pOwnerName = argv[++i];
                    break;
                case 't':
                    if (!_stricmp(argv[i + 1], "A"))
                        wType = DNS_TYPE_A; //Query host records to resolve a name.
                    else if (!_stricmp(argv[i + 1], "PTR"))
                    {
                        //pOwnerName should be in "xxx.xxx.xxx.xxx" format
                        if (strlen(pOwnerName) <= 15)
                        {
                            //You must reverse the IP address to request a Reverse Lookup 
                            //of a host name.
                            sprintf_s(pReversedIP, MAX_IP_STR_LEN, "%s", pOwnerName);
                            ReverseIP(pReversedIP);
                            pOwnerName = pReversedIP;
                            wType = DNS_TYPE_PTR; //Query PTR records to resolve an IP address
                        }
                        else
                        {
                            Usage(argv[0]);
                        }
                    }
                    else
                        Usage(argv[0]);
                    i++;
                    break;

                case 's':
                    // Allocate memory for IP4_ARRAY structure.
                    pSrvList = (PIP4_ARRAY)LocalAlloc(LPTR, sizeof(IP4_ARRAY));
                    if (!pSrvList)
                    {
                        printf("Memory allocation failed \n");
                        exit(1);
                    }
                    if (argv[++i])
                    {
                        strcpy_s(DnsServIp, MAX_IP_STR_LEN, argv[i]);
                        pSrvList->AddrCount = 1;
                        IP4_ADDRESS addr;
                        int err = inet_pton(AF_INET, DnsServIp, &addr);
                        if (err == -1) {
                            printf("DNS server '%s' was not a valid IP4 string.\n", DnsServIp);
                            exit(1);
                        }
                        else if (err != 1) {
                            printf("DNS server '%s' parse error: %d\n", DnsServIp, err);
                            exit(1);
                        }
                        pSrvList->AddrArray[0] = addr; //DNS server IP address
                        break;
                    }

                default:
                    Usage(argv[0]);
                    break;
                }
            }
            else
                Usage(argv[0]);
        }
    }
    else
        Usage(argv[0]);

    // Calling function DnsQuery to query Host or PTR records 
    status = DnsQuery_A(pOwnerName, //Pointer to OwnerName. 
        wType, //Type of the record to be queried.
        DNS_QUERY_BYPASS_CACHE, // Bypasses the resolver cache on the lookup. 
        pSrvList, //Contains DNS server IP address.
        &pDnsRecord, //Resource record that contains the response.
        NULL); //Reserved for future use.

    if (status)
    {
        if (wType == DNS_TYPE_A)
            printf("Failed to query the host record for %s and the error is %d \n", pOwnerName, status);
        else
            printf("Failed to query the PTR record and the error is %d \n", status);
    }
    else
    {
        if (wType == DNS_TYPE_A)
        {
            //convert the Internet network address into a string
            //in Internet standard dotted format.
            const IN_ADDR ipaddr = { .S_un.S_addr = (pDnsRecord->Data.A.IpAddress) };
            //int p = inet_ntop(ipaddr);
            char buf[MAX_IP_STR_LEN];
            PSTR bufp = &buf;
            const char* ipaddr_str = inet_ntop(AF_INET, &ipaddr, bufp, MAX_IP_STR_LEN);
            printf("The IP address of the host %s is %s \n", pOwnerName, ipaddr_str);

            // Free memory allocated for DNS records. 
            DnsRecordListFree(pDnsRecord, freetype);
        }
        else
        {
            printf("The host name is %ws \n", (pDnsRecord->Data.PTR.pNameHost));

            // Free memory allocated for DNS records. 
            DnsRecordListFree(pDnsRecord, freetype);
        }
    }
    LocalFree(pSrvList);
}