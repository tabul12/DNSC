#include <stdio.h> 
#include <string.h>    
#include <stdlib.h>    
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>

#define code_A 1 
#define code_NS 2
#define code_MX 15
#define code_TXT 16
#define code_SOA 6
#define code_AAAA 28
#define code_CNAME 5
#define code_ALL 255
#define PORT 53
#define HEAD_SIZE 12
#define QUESTION_SIZE 4
char dns_server[256];
int dns_server_count = 0;
//es wertilini formidan gadmoyvana
void convert_from_dot_to_name_format(unsigned char* dns,unsigned char* host)
{
    strcat((char*)host,".");

    int lock = 0;
    int i;
    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns = i-lock;
            dns++;
            for(;lock<i;lock++)
            {
                *dns=host[lock];
                dns++;
            }
            lock++;
        }
    }
    *dns='\0';
    dns++;
}
//gasagzavni mexsierebis gagzavna
void *make_row_array(unsigned char *host,unsigned short query_type,int* buff_size)
{
	void* buff=malloc(65536);

	unsigned char * temp=(char*)buff;
    *((unsigned short*)temp)=(unsigned short) htons(getpid());
  	temp=temp+2;

  	*((unsigned short*)temp)=(unsigned short) htons(256);
  	temp=temp+2;

  	*((unsigned short*)temp)=(unsigned short) htons(1); //QDCOUNT
  	temp=temp+2;

  	*((unsigned short*)temp)=(unsigned short) htons(0); //ANCOUNT
  	temp=temp+2;
 
  	*((unsigned short*)temp)=(unsigned short) htons(0); //NSCOUNT
  	temp=temp+2;

  	*((unsigned short*)temp)=(unsigned short) htons(0); //ARCOUNT
  	temp=temp+2;

	unsigned char* qname=temp;

	convert_from_dot_to_name_format(qname,host);


	//add qinfo
	int len=strlen((const char*)qname) + 1;
	unsigned char * qinfo=qname+len;
	temp=qinfo;
	
	*((unsigned short*)temp)=htons(query_type);
	temp=temp+2;

	*((unsigned short*)temp)=htons(1);
	temp=temp+2;
	int size=HEAD_SIZE+len+QUESTION_SIZE;
	*buff_size=size;
	return buff;
}
//akonvertirebs wertilian formatshi
char* convert_to_dot_form(char* a)
{
  char *point=a;
  char* ret=malloc(strlen(a)+1);
  char* pointb=ret;

  uint8_t cur=0;
  while(1)
  {
    uint8_t offset=(uint8_t)a[cur];
    cur++;
    if(offset==0) break;

    uint8_t ind;
    for(ind=cur; ind<cur+offset; ind++)
    {
       ret[ind-1]=a[ind];
    }
    cur=ind;
    ret[cur-1]=(char)'.';
  }
  ret[cur-2]='\0';
  return ret;
}
//rekursiuli ayola ciklit implementirebuli
int recursion_imitation(char* head,char * read_pointer)
{
    int byte_used=0;

    int indicator=0;
    int indicator1=0;
    char* recur=read_pointer;
    
    indicator=0;
    indicator1=0;

    while(1)
    {
        uint16_t tem=ntohs(*((uint16_t*)recur));
        if((1<<15)+(1<<14)<=tem)
        {
          tem-=((1<<15)+(1<<14));
          recur=((char*)head+tem);
          if(indicator1==0){byte_used=byte_used+2;}
          indicator1++;
          indicator++;
        }
        else
        {
          uint8_t offset=*((uint8_t*)recur);
          if(indicator==0)
            byte_used++;
          recur++;
          if(offset==0){ printf("%s ","");break;}
          uint8_t p;
          for(p=0; p<offset; p++)
          {
              printf("%c",*(recur));
              recur++;
              if(indicator==0)
                byte_used++;
          }
          printf("%c",'.');
        }
    }
    return byte_used;
}
//ვამუშავებთ A ტიპის რდატას 
void execute_A(char* read_pointer){
    uint32_t ipv4=*(uint32_t*)read_pointer;
    printf("%s","has address ");

    struct sockaddr_in antelope;
    antelope.sin_addr.s_addr=ipv4;

    char * some_addr=malloc(32);
    some_addr=inet_ntoa(antelope.sin_addr);
    printf("%s\n",some_addr);
}
// ვამუშავებთ NS სს.
void execute_NS(char* head,char* read_pointer){
  printf("%s","name server " );
  recursion_imitation(head,read_pointer);
  printf("%s\n","");
}
//MX
void execute_MX(char* head,char* read_pointer){
  printf("%s","mail is handled by " );
  uint16_t xx=ntohs(*((uint16_t*)read_pointer));
  read_pointer=read_pointer+2;
  printf("%u ",xx);
  recursion_imitation(head,read_pointer);
  printf("%s\n","");
}
//txt
void execute_TXT(char* head,char* read_pointer){
  recursion_imitation(head,read_pointer);
  printf("%s\n","");
}
//soa
void execute_SOA(char* head,char* read_pointer){
  printf("%s","has SOA record ");
  int size=recursion_imitation(head,read_pointer);
  read_pointer=read_pointer+size;
  printf("%s ","");
  size=recursion_imitation(head,read_pointer);
  read_pointer=read_pointer+size;

  uint32_t a1=ntohl(*((uint32_t*)read_pointer));
  read_pointer=read_pointer+4;

  uint32_t a2=ntohl(*((uint32_t*)read_pointer));
  read_pointer=read_pointer+4;

  uint32_t a3=ntohl(*((uint32_t*)read_pointer));
  read_pointer=read_pointer+4;

  uint32_t a4=ntohl(*((uint32_t*)read_pointer));
  read_pointer=read_pointer+4;

  uint32_t a5=ntohl(*((uint32_t*)read_pointer));
  read_pointer=read_pointer+4;

  printf("%u ",a1);
  printf("%u ",a2);
  printf("%u ",a3);
  printf("%u ",a4);
  printf("%u", a5);
  printf("%s\n","");
}
//AAAA answer
void execute_AAAA(char* read_pointer){
  printf("%s ","has ipv6 address ");
  char* buff = (char*)malloc(INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6,read_pointer,buff,INET6_ADDRSTRLEN);
  printf("%s\n",buff);
}
//CNAME answer
void execute_CNAME(char* head,char* read_pointer,uint16_t RDLENGTH){
  recursion_imitation(head,read_pointer);
  printf("%s\n","");
}
//აქ ვაკეთებთ დაბეჭდვას სექციების, answer, additional
int print_sections(char* head,char* read_pointer,unsigned short N_COUNT)
{
  uint16_t i=0;
  int dst_size=0;
  for(i=0; i<N_COUNT; i++)
  {
      
      int used=recursion_imitation(head,read_pointer);
      read_pointer=read_pointer+used; //აქ გადავწიე იმდენი ბიჯიტ რამდენი ბაიტითაც წაწევა მომიწია
      dst_size=dst_size+used;

      uint16_t resp_type=ntohs(*((uint16_t*)read_pointer));
      read_pointer=read_pointer+2;
      dst_size=dst_size+2;
      
      uint16_t resp_cl=ntohs(*((uint16_t*)read_pointer));
      read_pointer=read_pointer+2;
      dst_size=dst_size+2;
      
      uint32_t resp_ttl=ntohl(*((uint32_t*)read_pointer));
      read_pointer=read_pointer+4;
      dst_size=dst_size+4;

      uint16_t RDLENGTH=ntohs(*((uint16_t*)read_pointer));
      read_pointer=read_pointer+2;
      dst_size=dst_size+2;
      //gavarkvev tips
      if(resp_type==code_A) execute_A(read_pointer);
      if(resp_type==code_NS) execute_NS(head,read_pointer);
      if(resp_type==code_MX) execute_MX(head,read_pointer);
      if(resp_type==code_TXT) execute_TXT(head,read_pointer);
      if(resp_type==code_SOA) execute_SOA(head,read_pointer);
      if(resp_type==code_AAAA) execute_AAAA(read_pointer);
      if(resp_type==code_CNAME) execute_CNAME(head,read_pointer,RDLENGTH);

      read_pointer=read_pointer+RDLENGTH;
      dst_size=dst_size+RDLENGTH;

  }
  return dst_size;
}
//მთავარი პროგრამა რომელიც ანაწილებს საქმეს
void get_host_program(unsigned char *host , unsigned short query_type)
{
  	unsigned char buff[65536];
    unsigned char *qname;
    unsigned char *reader;
    struct sockaddr_in a;    
    struct sockaddr_in dest;
    int s;
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);
    dest.sin_addr.s_addr = inet_addr(dns_server);
    int* buff_size=malloc(sizeof(int));
    void* row_ar=make_row_array(host,query_type,buff_size);
    memcpy(buff,row_ar,*buff_size);

    if(sendto(s,(char*)buff,*buff_size,0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    //ახლა დავიწყებ მიღებას
    unsigned char recv_buff[65536];
    int flag;
    if(recvfrom (s,(char*)recv_buff , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&flag ) < 0)
    {
        perror("recvfrom failed");
    }
    char * read_pointer=(char*)recv_buff;
    char* head=read_pointer;
    read_pointer=read_pointer+(*buff_size);//გადავხტით respnses კითხვაზე

    unsigned short ANCOUNT= ntohs(*((uint16_t*)(head+6)));
    unsigned short ARCOUNT= ntohs(*((uint16_t*)(head+10)));
    printf("Answer Number :%u\n",ANCOUNT);
    printf("Additional Number :%u\n",ARCOUNT);
    printf("%s\n","Answer Section"); //პასუხების სექცია 
    int sz=print_sections(head,read_pointer,ANCOUNT);
    read_pointer=read_pointer+sz;

    printf("%s\n","Additional section");
    print_sections(head,read_pointer,ARCOUNT);


    free(row_ar);
}
int main(int argc, char const *argv[])
{
  //uni
  unsigned short query_type;
	unsigned char* hostname;
  int ind=2;
  if(strcmp(argv[1],"-a")==0)
      query_type=code_ALL;
  else      //ვამოწმებ ტიპებს
  if(strcmp(argv[1],"-t")==0)
  {
      if(strcmp(argv[2],"A")==0) query_type=code_A;
      if(strcmp(argv[2],"NS")==0) query_type=code_NS;
      if(strcmp(argv[2],"MX")==0) query_type=code_MX;
      if(strcmp(argv[2],"TXT")==0) query_type=code_TXT;
      if(strcmp(argv[2],"SOA")==0) query_type=code_SOA;
      if(strcmp(argv[2],"AAAA")==0) query_type=code_AAAA;
      if(strcmp(argv[2],"CNAME")==0) query_type=code_CNAME;
      ind++;
  }
	strcpy(dns_server,argv[ind+1]);
  hostname=(unsigned char*)argv[ind];

	get_host_program(hostname,query_type);
	return 0;
}
