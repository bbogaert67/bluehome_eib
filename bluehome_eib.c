/*
 * bluehouse_eib - link eib with MQTTClient
 *
 * based on
 *    eibtrace - eib packet trace - requires linking with -L /usr/local/lib -leibnetmux -lm -lpth
 *    mqtt_paho_c_publisher - requires linking with -lpaho-mqtt3c
 *
 * requires running eibnetmux
 *     eibnetmux - eibnet/ip multiplexer
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <pthread.h>

#include <MQTTClient.h>

#ifndef WITH_LOCALHEADERS
#include <eibnetmux/enmx_lib.h>
#else
#include <../src/client_lib/c/enmx_lib.h>
#endif

/*
 * EIB constants
 */
#define EIB_CTRL_LENGTHTABLE                    0x00
#define EIB_CTRL_LENGTHBYTE                     0x80
#define EIB_CTRL_DATA                           0x00
#define EIB_CTRL_POLL                           0x40
#define EIB_CTRL_REPEAT                         0x00
#define EIB_CTRL_NOREPEAT                       0x20
#define EIB_CTRL_ACK                            0x00
#define EIB_CTRL_NONACK                         0x10
#define EIB_CTRL_PRIO_LOW                       0x0c
#define EIB_CTRL_PRIO_HIGH                      0x04
#define EIB_CTRL_PRIO_ALARM                     0x08
#define EIB_CTRL_PRIO_SYSTEM                    0x00
#define EIB_NETWORK_HOPCOUNT                    0x70
#define EIB_DAF_GROUP                           0x80
#define EIB_DAF_PHYSICAL                        0x00
#define EIB_LL_NETWORK                          0x70
#define T_GROUPDATA_REQ                         0x00
#define A_READ_VALUE_REQ                        0x0000
#define A_WRITE_VALUE_REQ                       0x0080
#define A_RESPONSE_VALUE_REQ                    0x0040

/**
 * cEMI Message Codes
 **/
#define L_BUSMON_IND            0x2B
#define L_RAW_IND               0x2D
#define L_RAW_REQ               0x10
#define L_RAW_CON               0x2F
#define L_DATA_REQ              0x11
#define L_DATA_CON              0x2E
#define L_DATA_IND              0x29
#define L_POLL_DATA_REQ         0x13
#define L_POLL_DATA_CON         0x25
#define M_PROP_READ_REQ         0xFC
#define M_PROP_READ_CON         0xFB
#define M_PROP_WRITE_REQ        0xF6
#define M_PROP_WRITE_CON        0xF5
#define M_PROP_INFO_IND         0xF7
#define M_RESET_REQ             0xF1
#define M_RESET_IND             0xF0

/*
 * EIB Global variables
 */
ENMX_HANDLE     sock_con = 0;
unsigned char   conn_state = 0;

/*
 * EIB local function declarations
 */
static void     Usage( char *progname );
static char     *knx_physical( uint16_t phy_addr );
static char     *knx_group( uint16_t grp_addr );

/*
 * Global MQTT client
 */
MQTTClient client;
MQTTClient_connectOptions conn_opts;

int                     quiet = 0;
FILE                    *logfile;

/*
 * EIB request frame
 */
typedef struct __attribute__((packed)) {
        uint8_t  code;
        uint8_t  zero;
        uint8_t  ctrl;
        uint8_t  ntwrk;
        uint16_t saddr;
        uint16_t daddr;
        uint8_t  length;
        uint8_t  tpci;
        uint8_t  apci;
        uint8_t  data[16];
} CEMIFRAME;

typedef struct device {
  char knx[16];
  char name[64];
  char event[64];
  char type[64];
  struct device * next;
} device;

typedef struct config {
   char address[1024];
   char clientid[255];
   char username[255];
   char password[255];
   char eibd_ip[16];
   char solar_ip[255];
   int qos;
   long timeout;
   struct device * devicelist;
} config;

struct config           configuration;

/*
* Print out when using invalid options
*/
static void Usage( char *progname ) {
    fprintf(logfile, "Usage: %s [options] [hostname[:port]]\n"
                     "where:\n"
                     "  hostname[:port]                      defines eibnetmux server with default port of 4390\n"
                     "\n"
                     "options:\n"
                     "  -u user                              name of user                           default: -\n"
                     "  -c count                             stop after count number of requests    default: endless\n"
                     "  -f filename                          configfile                             default: bluehome.conf\n"
                     "  -l filename                          logfile                                default: on screen\n"
                     "  -q                                   no verbose output (default: no)\n"
                     "\n", basename( progname ));
}

/*
 * get password
 */
int getpassword( char *pwd ) {
    struct termios  term_settings;
    char            *result;

    if( isatty( 0 )) {
        printf( "Password: " );
    }

    tcgetattr( 0, &term_settings );
    term_settings.c_lflag &= (~ECHO);
    tcsetattr( 0, TCSANOW, &term_settings );
    term_settings.c_lflag |= ECHO;

    result = fgets( pwd, 256, stdin );
    printf( "\n" );

    tcsetattr( 0, TCSANOW, &term_settings );

    if( result == NULL ) {
        return( -1 );
    }
    if( pwd[strlen(pwd) -1] == '\n' ) {
        pwd[strlen(pwd) -1] = '\0';
    }
    return( 0 );
}

/*
 * produce hexdump of a (binary) string
 */
char *hexdump( void *string, int len, int spaces ) {
    int             idx = 0;
    unsigned char   *ptr;
    static char     *buf = NULL;
    static int      buflen = 0;

    if( string == NULL ) {
        if( buf != NULL ) {
            free( buf );
            fprintf(stdout, "Free memory of buf\n" );
            buflen = 0;
        }
    }

    if( len == 0 )
        len = strlen( string );
    if( (len *2 + (spaces ? len : 0) +1) > buflen ) {
        buflen = len *2 + (spaces ? len : 0) +1;
        if( buf == NULL )
            buf = malloc( buflen );
        else
            buf = realloc( buf, buflen );
        if( buf == NULL ) {
            fprintf(logfile, "Out of memory: %s\n", strerror( errno ));
            exit( -9 );
        }
    }

    ptr = string;
    while( len > 0 ) {
        sprintf( &buf[idx], "%2.2x", *ptr );
        idx +=2;
        if( spaces ) {
            sprintf( &buf[idx], " " );
            idx++;
        }
        ptr++;
        len--;
    }

    return( buf );
}


/*
 * Shutdown
 *
 * catches SIGINT and SIGTERM and shuts down
 */

void Shutdown( int arg ) {
    fprintf(logfile, "Signal received - shutting down\n" );

    // close monitoring connection
    if( conn_state != 0 ) {
        fprintf(logfile, "Disconnecting from eibnetmux\n" );
        enmx_close( sock_con );
    }

    // Disconnecting MQTT clients
    MQTTClient_disconnect(client, 10000);
 	  MQTTClient_destroy(&client);
    fclose (logfile);
    exit( 0 );
}

int read_configfile(char * filename, struct config * configuration) {
 FILE *file;
 char line[255];
 struct device * lastdevice;

 if (filename == NULL)
    filename = strdup("bluehome.conf");

 file = fopen (filename, "r");

 if (file == NULL) {
   fprintf(logfile, "Can not open configuration file %s\n",filename );
   exit(-1);
 }
 while(fgets(line, sizeof(line), file) != NULL) {
  if (line[0] != '#') {   // skip commented line
     char * token = strtok(line,"=");
     if (strcmp(token,"ADDRESS") == 0)
        strcpy(configuration->address,strtok(NULL,"\n"));

     if (strcmp(token,"CLIENTID") == 0)
        strcpy(configuration->clientid,strtok(NULL,"\n"));
     if (strcmp(token,"QOS") == 0)
        configuration->qos = atoi(strtok(NULL,"\n"));
     if (strcmp(token,"TIMEOUT") == 0)
        configuration->timeout = strtol(strtok(NULL,"\n"),NULL,0);
     if (strcmp(token,"USERNAME") == 0)
        strcpy(configuration->username,strtok(NULL,"\n"));
     if (strcmp(token,"PASSWORD") == 0)
        strcpy(configuration->password,strtok(NULL,"\n"));
    if (strcmp(token,"SOLAR_IP") == 0)
       strcpy(configuration->solar_ip,strtok(NULL,"\n"));
     if (strcmp(token,"DEVICE") == 0) {
        struct device * newdevice = (device *) malloc(sizeof(device));
        newdevice->next = configuration->devicelist;
        configuration->devicelist = newdevice;
        strcpy(newdevice->knx,strtok(NULL," "));
        strcpy(newdevice->name,strtok(NULL," "));
        strcpy(newdevice->event,strtok(NULL," "));
        strcpy(newdevice->type,strtok(NULL,"\n"));
     }
    }
 }
 if (! quiet) {
    lastdevice = configuration->devicelist;
    while (lastdevice) {
      fprintf(logfile, "On devicelist is %s %s\n",lastdevice->knx,lastdevice->name);
      lastdevice=lastdevice->next;
    }
 }
 fclose(file);
}

/*
    Client subscription to messages, for every message received these functions are called
*/

volatile MQTTClient_deliveryToken deliveredtoken;

void delivered(void *context, MQTTClient_deliveryToken dt) {
  if (! quiet)
	  fprintf(logfile, "Message with token value %d delivery confirmed\n", dt);
	deliveredtoken = dt;
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
	 int             i;
	 char            *payloadptr;
   char            payload[1024];
   struct          device *actual;
   uint16_t        knxaddress = 0;
   uint16_t        eis;
   unsigned char   *data;
   unsigned char   *p_val = NULL;
   int             len;
   char            value_byte;
   unsigned char   value_char;
   int             value_integer;
   uint32_t        value_int32;
   float           value_float;
   char            *string = NULL;
   int             enmx_version;
   ENMX_HANDLE     sock_con2 = 0;

   strncpy(payload,message->payload,message->payloadlen);

	 fprintf(logfile, "Received topic: %s\n", topicName);
	 fprintf(logfile, "Received message: %s\n", payload);

   char devicetype[64];
   char devicename[64];
   char deviceaction[64];
   char devicevalue[64];
   char * token = strtok(payload,":"); // strip everything before first ':''
   token = strtok(NULL,"\"");
   strcpy(devicetype,strtok(NULL,"\""));
   token = strtok(NULL,"\"");
   strcpy(devicename,strtok(NULL,"\""));
   token = strtok(NULL,"\"");
   strcpy(deviceaction,strtok(NULL,"\""));
   token = strtok(NULL,"\"");
   strcpy(devicevalue,strtok(NULL,"\""));
//   fprintf(logfile, "device type:%s name:%s type:%s value:%s\n", devicetype,devicename,deviceaction,devicevalue);

   actual = configuration.devicelist;
   while ((strcmp(actual->name,devicename) != 0) && (actual->next)){
       actual = actual->next;
   }
//   fprintf(logfile, "actual = %s\n",actual->name);

   if (strcmp(actual->name, devicename) == 0) {
      knxaddress = enmx_getaddress(actual->knx);
//      fprintf(logfile, "KNX = %s\n",actual->knx);

      if (strcmp(deviceaction,"BYTE") == 0)   { eis=1;  value_byte = atoi(devicevalue);    p_val = (unsigned char *)&value_byte; }
      if (strcmp(deviceaction,"INT") == 0)    { eis=10; value_integer = atoi(devicevalue); p_val = (unsigned char *)&value_integer; }
      if (strcmp(deviceaction,"INT32") == 0)  { eis=11; value_int32 = atol(devicevalue);   p_val = (unsigned char *)&value_int32; }
      if (strcmp(deviceaction,"FLOAT") == 0)  { eis=9;  value_float = atof(devicevalue);   p_val = (unsigned char *)&value_float; }
      if (strcmp(deviceaction,"CHAR") == 0)   { eis=13; value_char = devicevalue[0];       p_val = (unsigned char *)&value_char; }
      if (strcmp(deviceaction,"STRING") == 0) { eis=15; string = devicevalue;              p_val = (unsigned char *)string; }

      sock_con2 = enmx_open(configuration.eibd_ip, "BlueHouse" );
      if( (data = malloc( enmx_EISsizeKNX[eis] )) == NULL ) {
          fprintf(logfile, "Out of memory\n" );
          exit( -4 );
      }
      if( enmx_value2eis( eis, (void *)p_val, data ) != 0 ) {
          fprintf(logfile, "Error in value conversion\n" );
          exit( -5 );
      }

      len = (eis != 15) ? enmx_EISsizeKNX[eis] : strlen( string );

      if( enmx_write( sock_con2, knxaddress, len, data ) != 0 ) {
          fprintf(logfile, "Unable to send command: %s\n", enmx_errormessage( sock_con ));
      //    exit( -7 );
      }
      free(data);
      enmx_close( sock_con2 );
   }

	 MQTTClient_freeMessage(&message);
	 MQTTClient_free(topicName);
   fflush(logfile);
	 return 1;
}

void connlost(void *context, char *cause) {
	 fprintf(logfile, "\nConnection lost\n");
	 fprintf(logfile, "     cause: %s\n", cause);
}


int main( int argc, char **argv ) {
    uint16_t                value_size;
    struct timeval          tv;
    struct tm               *ltime;
    uint16_t                buflen;
    unsigned char           *buf;
    CEMIFRAME               *cemiframe;
    int                     enmx_version;
    int                     c;
    int                     total = -1;
    int                     count = 0;
    int                     spaces = 1;
    char                    *user = NULL;
    char                    *configfile = NULL;
    char                    pwd[255];
    char                    *target;
    char                    *eis_types;
    int                     hour;
    int                     minute;
    int                     seconds;
    unsigned char           value[20];
    uint32_t                *p_int = 0;
    double                  *p_real;

    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    int                      rc;
    char                     payload[1024];
    char                     topic[1024];
    char                     buffer[255];
    struct device            *actual;
    char                     *subscription = strdup("iot-2/type/HomeGateway/id/HomePi3/cmd/+/fmt/+");

    logfile = stdout;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(logfile, NULL , _IONBF, 0);
    opterr = 0;
    while( ( c = getopt( argc, argv, "c:u:f:l:q" )) != -1 ) {
        switch( c ) {
            case 'c':
                total = atoi( optarg );
                break;
            case 'u':
                user = strdup( optarg );
                break;
            case 'f':
                configfile = strdup(optarg);
                break;
            case 'l':
                logfile = fopen (optarg, "a");
                if (logfile == NULL) {
                  fprintf(logfile, "Can not write to logfile %s\n", optarg );
                  logfile = stdout;
                }
                break;
            case 'q':
                quiet = 1;
                break;
            default:
                fprintf(logfile, "Invalid option: %c\n", c );
                Usage( argv[0] );
                exit( -1 );
        }
    }
    if( optind == argc ) {
        target = NULL;
    } else if( optind + 1 == argc ) {
        target = argv[optind];
    } else {
        Usage(argv[0] );
        exit( -1 );
    }
    configuration.devicelist = NULL;
    strcpy(configuration.solar_ip,"");
    strcpy(configuration.eibd_ip,target);
    read_configfile(configfile,&configuration);

    rc = MQTTClient_create(&client, configuration.address, configuration.clientid,MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (! quiet) {
       fprintf(logfile, "MQTTClient created with return code %i\n",rc);
       fprintf(logfile, "address %s\n",configuration.address );
       fprintf(logfile, "clientid %s\n",configuration.clientid );
    }
 	  conn_opts.keepAliveInterval = 3000;
 	  conn_opts.cleansession = 1;
 	  conn_opts.username = strdup(configuration.username);
 	  conn_opts.password = strdup(configuration.password);
    conn_opts.retryInterval = 1;
    if (! quiet) {
       fprintf(logfile, "username %s\n",conn_opts.username );
       fprintf(logfile, "password %s\n",conn_opts.password );
    }
	  MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)  {
 	  	  fprintf(logfile, "Failed to connect to MQTT, return code %d\n", rc);
 		    exit(-1);
 	  }

    MQTTClient_subscribe(client, subscription, 0);

    // catch signals for shutdown
    signal( SIGINT, Shutdown );
    signal( SIGTERM, Shutdown );

    // request monitoring connection
    if( (enmx_version = enmx_init()) != ENMX_VERSION_API ) {
        fprintf(logfile, "Incompatible eibnetmux API version (%d, expected %d)\n", enmx_version, ENMX_VERSION_API );
        exit( -8 );
    }
    sock_con = enmx_open( target, "BlueHouse" );
    if( sock_con < 0 ) {
        fprintf(logfile, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        exit( -2 );
    }

    // authenticate
    if( user != NULL ) {
        if( getpassword( pwd ) != 0 ) {
            fprintf(logfile, "Error reading password - cannot continue\n" );
            exit( -6 );
        }
        if( enmx_auth( sock_con, user, pwd ) != 0 ) {
            fprintf(logfile, "Authentication failure\n" );
            exit( -3 );
        }
    }
    if( quiet == 0 ) {
        fprintf(logfile, "Connection to eibnetmux %s established\n", enmx_gethost( sock_con ));
    }

    buf = malloc( 10 );
    buflen = 10;
    if( total != -1 ) {
        spaces = floor( log10( total )) +1;
    }

   fflush(logfile);

    while( total == -1 || count < total ) {
        buf = enmx_monitor( sock_con, 0xffff, buf, &buflen, &value_size );
        if( buf == NULL ) {
            switch( enmx_geterror( sock_con )) {
                case ENMX_E_COMMUNICATION:
                case ENMX_E_NO_CONNECTION:
                case ENMX_E_WRONG_USAGE:
                case ENMX_E_NO_MEMORY:
                    fprintf(logfile, "Error on write: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_INTERNAL:
                    fprintf(logfile, "Bad status returned\n" );
                    break;
                case ENMX_E_SERVER_ABORTED:
                    fprintf(logfile, "EOF reached: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_TIMEOUT:
                    fprintf(logfile, "No value received\n" );
                    break;
            }
        } else {
            count++;
            cemiframe = (CEMIFRAME *) buf;
            gettimeofday( &tv, NULL );
            ltime = localtime( &tv.tv_sec );
            fprintf(logfile,  "EIB: " );
            if( total != -1 ) {
                fprintf(logfile,  "%*d: ", spaces, count );
            }
            fprintf(logfile, "%04d/%02d/%02d %02d:%02d:%02d:%03d - ",
                       ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday,
                       ltime->tm_hour, ltime->tm_min, ltime->tm_sec, (uint32_t)tv.tv_usec / 1000 );
            fprintf(logfile,  "%8s  ", knx_physical( cemiframe->saddr ));
            if( cemiframe->code == L_DATA_REQ ) {
                fprintf(logfile,  "REQ " );
            } else if( cemiframe->code == L_DATA_CON ) {
                fprintf(logfile,  "CON " );
            } else if( cemiframe->code == L_DATA_IND ) {
                fprintf(logfile,  "IND " );
            } else if( cemiframe->code == L_BUSMON_IND ) {
                fprintf(logfile,  "MON " );
            } else {
                fprintf(logfile,  " %02x ", cemiframe->code );
            }
            if( cemiframe->ctrl & EIB_CTRL_PRIO_LOW ) {
                fprintf(logfile,  "low" );
            } else if( cemiframe->ctrl & EIB_CTRL_PRIO_HIGH ) {
                    fprintf(logfile,  "hgh" );
            } else if( cemiframe->ctrl & EIB_CTRL_PRIO_SYSTEM ) {
                    fprintf(logfile,  "sys" );
            } else if( cemiframe->ctrl & EIB_CTRL_PRIO_ALARM ) {
                    fprintf(logfile,  "alm" );
            }
            if( cemiframe->ctrl & EIB_CTRL_REPEAT ) {
                fprintf(logfile,  " r" );
            } else {
                fprintf(logfile,  "  " );
            }
            if( cemiframe->ctrl & EIB_CTRL_ACK ) {
                fprintf(logfile,  "k " );
            } else {
                fprintf(logfile,  "  " );
            }
            if( cemiframe->apci & A_WRITE_VALUE_REQ ) {
                fprintf(logfile,  "W " );
            } else if( cemiframe->apci & A_RESPONSE_VALUE_REQ ) {
                fprintf(logfile,  "A " );
            } else {
                fprintf(logfile,  "R " );
            }
            fprintf(logfile,  "%8s", (cemiframe->ntwrk & EIB_DAF_GROUP) ? knx_group( cemiframe->daddr ) : knx_physical( cemiframe->daddr ));
            if( cemiframe->apci & (A_WRITE_VALUE_REQ | A_RESPONSE_VALUE_REQ) ) {
                fprintf(logfile,  " : " );
                p_int = (uint32_t *)value;
                p_real = (double *)value;
                switch( cemiframe->length ) {
                    case 1:     // EIS 1, 2, 7, 8
                        enmx_frame2value( 1, cemiframe, value );
                        fprintf(logfile, "%s | ", (*p_int == 0) ? "off" : "on" );
                        sprintf(buffer,"%s",(*p_int == 0) ? "0" : "1" );
                        enmx_frame2value( 2, cemiframe, value );
                        fprintf(logfile,  "%d | ", *p_int );
                        enmx_frame2value( 7, cemiframe, value );
                        fprintf(logfile,  "%d | ", *p_int );
                        enmx_frame2value( 8, cemiframe, value );
                        fprintf(logfile,  "%d", *p_int );
                        eis_types = "1, 2, 7, 8";
                        break;
                    case 2:     // 6, 13, 14
                        enmx_frame2value( 6, cemiframe, value );
                        fprintf(logfile,  "%d%% | %d", *p_int * 100 / 255, *p_int );
                        sprintf(buffer,"%d%%", *p_int * 100 / 255);
                        enmx_frame2value( 13, cemiframe, value );
                        if( *p_int >=  0x20 && *p_int < 0x7f ) {
                            fprintf(logfile,  " | %c", *p_int );
                            eis_types = "6, 14, 13";
                        } else {
                            eis_types = "6, 14";
                        }
                        break;
                    case 3:     // 5, 10
                        enmx_frame2value( 5, cemiframe, value );
                        fprintf(logfile,  "%.2f | ", *p_real );
                        sprintf(buffer,"%.2f", *p_real );
                        enmx_frame2value( 10, cemiframe, value );
                        fprintf(logfile,  "%d", *p_int );
                        eis_types = "5, 10";
                        break;
                    case 4:     // 3, 4
                        enmx_frame2value( 3, cemiframe, value );
                        seconds = *p_int;
                        hour = seconds / 3600;
                        seconds %= 3600;
                        minute = seconds / 60;
                        seconds %= 60;
                        fprintf(logfile,  "%02d:%02d:%02d | ", hour, minute, seconds );
                        sprintf(buffer, "%02d:%02d:%02d", hour, minute, seconds );
                        enmx_frame2value( 4, cemiframe, value );
                        ltime = localtime( (time_t *)p_int );
                        if( ltime != NULL ) {
                            fprintf(logfile,  "%04d/%02d/%02d", ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday );
                        } else {
                            fprintf(logfile,  "inval date" );
                        }
                        eis_types = "3, 4";
                        break;
                    case 5:     // 9, 11, 12
                        enmx_frame2value( 11, cemiframe, value );
                        fprintf(logfile, "%d | ", *p_int );
                        sprintf(buffer, "%d", *p_int );
                        enmx_frame2value( 9, cemiframe, value );
                        fprintf(logfile,  "%.2f", *p_real );
                        enmx_frame2value( 12, cemiframe, value );
                        fprintf(logfile,  "12: <->" );
                        eis_types = "9, 11, 12";
                        break;
                    default:    // 15
                        // fprintf(logfile,  "%s", string );
                        eis_types = "15";
                        break;
                }
                if( cemiframe->length == 1 ) {
                    fprintf(logfile,  " (%s", hexdump( &cemiframe->apci, 1, 1 ));
                } else {
                    fprintf(logfile,  " (%s", hexdump( (unsigned char *)(&cemiframe->apci) +1, cemiframe->length -1, 1 ));
                }
                fprintf(logfile,  " - eis types: %s)", eis_types );
            }
            fprintf(logfile,  "\n" );

            // search device in the list of devices
            actual = configuration.devicelist;
            char knxaddres [16];
            strcpy(knxaddres,knx_group(cemiframe->daddr));
            while ((strcmp(actual->knx,knxaddres) != 0) && (actual->next)){
                actual = actual->next;
            }

            // if device is found
            if(strcmp(actual->knx,knxaddres) == 0) {
            strcpy(topic,"iot-2/type/");
            strcat(topic,actual->event);
            strcat(topic,"/id/");
            strcat(topic,actual->name);
            strcat(topic,"/evt/");
            strcat(topic,actual->type);
            strcat(topic,"/fmt/json");
            // #define TOPIC       "iot-2/type/Temperature/id/Boiler/evt/Measurement/fmt/json"
            strcpy(payload,"{\"d\":{\"value\":\"");
            strcat(payload,buffer);
            strcat(payload,"\",\"date\":\"");
            sprintf(buffer,"%04d/%02d/%02d",ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday);
            strcat(payload,buffer);
            strcat(payload,"\",\"time\":\"");
            sprintf(buffer,"%02d:%02d:%02d",ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
            strcat(payload,buffer);
            strcat(payload,"\"}}");
            // #define PAYLOAD     "{\"d\":{\"value\":\"42.00\",\"date\":\"2016-07-19\",\"time\":\"15:55:29\"}}"
            if (! quiet) {
              fprintf(logfile,"Published topic: %s\n",topic);
              fprintf(logfile,"Published payload: %s\n",payload);
            }
            pubmsg.payload = payload;
          	pubmsg.payloadlen = strlen(payload);
         	  pubmsg.qos = configuration.qos;
         	  pubmsg.retained = 0;
         //	  deliveredtoken = 0;

         	  rc = MQTTClient_publishMessage(client, topic, &pubmsg, &token);
            if (rc) {
                fprintf(logfile, "Published to MQTT, return code %d\n", rc);
                sleep(1);
                if (MQTTClient_isConnected(client) == 0) {
                  fprintf(logfile, "Reconnecting MQTT Client\n");
                  if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)  {
          	  	    fprintf(logfile, "Failed to connect to MQTT, return code %d\n", rc);
          		      exit(-1);
          	      }
                  MQTTClient_subscribe(client, subscription, 0);
                }
                rc = MQTTClient_publishMessage(client, topic, &pubmsg, &token);
                fprintf(logfile, "Retry published to MQTT and return code %d\n", rc);
            }
}
fflush(logfile);
        }
    }
    return( 0 );
}


/*
 * Return representation of physical device KNX address as string
 */
static char *knx_physical( uint16_t phy_addr ) {
        static char     textual[64];
        int             area;
        int             line;
        int             device;

        phy_addr = ntohs( phy_addr );

        area = (phy_addr & 0xf000) >> 12;
        line = (phy_addr & 0x0f00) >> 8;
        device = phy_addr & 0x00ff;

        sprintf( textual, "%d.%d.%d", area, line, device );
        return( textual );
}


/*
 * Return representation of logical KNX group address as string
 */
static char *knx_group( uint16_t grp_addr ) {
        static char     textual[64];
        int             top;
        int             sub;
        int             group;

        grp_addr = ntohs( grp_addr );

        top = (grp_addr & 0x7800) >> 11;
        sub = (grp_addr & 0x0700) >> 8;
        group = grp_addr & 0x00ff;
        sprintf( textual, "%d/%d/%d", top, sub, group );
        return( textual );
}
