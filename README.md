# bluehome_eib
Bluehome EIB interface

files:
  bluehome_eib.c is the main program
  bluehome.conf is the configuration file required for the main program
  
required prior installed:
  paho-mqtt3c : MQTT client, see http://www.eclipse.org/paho/
  eibnetmux : EIB net interface, see http://eibnetmux.sourceforge.net/
  
compile:
  gcc bluehome_eib.c  -L /usr/local/lib -lpaho-mqtt3c -lcurl -lpthread  -leibnetmux -lm -o bluehome_eib

runtime parameters:
  required parameter is IP address of the eibnetmux
  -u username : required for EIB
  -c count    : stop after count number of EIB requests, detault is endless
  -f filename : name of configuration file, default is 'bluehome.conf'
  -l filename : name of logfile, default is on screen
  -q          : no verbose output
 
run:
  sudo ./bluehome_eib -l bluehome_eib.log 127.0.0.1
