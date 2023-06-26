# README #

This repository summarize the content and has all the codes related to the Wireless Safety Layer from ADACORSA project.

### What is this repository for? ###

* Quick summary of what is being developed
* Source codes for WSSL Sender and WSSL Receiver
* Quick tutorial to install and run WSSL

### What is WSSL?

**Wireless Safety and Security Layer (WSSL)** consists of an additional layer to the adopted communication system, implementing a detection process for relevant communication issues, establishing a safe and secure connection between each WSSL end-point, and providing an extra level of confidence to the CPS devices. Furthermore, the WSSL implementation seeks to increase trust between the Sender and Receiver since communication failures or malicious interactions can have critical consequences depending on the scenario. It focuses on open communication systems where the transmission is unsafe. The basic implementation is agnostic, being available for generic use cases independently of the communication protocol.

WSSL is part of the project Airborne data collection on resilient system architectures (ADACORSA) within CISTER Research Centre. To know more, visit [ADACORSA](http://cister-labs.pt/projects/adacorsa/).

## How do I get set up? ##

* Environment configured with C++ compilators (g++);
* Install dependencies and third-party libraries;
* Build the library using Make and CMake;

### Make and CMake

To install Make and CMake in Ubuntu OS use the following commands:

> sudo apt update
> make -version

If make is not installed in Ubuntu, then install it:
> sudo apt install make 

If nothing works, try this:
> sudo apt install build-essential

### VORTEX Library & WSSL

Go to the location of WSSL_Security&Safety and do the following:

**To include:**
 - Requires ```sodium``` library; Can be installed via ```apt install libsodium-dev``` or similar installers, or through local building: https://libsodium.gitbook.io/doc/installation

 - Include on your projects build files CryptoLib and sodium to the CMakeList.txt file:
   - cmake: ```target_link_libraries(<project name> CryptoLib sodium)```

**To build:**
> ```cmake -Bbuild -H. && cmake --build build```

### MQTT LIB Mosquitto.h

First install libmosquitto:

> sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
> sudo apt-get update
> sudo apt-get install libmosquitto-dev

Then, install mosquitto clients:

> sudo apt-get install mosquitto
> sudo apt-get install mosquitto-clients
> sudo apt clean

Include the library in your code:

>#include <mosquitto.h>

change the listener port from 1883 to 1885 and restart the service:

> sudo nano /etc/mosquitto/conf.d/custom.conf

Port to use for the default listener
> listener 1885

Allow anonymous authentication
> allow_anonymous true

Restart the service broker:
> service mosquitto restart

## References 

https://mosquitto.org/download/

http://www.steves-internet-guide.com/install-mosquitto-linux/

https://linuxhint.com/install-make-ubuntu/

https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures

