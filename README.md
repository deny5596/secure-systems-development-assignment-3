# secure-systems-development-assignment-3
This assignment is based on getting real-time blockchain data from blockchain nodes.

## There are two primary files for this assignment
### bitcoin-network-data.js
### bitcoin-data-through-api.js

# File Description
## bitcoin-network-data.js
### This file contains code which could be run directly using the following command
``` node bitcoin-network-data.js ```
### The code in this file connects to the available bitcoin servers using a pre-defined list of DNS and tries to establish a connection to all of the IP addresses associated to each of the DNS servers. If the connection is made successfully, we send the version payload ahead to the node to communicate with the node.
### The output is command-line based.
## Note: Please install the packages using the below command before executing the above script.
``` npm install net crypto long dns ```
### I am using node version = v16.13.1.

## bitcoin-data-through-api.js
### This file could be run directly using the following command
``` node bitcoin-data-through-api.js ```
### This code is an alternative solution for getting real-time data.
### In this code, I use the blockchain API in order to pull the latest block which was mined and then show it's details in the console.
### The output is command-line based.
## Note: Please install the packages using the below command before executing the above script.
``` npm install axios crypto ```
### I am using node version = v16.13.1.
