# Mobility-Improvement-using-SDN
This project uses the capabilities of Software Defined Networks (SDN) to improve the performance of both TCP and non-TCP flows in mobility scenarios. It improves the throughput of the connection in case of TCP by handing the losses caused due to frequent disconnection due to mobility and corruption errors due to wireless nature. 

## What it does

1. In this approach, we try to buffer all the packets coming to and from the mobile node in the controller.
2. When the mobile node disconnects and later reconnects to an AP, the buffered packets are then sent to the node.
3. Upon getting ack, these packets are deleted from the controller

## How to Run -

1. Install Mininet-Wifi and RYU or download its VM. (More info here https://github.com/intrig-unicamp/mininet-wifi)
2. Clone this repo
3. Run the contoller and topology scripts in different terminals
