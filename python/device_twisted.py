#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Simple load test tool. Code is commented and modifications are needed for
# custom needs (like data to be sent, server connection IP, etc..). Twisted for
# Python is needed. Install it via(Ubuntu):
#
#   sudo apt-get install python-twisted
#
# Example:
# Connect with 10 devices, each sending 5 events every 1 second for the
# duration of 10 seconds. Note that 'device' is a single TCP connection.
#
#   ./device_twisted.py -d 10 -e 5 -t 1 -s 10
#
#           or 
#
#   ./device_twisted.py --device 10 -event 5 --interval 1 --duration 10
#
# For questions or improvings sent pull request via:
# https://github.com/farslan/snippets

import sys
import argparse
from twisted.internet import reactor, protocol, task

class MyProtocol(protocol.Protocol):
    def connectionMade(self):
        self.messageCount = 0
        self.name = "Client %d connected"  % self.factory.n
        print self.name
        self.factory.clients.append(self)

    def dataReceived(self, data):
        print "Server said:", data

    def connectionLost(self, reason):
        self.factory.clients.remove(self)
        print "Connection lost"

class MyFactory(protocol.ClientFactory):
    protocol = MyProtocol

    def __init__(self, num, events, interval, duration):
        self.clients = []
        self.n = num #Used by protocol (see connectionMade)
        self.event_number = int(events)
        self.lc = task.LoopingCall(self.sent_event)
        self.lc.start(int(interval), now=True)

        # If duration is "0", then assume we dont want to stop the test
        if int(duration):
            print "Test duration is: ", duration
            reactor.callLater(int(duration), self.lc.stop)
        else:
            print "Test duration is infinite"

    def sent_event(self):
        """Customize the data to be sent, here final_data should be changed"""

        final_data = "I love Coffee! "
        for client in self.clients:
            for e in range(self.event_number):
                # Just append a number to our example string.
                final_data += e

                # Goodbye little packet...
                client.transport.write(final_data)
                print "Sent data: ", final_data

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed - goodbye!"
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        reactor.stop()

    def startedConnecting(self, connector):
        print 'Started to connect.'

def main(args):
    #Debug arguments
    #print args

    # To create multiple client connections just create new connectTCP()
    # method. We could use a single factory, however each connection has a
    # different device_id (the "i" in the for loop is used for it)
    for i in range(int(args.devices)):
        myfactory = MyFactory(i, args.event_number, args.time_interval, args.test_duration)
        reactor.connectTCP("localhost", 8000, myfactory)

    # .. start the machine!
    reactor.run()

def argument():
    parser = argparse.ArgumentParser(description='Device Load Test Tool',
                                     prog='device_twisted',
                                     usage='%(prog)s [options]')

    parser.add_argument('-v', '--version',
                         action='version',
                         version='%(prog)s 0.0.1')

    parser.add_argument('-d', '--devices',
                         action='store',
                         dest='devices',
                         default='1',
                         help="Number of devices to be connected (default is 1 device)")

    parser.add_argument('-e', '--events',
                         action='store',
                         dest='event_number',
                         default='1',
                         help="Number of events each device will sent (default is 1 event)")

    parser.add_argument('-i', '--interval',
                         action='store',
                         dest='time_interval',
                         default='1',
                         help="Time interval between each event (default is 1 second)")

    parser.add_argument('-t', '--duration',
                         action='store',
                         dest='test_duration',
                         default='0',
                         help="Configure the test duration (default is infinite)")

    return parser.parse_args()

if __name__ == '__main__':
    args = argument()
    sys.exit(main(args))
