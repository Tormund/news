import news, asyncdispatch, asynchttpserver, net

# works with simple echo server from https://github.com/dpallot/simple-websocket-server
# protSSLv23 is compatible with SimpleExampleServer.py --ver 2
# protTLSv1 is compatible with SimpleExampleServer.py --ver 3

# this test needs to be compiled with -d:ssl

proc sendMsg() {.async.} =
    var ws = await newWebSocket("wss://localhost/")
    await ws.send("hi")
    while ws.readyState == Open:
        let packet = await ws.receivePacket()
        echo "received ", packet

asyncCheck sendMsg()
runForever()
