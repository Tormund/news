import news, asyncdispatch, asynchttpserver

var continueTest = true

proc establishConnectionAndListen() {.async.} =
    var ws = await newWebSocket("ws://echo.websocket.org:80")
    await ws.sendPing()
    let pong = await ws.receivePacket()
    assert(pong.kind == Pong)
    echo "Got pong"
    continueTest = false

asyncCheck sleepAsync(100000) # just to keep dispatcher's queue non-empty
asyncCheck establishConnectionAndListen()
while continueTest:
  poll()
echo "Finished"
