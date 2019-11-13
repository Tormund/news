import news, asyncdispatch, asynchttpserver

var continueTest = true

{.push hint[XDeclaredButNotUsed]: off.}

proc socketDied() =
  echo "Socket died"
  continueTest = false

proc establishConnectionAndListen() {.async.} =
    var ws = await newWebSocket("ws://echo.websocket.org")
    ws.enableAutoCloseWithParameters(onAutoClose = socketDied,
                                     pingInterval = 1000, maxMissedReplies = 5)
    await ws.send("hi")
    let hiPacket = await ws.receivePacket()
    if $hiPacket == "hi":
      echo "Connection established"
    while true:
      try:
        let anotherPacket = await ws.receivePacket()
        echo "Socket is still alive"
      except WebSocketClosedError:
        socketDied()

asyncCheck sleepAsync(1000000) # just to keep dispatcher's queue non-empty
asyncCheck establishConnectionAndListen()
while continueTest:
  poll()
echo "Finished"
