import news, asyncdispatch, asynchttpserver

var server = newAsyncHttpServer()
proc cb(req: Request) {.async.} =
  echo "cb ", req
  if req.url.path == "/ws":
    var ws = await newWebsocket(req)
    await ws.send("Welcome to simple echo server")
    while ws.readyState == Open:
      let packet = await ws.receivePacket()
      await ws.send(packet)
  await req.respond(Http200, "Hello World")

asyncCheck server.serve(Port(9001), cb)

proc sendMsg() {.async.} =
    var ws = await newWebSocket("ws://localhost:9001/ws")
    await ws.send("hi")
    while ws.readyState == Open:
        let str = await ws.receiveString()
        echo "received ", str

asyncCheck sendMsg()
runForever()
