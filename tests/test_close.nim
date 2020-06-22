import news, asyncdispatch, asynchttpserver, asyncnet

proc cb(req: Request): Future[void] {.async.} =
  echo "cb ", req
  var ws = await newWebsocket(req)
  await ws.send("Welcome to simple echo server")
  while ws.readyState == Open:
    let packet = await ws.receivePacket()
    await ws.send(packet)
    await ws.shutdown()
  await req.respond(Http200, "Hello World")


proc sendMsg() {.async.} =
  var ws = await newWebSocket("ws://localhost:9001")
  await ws.send("hi")
  while ws.readyState == Open:
    let str = await ws.receiveString()
    echo "received ", str
  ws.close()


proc sendClose() {.async.} =
  var ws = await newWebSocket("ws://echo.websocket.org:80")
  await ws.sendPing()
  let pong = await ws.receivePacket()
  assert(pong.kind == Pong)
  await ws.shutdown()
  let close = await ws.receivePacket()
  assert(close.kind == Close)
  ws.close()

proc run() {.async.} =
  var server = newAsyncHttpServer()
  asyncCheck server.serve(Port(9001), cb)
  await sendMsg()
  await sendClose()
  server.close()

waitFor run()