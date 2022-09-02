import std/[
  base64, deques, httpcore, nativesockets, net, oids, random, sha1, streams,
  strformat, strtabs, strutils, uri]

when not declaredInScope(newsUseChronos):
  # Currently chronos is second class citizen. To use this library in chronos-based
  # projects, include this file as follows:
  # const newsUseChronos = true
  # include news
  const newsUseChronos = false

type
  WebSocketError* = object of CatchableError
  WebSocketClosedError* = object of WebSocketError

when newsUseChronos:
  import chronos, chronos/streams/[asyncstream, tlsstream]

  type Transport = object
    transp: StreamTransport
    reader: AsyncStreamReader
    writer: AsyncStreamWriter

  proc send(s: Transport, data: string) {.async.} =
    # echo "sending: ", data.len
    if s.writer == nil:
      raise newException(WebSocketClosedError, "WebSocket is closed")
    await s.writer.write(data)

  proc recv(s: Transport, len: int): Future[string] {.async.} =
    var res = newString(len)
    if len != 0:
      # echo "receiving: ", len
      if s.reader == nil:
        raise newException(WebSocketClosedError, "WebSocket is closed")
      await s.reader.readExactly(addr res[0], len)
    return res

  proc isClosed(transp: Transport): bool {.inline.} =
    (transp.reader == nil and transp.writer == nil) or
    (transp.reader.closed or transp.writer.closed)

  proc close(transp: var Transport) =
    if transp.reader != nil:
      transp.reader.close()
      transp.reader = nil
    if transp.writer != nil:
      transp.writer.close()
      transp.writer = nil
    transp.transp.close()
    transp.transp = nil

  proc closeWait(transp: var Transport): Future[void] =
    if transp.reader != nil:
      transp.reader.close()
      transp.reader = nil
    if transp.writer != nil:
      transp.writer.close()
      transp.writer = nil
    let t = transp.transp
    transp.transp = nil
    t.closeWait()

else:
  import std/[asyncdispatch, asynchttpserver, asyncnet]
  type Transport = AsyncSocket

const CRLF = "\c\l"
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type
  Opcode* = enum
    ## 4 bits. Defines the interpretation of the "Payload data".
    Cont = 0x0 ## denotes a continuation frame
    Text = 0x1 ## denotes a text frame
    Binary = 0x2 ## denotes a binary frame
    # 3-7 are reserved for further non-control frames
    Close = 0x8 ## denotes a connection close
    Ping = 0x9 ## denotes a ping
    Pong = 0xa ## denotes a pong
    # B-F are reserved for further control frames

  #[
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-------+-+-------------+-------------------------------+
  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
  | |1|2|3|       |K|             |                               |
  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
  |     Extended payload length continued, if payload len == 127  |
  + - - - - - - - - - - - - - - - +-------------------------------+
  |                               |Masking-key, if MASK set to 1  |
  +-------------------------------+-------------------------------+
  | Masking-key (continued)       |          Payload Data         |
  +-------------------------------- - - - - - - - - - - - - - - - +
  :                     Payload Data continued ...                :
  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
  |                     Payload Data continued ...                |
  +---------------------------------------------------------------+
  ]#
  Frame* = tuple
    fin: bool ## Indicates that this is the final fragment in a message.
    rsv1: bool ## MUST be 0 unless negotiated that defines meanings
    rsv2: bool
    rsv3: bool
    opcode: Opcode ## Defines the interpretation of the "Payload data".
    mask: bool ## Defines whether the "Payload data" is masked.
    data: string ## Payload data

  Packet* = object
    case kind*: Opcode
    of Text, Binary:
      data*: string
    else:
      discard

  ReadyState* = enum
    Connecting = 0 # The connection is not yet open.
    Open = 1 # The connection is open and ready to communicate.
    Closing = 2 # The connection is in the process of closing.
    Closed = 3 # The connection is closed or couldn't be opened.

  WebSocket* = ref object
    transp*: Transport
    version*: int
    key*: string
    protocol*: string
    readyState*: ReadyState
    maskFrames*: bool
    sendFut: Future[void]
    sendQueue: Deque[tuple[text: string, opcode: Opcode, fut: Future[void]]]

template `[]`(value: uint8, index: int): bool =
  ## get bits from uint8, uint8[2] gets 2nd bit
  (value and (1 shl (7 - index))) != 0


proc nibbleFromChar(c: char): int =
  ## converts hex chars like `0` to 0 and `F` to 15
  case c:
    of '0'..'9': (ord(c) - ord('0'))
    of 'a'..'f': (ord(c) - ord('a') + 10)
    of 'A'..'F': (ord(c) - ord('A') + 10)
    else: 255


proc nibbleToChar(value: int): char =
  ## converts number like 0 to `0` and 15 to `fg`
  case value:
    of 0..9: char(value + ord('0'))
    else: char(value + ord('a') - 10)


proc decodeBase16*(str: string): string =
  ## base16 decode a string
  result = newString(str.len div 2)
  for i in 0 ..< result.len:
    result[i] = chr(
      (nibbleFromChar(str[2 * i]) shl 4) or
      nibbleFromChar(str[2 * i + 1]))


proc encodeBase16*(str: string): string =
  ## base16 encode a string
  result = newString(str.len * 2)
  for i, c in str:
    result[i * 2] = nibbleToChar(ord(c) shr 4)
    result[i * 2 + 1] = nibbleToChar(ord(c) and 0x0f)


proc genMaskKey*(): array[4, char] =
  ## Generates a random key of 4 random chars
  [char(rand(255)), char(rand(255)), char(rand(255)), char(rand(255))]

when not defined(ssl):
  type SSLContext = ref object
var defaultSslContext {.threadvar.}: SSLContext

proc getDefaultSslContext(): SSLContext =
  when defined(ssl):
    if defaultSslContext.isNil:
      defaultSslContext = newContext(protVersion = protTLSv1, verifyMode = CVerifyNone)
      if defaultSslContext.isNil:
        raise newException(WebSocketError, "Unable to initialize SSL context.")
  result = defaultSslContext

proc close*(ws: WebSocket) =
  ## close the socket
  ws.readyState = Closed
  if not ws.transp.isClosed:
    ws.transp.close()

when newsUseChronos:
  proc closeWait*(ws: WebSocket) {.async.} =
    ## close the socket
    ws.readyState = Closed
    if not ws.transp.isClosed:
      await ws.transp.closeWait()

else:
  proc newWebSocket*(req: Request): Future[WebSocket] {.async.} =
    ## Creates a new socket from a request
    var ws = WebSocket()

    try:
      ws.version = parseInt(req.headers["sec-webSocket-version"])
      ws.key = req.headers["sec-webSocket-key"].strip()
      if req.headers.hasKey("sec-webSocket-protocol"):
        ws.protocol = req.headers["sec-webSocket-protocol"].strip()

      let sh = secureHash(ws.key & GUID)
      let acceptKey = base64.encode(decodeBase16($sh))

      var response = "HTTP/1.1 101 Web Socket Protocol Handshake" & CRLF
      response.add("Sec-WebSocket-Accept: " & acceptKey & CRLF)
      response.add("Connection: Upgrade" & CRLF)
      response.add("Upgrade: websocket" & CRLF)
      if ws.protocol.len > 0:
        response.add("Sec-WebSocket-Protocol: " & ws.protocol & CRLF)
      response.add CRLF

      ws.transp = req.client
      # await ws.transp.connect(uri.hostname, port)
      await ws.transp.send(response)
      ws.readyState = Open
    finally:
      if ws.readyState != Open:
        close(ws)

    return ws

proc validateServerResponse(resp, secKey: string): string =
  let respLines = resp.splitLines()
  block statusCode:
    const httpVersionStr = "HTTP/1.1 "
    let httpVersionPos = respLines[0].find(httpVersionStr)
    if httpVersionPos == -1:
      return "HTTP version not specified"
    let i = httpVersionPos + httpVersionStr.len
    if respLines[0].len <= i + 2:
      return "Request too short"
    let v = respLines[0][i .. i + 2]
    if v != "101":
      return respLines[0][i ..< respLines[0].len]

  var validatedHeaders: array[3, bool]
  for i in 1 ..< respLines.len:
    let h = parseHeader(respLines[i])
    if cmpIgnoreCase(h.key, "Upgrade") == 0:
      if cmpIgnoreCase(h.value[0].toLowerAscii, "websocket") != 0:
        return "Upgrade header is invalid"
      validatedHeaders[0] = true

    elif cmpIgnoreCase(h.key, "Connection") == 0:
      if cmpIgnoreCase(h.value[0], "upgrade") != 0:
        return "Connection header is invalid"
      validatedHeaders[1] = true

    elif cmpIgnoreCase(h.key, "Sec-WebSocket-Accept") == 0:
      let sh = decodeBase16($secureHash(secKey & GUID))
      if cmpIgnoreCase(h.value[0], base64.encode(sh)) != 0:
        return "Secret key invalid"
      validatedHeaders[2] = true

  if not validatedHeaders[0]: return "Missing Upgrade header"
  if not validatedHeaders[1]: return "Missing Connection header"
  if not validatedHeaders[2]: return "Missing Sec-WebSocket-Accept header"

proc newWebSocket*(url: string, headers: StringTableRef = nil,
                   sslContext: SSLContext = getDefaultSslContext()): Future[WebSocket] {.async.} =
  ## Creates a client
  var ws = WebSocket()

  try:
    let uri = parseUri(url)
    var port = Port(80)
    case uri.scheme
      of "wss":
        port = Port(443)
      of "ws":
        discard
      else:
        raise newException(WebSocketError, &"Scheme {uri.scheme} not supported yet.")
    if uri.port.len > 0:
      port = Port(parseInt(uri.port))

    when newsUseChronos:
      let tr = await connect(resolveTAddress(uri.hostname, port)[0])
      ws.transp.transp = tr
      ws.transp.reader = newAsyncStreamReader(tr)
      ws.transp.writer = newAsyncStreamWriter(tr)

      if uri.scheme == "wss":
        let s = newTLSClientAsyncStream(ws.transp.reader, ws.transp.writer, serverName = uri.hostname)
        ws.transp.reader = s.reader
        ws.transp.writer = s.writer

    else:
      ws.transp = newAsyncSocket()
      if uri.scheme == "wss":
        when defined(ssl):
          sslContext.wrapSocket(ws.transp)
        else:
          raise newException(WebSocketError, "SSL support is not available. Compile with -d:ssl to enable.")
      await ws.transp.connect(uri.hostname, port)

    var urlPath = uri.path
    if uri.query.len > 0:
      urlPath.add("?" & uri.query)
    if urlPath.len == 0:
      urlPath = "/"
    let
      secKey = ($genOid())[^16..^1]
      secKeyEncoded = encode(secKey)
    let requestLine = &"GET {urlPath} HTTP/1.1"
    let predefinedHeaders = [
      &"Host: {uri.hostname}:{$port}",
      "Connection: Upgrade",
      "Upgrade: websocket",
      "Sec-WebSocket-Version: 13",
      &"Sec-WebSocket-Key: {secKeyEncoded}"
    ]

    var customHeaders = ""
    if not headers.isNil:
      for k, v in headers:
        customHeaders &= &"{k}: {v}{CRLF}"
    var hello = requestLine & CRLF &
                customHeaders &
                predefinedHeaders.join(CRLF) &
                static(CRLF & CRLF)

    await ws.transp.send(hello)

    var output = ""
    while not output.endsWith(static(CRLF & CRLF)):
      output.add await ws.transp.recv(1)

    let error = validateServerResponse(output, secKeyEncoded)
    if error.len > 0:
      raise newException(WebSocketError, "WebSocket connection error: " & error)

    ws.readyState = Open
    ws.maskFrames = true
  finally:
    if ws.readyState != Open:
      close(ws)

  return ws

proc encodeFrame*(f: Frame): string =
  ## Encodes a frame into a string buffer
  ## See https://tools.ietf.org/html/rfc6455#section-5.2

  var ret = newStringStream()

  var b0 = (f.opcode.uint8 and 0x0f) # 0th byte: opcodes and flags
  if f.fin:
    b0 = b0 or 128u8

  ret.write(b0)

  # Payload length can be 7 bits, 7+16 bits, or 7+64 bits

  var b1 = 0u8 # 1st byte: playload len start and mask bit

  if f.data.len <= 125:
    b1 = f.data.len.uint8
  elif f.data.len > 125 and f.data.len <= 0xffff:
    b1 = 126u8
  else:
    b1 = 127u8

  if f.mask:
    b1 = b1 or (1 shl 7)

  ret.write(uint8 b1)

  # Only need more bytes if data len is 7+16 bits, or 7+64 bits
  if f.data.len > 125 and f.data.len <= 0xffff:
    # data len is 7+16 bits
    ret.write(htons(f.data.len.uint16))
  elif f.data.len > 0xffff:
    # data len is 7+64 bits
    var len = f.data.len
    ret.write char((len shr 56) and 255)
    ret.write char((len shr 48) and 255)
    ret.write char((len shr 40) and 255)
    ret.write char((len shr 32) and 255)
    ret.write char((len shr 24) and 255)
    ret.write char((len shr 16) and 255)
    ret.write char((len shr 8) and 255)
    ret.write char(len and 255)

  var data = f.data

  if f.mask:
    # if we need to maks it generate random mask key and mask the data
    let maskKey = genMaskKey()
    for i in 0..<data.len:
      data[i] = (data[i].uint8 xor maskKey[i mod 4].uint8).char
    # write mask key next
    ret.write(maskKey)

  # write the data
  ret.write(data)
  ret.setPosition(0)
  return ret.readAll()

proc doSend(ws: WebSocket, text: string, opcode: Opcode): Future[void] {.async.} =
  try:
    ## write data to WebSocket
    var frame = encodeFrame((
      fin: true,
      rsv1: false,
      rsv2: false,
      rsv3: false,
      opcode: opcode,
      mask: ws.maskFrames,
      data: text
    ))
    const maxSize = 1024*1024
    # send stuff in 1 megabyte chunks to prevent IOErrors
    # with really large packets
    var i = 0
    while i < frame.len:
      let data = frame[i ..< min(frame.len, i + maxSize)]
      if ws.transp.isClosed:
        raise newException(WebSocketClosedError, "Socket closed")
      await ws.transp.send(data)
      i += maxSize
      await sleepAsync(1)
  except CatchableError as e:
    if ws.transp.isClosed:
      ws.readyState = Closed
      raise newException(WebSocketClosedError, "Socket closed")
    else:
      raise newException(WebSocketError,
                         &"Could not send packet because of [{e.name}]: {e.msg}")

proc continueSending(ws: WebSocket) =
  if ws.sendQueue.len <= 0:
    return

  let
    task = ws.sendQueue.popFirst()
    fut = task.fut
    sendFut = ws.doSend(task.text, task.opcode)
  ws.sendFut = sendFut

  proc doHandleSent() =
    if ws.sendFut.failed:
      fut.fail(ws.sendFut.error)
    else:
      fut.complete()
    ws.sendFut = nil
    ws.continueSending()

  when newsUseChronos:
    proc handleSent(future: pointer) =
      doHandleSent()
  else:
    proc handleSent() =
      doHandleSent()

  ws.sendFut.addCallback(handleSent)

proc send*(ws: WebSocket, text: string, opcode = Opcode.Text): Future[void] =
  if ws.sendFut != nil:
    let fut = newFuture[void]("send")
    ws.sendQueue.addLast (text: text, opcode: opcode, fut: fut)
    return fut

  ws.sendFut = ws.doSend(text, opcode)

  proc doHandleSent() =
    ws.sendFut = nil
    ws.continueSending()

  when newsUseChronos:
    proc handleSent(future: pointer) =
      doHandleSent()
  else:
    proc handleSent() =
      doHandleSent()

  ws.sendFut.addCallback(handleSent)
  ws.sendFut

proc send*(ws: WebSocket, packet: Packet): Future[void] =
  if packet.kind == Text or packet.kind == Binary:
    return ws.send(packet.data, packet.kind)
  else:
    return ws.send("", packet.kind)

proc recvFrame(ws: WebSocket): Future[Frame] {.async.} =
  ## Gets a frame from the WebSocket
  ## See https://tools.ietf.org/html/rfc6455#section-5.2

  if ws.transp.isClosed:
    ws.readyState = Closed
    return result

  # grab the header
  let header = try:
    await ws.transp.recv(2)
  except CatchableError as err:
    close ws
    raise err

  if header.len != 2:
    ws.readyState = Closed
    close ws
    raise newException(WebSocketClosedError, "socket closed")

  let b0 = header[0].uint8
  let b1 = header[1].uint8

  # read the flags and fin from the header
  result.fin  = b0[0]
  result.rsv1 = b0[1]
  result.rsv2 = b0[2]
  result.rsv3 = b0[3]

  let opcodeVal = b0 and 0x0f
  if opcodeVal > high(Opcode).uint8:
    raise newException(WebSocketError, "Server did not respond with a valid WebSocket frame")
  result.opcode = Opcode(opcodeVal)

  # if any of the rsv are set close the socket
  if result.rsv1 or result.rsv2 or result.rsv3:
    close ws
    raise newException(WebSocketError, "WebSocket Potocol missmatch")

  # Payload length can be 7 bits, 7+16 bits, or 7+64 bits
  var finalLen: uint = 0

  let headerLen = uint(b1 and 0x7f)
  if headerLen == 0x7e:
    # length must be 7+16 bits
    var lenstr = try:
      await ws.transp.recv(2)
    except CatchableError as err:
      close ws
      raise err

    if lenstr.len != 2:
      close ws
      raise newException(WebSocketClosedError, "Socket closed")

    finalLen = cast[ptr uint16](lenstr[0].addr)[].htons

  elif headerLen == 0x7f:
    # length must be 7+64 bits
    var lenstr = try:
      await ws.transp.recv(8)
    except CatchableError as err:
      close ws
      raise err

    if lenstr.len != 8:
      close ws
      raise newException(WebSocketClosedError, "Socket closed")

    finalLen = cast[ptr uint32](lenstr[4].addr)[].htonl

  else:
    # length must be 7 bits
    finalLen = headerLen

  # do we need to apply mask?
  result.mask = (b1 and 0x80) == 0x80
  var maskKey = ""
  if result.mask:
    # read mask
    maskKey = try:
      await ws.transp.recv(4)
    except CatchableError as err:
      close ws
      raise err

    if maskKey.len != 4:
      close ws
      raise newException(WebSocketClosedError, "Socket closed")

  # read the data
  result.data = try:
    await ws.transp.recv(int finalLen)
  except CatchableError as err:
    close ws
    raise err

  if result.data.len != int finalLen:
    close ws
    raise newException(WebSocketClosedError, "Socket closed")

  if result.mask:
    # apply mask if we need too
    for i in 0 ..< result.data.len:
      result.data[i] = (result.data[i].uint8 xor maskKey[i mod 4].uint8).char

proc sendPing*(ws: WebSocket): Future[void] {.async.} =
  await ws.send("", Opcode.Ping)

proc sendPong(ws: WebSocket): Future[void] {.async.} =
  await ws.send("", Opcode.Pong)

proc sendClose(ws: WebSocket): Future[void] {.async.} =
  await ws.send("", Opcode.Close)

proc shutdown*(ws: WebSocket): Future[void] {.async.} =
  ## close the socket
  ws.readyState = Closing
  await ws.sendClose

proc receivePacket*(ws: WebSocket): Future[Packet] {.async.} =
  try:
    ## wait for a string packet to come
    var frame = await ws.recvFrame()
    result = Packet(kind: frame.opcode)
    if frame.opcode == Text or frame.opcode == Binary:
      result.data = frame.data
      # If there are more parts read and wait for them
      while frame.fin != true:
        frame = await ws.recvFrame()
        if frame.opcode != Cont:
          close ws
          raise newException(WebSocketError, "Socket did not get continue frame")
        result.data.add frame.data
      return

    if frame.opcode == Ping:
      await ws.sendPong()

    elif frame.opcode == Pong:
      return

    elif frame.opcode == Close:
      if ws.readyState != Closing:
        await ws.sendClose()
      ws.readyState = Closed
      if not ws.transp.isClosed:
        ws.transp.close()

  except WebSocketError as e:
    raise e
  except CatchableError as e:
    if ws.transp.isClosed:
      ws.readyState = Closed
      result = Packet(kind: Close)
    else:
      raise newException(WebSocketError,
                         &"Could not receive packet because of [{e.name}]: {e.msg}")

proc receiveString*(ws: WebSocket): Future[string] {.async.} =
  var receivedString = false
  while not (receivedString or ws.readyState == Closed):
    let packet = await ws.receivePacket()
    case packet.kind
    of Text, Binary:
      receivedString = true
      result = packet.data
    of Close:
      result = ""
    else:
      discard
