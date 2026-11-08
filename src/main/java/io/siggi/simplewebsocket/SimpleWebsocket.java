package io.siggi.simplewebsocket;

import io.siggi.http.HTTPRequest;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class SimpleWebsocket implements Closeable {
    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;

    private final boolean isClient;
    private final SecureRandom random;

    /**
     * Close status code sent when an incoming frame or message exceeds the configured limits.
     */
    public static final int CLOSE_MESSAGE_TOO_BIG = 1009;

    /**
     * Close status code sent when the peer violates the WebSocket protocol.
     */
    public static final int CLOSE_PROTOCOL_ERROR = 1002;

    /**
     * Close status code sent when a text message is not valid UTF-8.
     */
    public static final int CLOSE_INVALID_DATA = 1007;

    /**
     * The largest frame or message size that can be received, limited by the maximum size of a Java array.
     */
    public static final long MAX_SIZE_LIMIT = Integer.MAX_VALUE - 8;

    private volatile long maxPayloadLength = 16384;
    private volatile long maxMessageSize = 1048576;
    private long pingFrequency = 5000L;
    private volatile boolean nonBlockingMode = false;
    private volatile boolean handleIncomingPingsAutomatically = true;

    /**
     * Held while writing a frame. Never acquire sendQueueLock while holding this.
     */
    private final ReentrantLock writeLock = new ReentrantLock();
    /**
     * A close frame has been written, nothing more may be written. Guarded by writeLock.
     */
    private boolean sentCloseFrame = false;

    /**
     * Guards the send queue and the close flags. Never held while doing I/O.
     */
    private final Object sendQueueLock = new Object();
    private volatile boolean closed = false;
    /**
     * A close frame has been queued, no more messages are accepted. Guarded by sendQueueLock.
     */
    private boolean closeQueued = false;
    private final List<WebSocketMessage> sendQueue = new LinkedList<>();
    /**
     * Total payload bytes in sendQueue. Guarded by sendQueueLock.
     */
    private long queuedBytes = 0L;
    private volatile long maxQueuedBytes = 16L * 1024L * 1024L;

    /**
     * How long close() waits to write the close frame before forcibly closing the socket.
     */
    private static final long CLOSE_TIMEOUT = 5000L;
    /**
     * How long to discard input after failing the connection, before closing the socket.
     */
    private static final long DISCARD_INPUT_TIMEOUT = 1000L;
    private volatile ScheduledFuture<?> forceCloseTimer;
    private volatile int writeTimeout = 15000;

    private final long id;
    private static long nextId = 0;

    private static synchronized long id() {
        return nextId++;
    }

    SimpleWebsocket(Socket socket, boolean isClient) throws IOException {
        this.socket = socket;
        this.in = socket.getInputStream();
        this.out = socket.getOutputStream();
        this.socket.setSoTimeout(15000);
        this.id = id();
        this.isClient = isClient;
        this.random = isClient ? new SecureRandom() : null;
    }

    public static SimpleWebsocket connect(URI uri) throws IOException {
        return SimpleWebsocketUtil.connect(uri, null);
    }

    public static SimpleWebsocket connect(URI uri, WebsocketHeaders headers) throws IOException {
        return SimpleWebsocketUtil.connect(uri, headers);
    }

    public static SimpleWebsocket accept(HTTPRequest request) throws IOException {
        return SimpleWebsocketUtil.accept(request);
    }

    public static boolean isWebsocketRequest(HTTPRequest request) {
        return SimpleWebsocketUtil.isWebsocketRequest(request);
    }

    /**
     * Get the maximum payload length of a single incoming frame.
     *
     * @return the maximum frame payload length in bytes
     */
    public long getMaxPayloadLength() {
        return maxPayloadLength;
    }

    /**
     * Set the maximum payload length of a single incoming frame. If a frame larger than this is received, the
     * connection is closed with status 1009 (Message Too Big). Defaults to 16 KiB. Values above
     * {@link #MAX_SIZE_LIMIT} are reduced to it.
     *
     * @param maxPayloadLength the maximum frame payload length in bytes
     */
    public void setMaxPayloadLength(long maxPayloadLength) {
        if (maxPayloadLength < 0L) throw new IllegalArgumentException("maxPayloadLength must not be negative");
        this.maxPayloadLength = Math.min(maxPayloadLength, MAX_SIZE_LIMIT);
    }

    /**
     * Get the maximum total size of an incoming message, after reassembling all of its fragments.
     *
     * @return the maximum message size in bytes
     */
    public long getMaxMessageSize() {
        return maxMessageSize;
    }

    /**
     * Set the maximum total size of an incoming message, after reassembling all of its fragments. If a message grows
     * beyond this, the connection is closed with status 1009 (Message Too Big). Defaults to 1 MiB. Values above
     * {@link #MAX_SIZE_LIMIT} are reduced to it.
     *
     * @param maxMessageSize the maximum message size in bytes
     */
    public void setMaxMessageSize(long maxMessageSize) {
        if (maxMessageSize < 0L) throw new IllegalArgumentException("maxMessageSize must not be negative");
        this.maxMessageSize = Math.min(maxMessageSize, MAX_SIZE_LIMIT);
    }

    /**
     * Get the read timeout. See {@link #setReadTimeout(int)}.
     *
     * @return the read timeout in milliseconds, 0 if reads never time out
     * @throws IOException if the timeout could not be read from the socket
     */
    public int getReadTimeout() throws IOException {
        return socket.getSoTimeout();
    }

    /**
     * Set how long a read may wait for data from the peer before failing with a
     * {@link java.net.SocketTimeoutException}. Defaults to 15 seconds.
     * <p>
     * In non-blocking mode, the pings sent every {@code pingFrequency} milliseconds make a responsive peer send pongs,
     * so the timeout only triggers when the peer has stopped responding. In blocking mode no pings are sent
     * automatically, and browsers don't send pings of their own, so either send pings yourself (for example from
     * another thread, at an interval shorter than the timeout), or set the timeout to 0 to disable it.
     * <p>
     * A timeout may happen in the middle of a frame, so treat it as fatal and close the connection.
     *
     * @param timeoutMillis the read timeout in milliseconds, 0 to never time out
     * @throws IOException if the timeout could not be set on the socket
     */
    public void setReadTimeout(int timeoutMillis) throws IOException {
        if (timeoutMillis < 0) throw new IllegalArgumentException("timeoutMillis must not be negative");
        socket.setSoTimeout(timeoutMillis);
    }

    /**
     * Get the write timeout. See {@link #setWriteTimeout(int)}.
     *
     * @return the write timeout in milliseconds, 0 if writes never time out
     */
    public int getWriteTimeout() {
        return writeTimeout;
    }

    /**
     * Set how long writing a single frame may take. If the peer stops reading, its receive buffer fills up and writes
     * block. When a write takes longer than this, the connection is closed and the write fails with an IOException,
     * so a peer that doesn't read can't block a sending thread forever. Defaults to 15 seconds.
     *
     * @param timeoutMillis the write timeout in milliseconds, 0 to never time out
     */
    public void setWriteTimeout(int timeoutMillis) {
        if (timeoutMillis < 0) throw new IllegalArgumentException("timeoutMillis must not be negative");
        this.writeTimeout = timeoutMillis;
    }

    /**
     * Get the send queue limit. See {@link #setMaxQueuedBytes(long)}.
     *
     * @return the maximum number of payload bytes waiting to be sent in non-blocking mode
     */
    public long getMaxQueuedBytes() {
        return maxQueuedBytes;
    }

    /**
     * Set how many payload bytes may wait in the send queue in non-blocking mode. If a {@link #send(WebSocketMessage)}
     * would go over this, the peer isn't keeping up: the connection is closed and send throws an IOException.
     * Defaults to 16 MiB.
     *
     * @param maxQueuedBytes the maximum number of queued payload bytes
     */
    public void setMaxQueuedBytes(long maxQueuedBytes) {
        if (maxQueuedBytes < 0L) throw new IllegalArgumentException("maxQueuedBytes must not be negative");
        this.maxQueuedBytes = maxQueuedBytes;
    }

    /**
     * Get whether incoming pings are answered automatically. See {@link #setHandleIncomingPingsAutomatically(boolean)}.
     *
     * @return true if pings are answered automatically
     */
    public boolean isHandlingIncomingPingsAutomatically() {
        return handleIncomingPingsAutomatically;
    }

    /**
     * Set whether incoming pings are answered with a pong automatically. When enabled (the default), pings are not
     * returned by {@link #read()} or passed to listeners. When disabled, they are, and the application should reply
     * with {@link WebSocketMessage#createPong(WebSocketMessage)}.
     *
     * @param handleIncomingPingsAutomatically true to answer pings automatically
     */
    public void setHandleIncomingPingsAutomatically(boolean handleIncomingPingsAutomatically) {
        this.handleIncomingPingsAutomatically = handleIncomingPingsAutomatically;
    }

    /**
     * Switch to non-blocking mode: incoming messages are passed to listeners, sends are queued, and a ping is sent
     * every pingFrequency milliseconds. Whether pings are answered automatically is kept as set by
     * {@link #setHandleIncomingPingsAutomatically(boolean)}.
     *
     * @param pingFrequency milliseconds between pings, 0 to not send pings
     */
    public void useNonBlockingMode(long pingFrequency) {
        useNonBlockingMode(pingFrequency, handleIncomingPingsAutomatically, null);
    }

    public void useNonBlockingMode(long pingFrequency, boolean handleIncomingPingsAutomatically, ThreadFactory threadFactory) {
        synchronized (sendQueueLock) {
            if (nonBlockingMode) {
                return;
            }
            nonBlockingMode = true;
        }
        this.pingFrequency = pingFrequency;
        this.handleIncomingPingsAutomatically = handleIncomingPingsAutomatically;
        if (threadFactory == null) {
            new Thread(this::incomingThread, "WebSocket-" + id + "-In").start();
            new Thread(this::outgoingThread, "WebSocket-" + id + "-Out").start();
        } else {
            Thread incoming = threadFactory.newThread(this::incomingThread);
            incoming.setName("WebSocket-" + id + "-In");
            incoming.start();
            Thread outgoing = threadFactory.newThread(this::outgoingThread);
            outgoing.setName("WebSocket-" + id + "-Out");
            outgoing.start();
        }
    }

    /**
     * Read the next message, blocking until one arrives. Pong and close frames are returned too. Pings are answered
     * automatically and not returned, unless that has been turned off with
     * {@link #setHandleIncomingPingsAutomatically(boolean)}.
     * <p>
     * Reads time out after the read timeout (15 seconds by default) if nothing arrives. See
     * {@link #setReadTimeout(int)}.
     *
     * @return the message, or null if the connection was closed
     * @throws IOException if an I/O error occurs, or the read times out
     */
    public WebSocketMessage read() throws IOException {
        if (nonBlockingMode) {
            throw new IllegalStateException("Non blocking mode in use! Add an event listener instead!");
        }
        try {
            while (true) {
                WebSocketMessage msg = read0();
                if (msg != null && msg.getOpcode() == WebSocketMessage.OPCODE_PING
                        && handleIncomingPingsAutomatically) {
                    // Pongs are written directly rather than through send(), so they don't fail after close().
                    send0(WebSocketMessage.createPong(msg));
                    continue;
                }
                return msg;
            }
        } catch (IOException e) {
            if (closed) {
                return null; // The socket was closed while closing the connection.
            }
            throw e;
        }
    }

    private ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
    /**
     * After a fragmented message larger than this, the reassembly buffer is replaced instead of reused, so a single
     * large message doesn't keep a large buffer allocated for the rest of the connection.
     */
    private static final int KEEP_READ_BUFFER_SIZE = 65536;
    private int readOpcode = 0;
    private boolean messageInProgress = false;
    private boolean receivedCloseFrame = false;

    private WebSocketMessage read0() throws IOException {
        while (true) {
            if (receivedCloseFrame) {
                return null;
            }
            WebSocketPacket pkt = read1();
            if (pkt == null) {
                abort(); // The stream ended or the connection was failed, nothing more can be read.
                return null;
            }
            if (pkt.opcode == WebSocketMessage.OPCODE_CLOSE) {
                byte[] p = pkt.payload;
                if (p.length >= 2) {
                    if (!isValidCloseCode(((p[0] & 0xff) << 8) | (p[1] & 0xff))) {
                        return fail(CLOSE_PROTOCOL_ERROR);
                    }
                    if (!isValidUtf8(p, 2)) {
                        return fail(CLOSE_INVALID_DATA);
                    }
                } else if (p.length == 1) {
                    return fail(CLOSE_PROTOCOL_ERROR);
                }
                receivedCloseFrame = true;
                // Answer with a close frame echoing the status code (unless we sent one already), then close.
                closeWith(p.length >= 2 ? new byte[]{p[0], p[1]} : new byte[0], false);
                return new WebSocketMessage(pkt.opcode, p);
            }
            if (pkt.opcode >= 0x8) {
                // Control frames may be interleaved with the fragments of a data message
                // and must not disturb the message being reassembled.
                return new WebSocketMessage(pkt.opcode, pkt.payload);
            }
            if (pkt.opcode == WebSocketMessage.OPCODE_CONTINUATION) {
                if (!messageInProgress) {
                    return fail(CLOSE_PROTOCOL_ERROR); // continuation without a message to continue
                }
            } else {
                if (messageInProgress) {
                    return fail(CLOSE_PROTOCOL_ERROR); // new message before the previous one was finished
                }
                readBuffer.reset();
                readOpcode = pkt.opcode;
            }
            if (pkt.fin) {
                messageInProgress = false;
                byte[] payload;
                if (readBuffer.size() != 0) {
                    readBuffer.write(pkt.payload);
                    payload = readBuffer.toByteArray();
                    if (payload.length > KEEP_READ_BUFFER_SIZE) {
                        readBuffer = new ByteArrayOutputStream();
                    } else {
                        readBuffer.reset();
                    }
                } else {
                    payload = pkt.payload;
                }
                if (readOpcode == WebSocketMessage.OPCODE_TEXT && !isValidUtf8(payload, 0)) {
                    return fail(CLOSE_INVALID_DATA);
                }
                return new WebSocketMessage(readOpcode, payload);
            } else {
                messageInProgress = true;
                readBuffer.write(pkt.payload);
            }
        }
    }

    private WebSocketPacket read1() throws IOException {
        int b0 = in.read();
        if (b0 == -1) {
            return null;
        }
        int b1 = in.read();
        if (b1 == -1) {
            return null;
        }
        boolean fin = (b0 & 0x80) != 0;
        boolean rsv = (b0 & 0x70) != 0;
        int opcode = b0 & 0x0F;
        boolean mask = (b1 & 0x80) != 0;
        long lengthOfPayload = b1 & 0x7F;
        if (lengthOfPayload == 126L || lengthOfPayload == 127L) {
            byte[] extendedLength = readFully(lengthOfPayload == 126L ? 2 : 8);
            if (extendedLength == null) {
                return null;
            }
            lengthOfPayload = 0L;
            for (byte b : extendedLength) {
                lengthOfPayload = (lengthOfPayload << 8) | (b & 0xffL);
            }
        }
        boolean controlFrame = opcode >= 0x8;
        if (rsv // no extensions are negotiated, so the reserved bits must be 0
                || !isKnownOpcode(opcode)
                || (controlFrame && (!fin || lengthOfPayload > 125L)) // control frames can't be fragmented or long
                || mask == isClient) { // clients must mask their frames, servers must not
            return fail(CLOSE_PROTOCOL_ERROR);
        }
        // Check the limits before allocating anything. A 64-bit length with the high bit set is negative.
        long messageSizeSoFar = opcode == WebSocketMessage.OPCODE_CONTINUATION ? readBuffer.size() : 0L;
        if (lengthOfPayload < 0L
                || lengthOfPayload > maxPayloadLength
                || (!controlFrame && messageSizeSoFar + lengthOfPayload > maxMessageSize)) {
            return fail(CLOSE_MESSAGE_TOO_BIG);
        }
        byte[] maskKey = null;
        if (mask) {
            maskKey = readFully(4);
            if (maskKey == null) {
                return null;
            }
        }
        byte[] payload = readFully((int) lengthOfPayload);
        if (payload == null) {
            return null;
        }
        if (mask) {
            for (int i = 0; i < payload.length; i++) {
                payload[i] ^= maskKey[i & 3];
            }
        }
        return new WebSocketPacket(fin, opcode, payload);
    }

    static boolean isValidUtf8(byte[] bytes, int offset) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private static boolean isValidCloseCode(int code) {
        // 1004, 1005, 1006 and 1015 are reserved and must never be sent, 1016-2999 are unassigned.
        return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) || (code >= 3000 && code <= 4999);
    }

    private static boolean isKnownOpcode(int opcode) {
        switch (opcode) {
            case WebSocketMessage.OPCODE_CONTINUATION:
            case WebSocketMessage.OPCODE_TEXT:
            case WebSocketMessage.OPCODE_BINARY:
            case WebSocketMessage.OPCODE_CLOSE:
            case WebSocketMessage.OPCODE_PING:
            case WebSocketMessage.OPCODE_PONG:
                return true;
            default:
                return false;
        }
    }

    /**
     * Read exactly length bytes.
     *
     * @return the bytes, or null if the stream ended first
     */
    private byte[] readFully(int length) throws IOException {
        byte[] bytes = new byte[length];
        int amountRead = 0;
        while (amountRead < length) {
            int c = in.read(bytes, amountRead, length - amountRead);
            if (c == -1) {
                return null;
            }
            amountRead += c;
        }
        return bytes;
    }

    /**
     * Fail the connection: send a close frame with the status code and close.
     *
     * @return null, for convenient use as {@code return fail(code);} in the read methods
     */
    private <T> T fail(int statusCode) {
        closeWithStatus(statusCode);
        return null;
    }

    /**
     * Send a message. In non-blocking mode the message is queued and sent by the outgoing thread.
     *
     * @param msg the message to send
     * @throws IOException if the connection is closed or closing, or the message could not be written
     */
    public void send(WebSocketMessage msg) throws IOException {
        boolean isClose = msg.getOpcode() == WebSocketMessage.OPCODE_CLOSE;
        if (nonBlockingMode) {
            synchronized (sendQueueLock) {
                if (closeQueued) {
                    if (isClose) return;
                    throw new IOException("WebSocket is closed");
                }
                if (isClose || queuedBytes + msg.getLength() <= maxQueuedBytes) {
                    if (isClose) closeQueued = true;
                    sendQueue.add(msg);
                    queuedBytes += msg.getLength();
                    sendQueueLock.notifyAll();
                    return;
                }
            }
            // The peer isn't keeping up. Drop the connection rather than buffer without limit.
            abort();
            throw new IOException("Send queue full, closed the WebSocket");
        }
        writeLock.lock();
        try {
            if (sentCloseFrame) {
                if (isClose) return;
                throw new IOException("WebSocket is closed");
            }
            writeFrame(msg);
        } finally {
            writeLock.unlock();
        }
    }

    private void send0(WebSocketMessage msg) throws IOException {
        writeLock.lock();
        try {
            writeFrame(msg);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Write a frame, unless a close frame has already been written. Must hold writeLock.
     */
    private void writeFrame(WebSocketMessage msg) throws IOException {
        if (sentCloseFrame) return;
        if (msg.getOpcode() == WebSocketMessage.OPCODE_CLOSE) sentCloseFrame = true;
        int timeout = writeTimeout;
        ScheduledFuture<?> timer = timeout > 0
                ? closeTimer().schedule(this::writeTimedOut, timeout, TimeUnit.MILLISECONDS)
                : null;
        try {
            send1(msg);
        } finally {
            if (timer != null) timer.cancel(false);
        }
        if (sentCloseFrame) {
            // Nothing may be sent after a close frame. Half-close so the peer sees the end of the stream, while we
            // can still read its close frame.
            try {
                socket.shutdownOutput();
            } catch (IOException | UnsupportedOperationException ignored) {
                // SSLSocket doesn't support half-closing.
            }
        }
    }

    /**
     * A write took longer than the write timeout, the peer has stopped reading. Closing the socket makes the stuck
     * write fail with an IOException.
     */
    private void writeTimedOut() {
        abort();
    }

    /**
     * Close the connection immediately without a close frame, discarding anything queued.
     */
    private void abort() {
        markClosed();
        closeSocket();
    }

    private void send1(WebSocketMessage msg) throws IOException {
        // Build the whole frame and write it at once: two writes per frame interact badly with Nagle's algorithm
        // and delayed ACKs.
        int len = msg.getLength();
        int headerLength = len < 126 ? 2 : (len <= 65535 ? 4 : 10);
        int payloadOffset = isClient ? headerLength + 4 : headerLength;
        byte[] frame = new byte[payloadOffset + len];
        frame[0] = (byte) (0x80 | (msg.getOpcode() & 0xF));
        if (len < 126) {
            frame[1] = (byte) len;
        } else if (len <= 65535) {
            frame[1] = (byte) 126;
            frame[2] = (byte) (len >> 8);
            frame[3] = (byte) len;
        } else {
            frame[1] = (byte) 127;
            for (int i = 0; i < 8; i++) {
                frame[2 + i] = (byte) ((long) len >>> (56 - 8 * i));
            }
        }
        msg.copyTo(frame, payloadOffset);
        if (isClient) {
            // Clients must mask every frame with a fresh random key.
            frame[1] |= (byte) 0x80;
            byte[] maskKey = new byte[4];
            random.nextBytes(maskKey);
            System.arraycopy(maskKey, 0, frame, headerLength, 4);
            for (int i = 0; i < len; i++) {
                frame[payloadOffset + i] ^= maskKey[i & 3];
            }
        }
        out.write(frame);
        out.flush();
    }

    /**
     * XOR the message with the mask key, in place.
     *
     * @param maskKey the 4-byte mask key, or null to leave the message unchanged
     * @param message the message, which is modified
     * @return the same array as message
     * @deprecated Internal helper that was public by mistake, no longer used by this library. It modifies the array
     * passed to it. Will be removed in a future version.
     */
    @Deprecated
    public byte[] maskMessage(byte[] maskKey, byte[] message) {
        if (maskKey != null) {
            for (int i = 0; i < message.length; i++) {
                message[i] = (byte) ((((int) message[i]) & 0xff) ^ (((int) maskKey[i % 4]) & 0xff));
            }
        }
        return message;
    }

    /**
     * Fail the connection: send a close frame with the status code and close.
     */
    private void closeWithStatus(int statusCode) {
        closeWith(new byte[]{(byte) ((statusCode >> 8) & 0xff), (byte) (statusCode & 0xff)}, true);
    }

    /**
     * Send a close frame with the given payload (written immediately, bypassing the send queue) and close the
     * socket. Only called from the thread reading from the socket.
     *
     * @param payload      the close frame payload
     * @param discardInput true when failing the connection: unread input is discarded for a short while before
     *                     closing, because closing a socket with unread input sends a TCP reset, which can make the
     *                     peer lose the close frame
     */
    private void closeWith(byte[] payload, boolean discardInput) {
        scheduleForceClose();
        // Write the close frame before setting closed: in non-blocking mode the outgoing thread exits as soon as it
        // sees closed with an empty queue.
        writeCloseFrame(payload);
        markClosed();
        if (discardInput) {
            discardInput();
        }
        closeSocket();
    }

    /**
     * Close the connection, sending a close frame first. The socket is closed when the peer answers with its own
     * close frame (read by whichever thread is reading), or after 5 seconds.
     * <p>
     * In non-blocking mode this returns immediately: messages already queued are sent first, then the close frame.
     *
     * @throws IOException never in practice, errors while closing are ignored
     */
    @Override
    public void close() throws IOException {
        boolean letOutgoingThreadFinish;
        synchronized (sendQueueLock) {
            if (closed) {
                return;
            }
            closed = true;
            letOutgoingThreadFinish = nonBlockingMode;
            if (letOutgoingThreadFinish && !closeQueued) {
                sendQueue.add(WebSocketMessage.create(WebSocketMessage.OPCODE_CLOSE));
            }
            closeQueued = true;
            sendQueueLock.notifyAll();
        }
        scheduleForceClose();
        if (letOutgoingThreadFinish) {
            return; // The outgoing thread sends what's queued, then the close frame.
        }
        if (!writeCloseFrame(new byte[0])) {
            closeSocket();
        }
    }

    /**
     * Write a close frame, unless one has been written already. Waits at most {@link #CLOSE_TIMEOUT} for another
     * thread's write to finish.
     *
     * @return true if a close frame has been written, by this call or earlier
     */
    private boolean writeCloseFrame(byte[] payload) {
        if (!lockWithin(writeLock, CLOSE_TIMEOUT)) {
            return false;
        }
        try {
            writeFrame(new WebSocketMessage(WebSocketMessage.OPCODE_CLOSE, payload));
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Acquire the lock, waiting at most timeoutMillis. Unlike {@link ReentrantLock#tryLock(long, TimeUnit)}, this
     * keeps waiting if the thread is interrupted (and restores the interrupt status afterwards), so closing from an
     * interrupted thread, e.g. during an executor shutdown, still sends the close frame.
     */
    private static boolean lockWithin(ReentrantLock lock, long timeoutMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    return lock.tryLock(Math.max(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void markClosed() {
        synchronized (sendQueueLock) {
            closed = true;
            closeQueued = true;
            sendQueue.clear();
            queuedBytes = 0L;
            sendQueueLock.notifyAll();
        }
    }

    /**
     * Read and discard input until the peer closes the connection, for at most {@link #DISCARD_INPUT_TIMEOUT}.
     */
    private void discardInput() {
        long deadline = System.currentTimeMillis() + DISCARD_INPUT_TIMEOUT;
        byte[] buffer = new byte[8192];
        try {
            long remaining;
            while ((remaining = deadline - System.currentTimeMillis()) > 0L) {
                socket.setSoTimeout((int) remaining);
                if (in.read(buffer) == -1) {
                    return;
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Make sure the socket gets closed after {@link #CLOSE_TIMEOUT} even if the peer never completes the closing
     * handshake. This also unblocks any thread stuck writing to a peer that isn't reading.
     */
    private void scheduleForceClose() {
        synchronized (sendQueueLock) {
            if (forceCloseTimer == null) {
                forceCloseTimer = closeTimer().schedule(this::closeSocket, CLOSE_TIMEOUT, TimeUnit.MILLISECONDS);
            }
        }
    }

    private void closeSocket() {
        ScheduledFuture<?> timer = forceCloseTimer;
        if (timer != null) {
            timer.cancel(false);
        }
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    private static ScheduledExecutorService closeTimer() {
        return CloseTimer.INSTANCE;
    }

    private static class CloseTimer {
        // Created on first use (class initialization is lazy), shared by all websockets.
        private static final ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1, r -> {
            Thread t = new Thread(r, "SimpleWebsocket-CloseTimer");
            t.setDaemon(true);
            return t;
        });

        static {
            INSTANCE.setRemoveOnCancelPolicy(true);
        }
    }

    // Copy-on-write, so listeners can add or remove listeners from inside a callback.
    private final Set<WebSocketListener> listeners = new CopyOnWriteArraySet<>();

    public void addListener(WebSocketListener listener) {
        listeners.add(listener);
    }

    public void removeListener(WebSocketListener listener) {
        listeners.remove(listener);
    }

    private void incomingThread() {
        try {
            while (true) {
                WebSocketMessage msg = read0();
                if (msg == null) {
                    break;
                }
                switch (msg.getOpcode()) {
                    case WebSocketMessage.OPCODE_PING:
                        if (handleIncomingPingsAutomatically) {
                            send(WebSocketMessage.createPong(msg));
                            continue;
                        } else {
                            break;
                        }
                    case WebSocketMessage.OPCODE_PONG:
                        break;
                }
                for (WebSocketListener listener : listeners) {
                    try {
                        listener.receivedMessage(this, msg);
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception e) {
        } finally {
            try {
                close();
            } catch (Exception e) {
            }
            for (WebSocketListener listener : listeners) {
                try {
                    listener.socketClosed(this);
                } catch (Exception e) {
                }
            }
        }
    }

    private void outgoingThread() {
        long lastSentPing = System.currentTimeMillis();
        try {
            while (true) {
                WebSocketMessage msg = null;
                // Pick the next thing to send while holding the queue lock, but write it after releasing the lock,
                // so a peer that stops reading can't block close() or send().
                synchronized (sendQueueLock) {
                    while (true) {
                        if (!sendQueue.isEmpty()) {
                            msg = sendQueue.remove(0);
                            queuedBytes -= msg.getLength();
                            break;
                        }
                        if (closed) {
                            // Everything queued before close() has been sent, including the close frame. The
                            // socket is closed when the peer answers, or by the force-close timer.
                            return;
                        }
                        if (pingFrequency <= 0L) {
                            // Pings disabled, wait until there's something to send.
                            sendQueueLock.wait();
                            continue;
                        }
                        long untilPing = lastSentPing + pingFrequency - System.currentTimeMillis();
                        if (untilPing <= 0L) {
                            break;
                        }
                        sendQueueLock.wait(untilPing);
                    }
                }
                if (msg == null) {
                    lastSentPing = System.currentTimeMillis();
                    msg = WebSocketMessage.create(WebSocketMessage.OPCODE_PING);
                }
                send0(msg);
            }
        } catch (IOException | InterruptedException e) {
            abort();
        }
    }

    private static class WebSocketPacket {
        private final boolean fin;
        private final int opcode;
        private final byte[] payload;

        private WebSocketPacket(boolean fin, int opcode, byte[] payload) {
            this.fin = fin;
            this.opcode = opcode;
            this.payload = payload;
        }
    }
}
