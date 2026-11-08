package io.siggi.simplewebsocket;

import io.siggi.http.HTTPRequest;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
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

    private volatile long maxPayloadLength = 16384;
    private volatile long maxMessageSize = 1048576;
    private long pingFrequency = 5000L;
    private volatile boolean nonBlockingMode = false;
    private boolean handleIncomingPingsAutomatically = true;

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
     * How long close() waits to write the close frame before forcibly closing the socket.
     */
    private static final long CLOSE_TIMEOUT = 5000L;
    private static ScheduledThreadPoolExecutor closeTimer;

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
     * connection is closed with status 1009 (Message Too Big). Defaults to 16 KiB.
     *
     * @param maxPayloadLength the maximum frame payload length in bytes
     */
    public void setMaxPayloadLength(long maxPayloadLength) {
        if (maxPayloadLength < 0L) throw new IllegalArgumentException("maxPayloadLength must not be negative");
        this.maxPayloadLength = maxPayloadLength;
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
     * beyond this, the connection is closed with status 1009 (Message Too Big). Defaults to 1 MiB.
     *
     * @param maxMessageSize the maximum message size in bytes
     */
    public void setMaxMessageSize(long maxMessageSize) {
        if (maxMessageSize < 0L) throw new IllegalArgumentException("maxMessageSize must not be negative");
        this.maxMessageSize = maxMessageSize;
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

    public void useNonBlockingMode(long pingFrequency) {
        useNonBlockingMode(pingFrequency, true, null);
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
     * Read the next message, blocking until one arrives. Control frames (ping, pong and close) are returned too, and
     * pings are not answered automatically in blocking mode. Reply to a ping with
     * {@link WebSocketMessage#createPong(WebSocketMessage)}.
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
        return read0();
    }

    private final ByteArrayOutputStream readBuffer = new ByteArrayOutputStream();
    private int readOpcode = 0;

    private WebSocketMessage read0() throws IOException {
        while (true) {
            WebSocketPacket pkt = read1();
            if (pkt == null) {
                return null;
            }
            if (pkt.opcode >= 0x8) {
                // Control frames may be interleaved with the fragments of a data message
                // and must not disturb the message being reassembled.
                return new WebSocketMessage(pkt.opcode, pkt.decoded);
            }
            if (pkt.opcode != WebSocketMessage.OPCODE_CONTINUATION) {
                readBuffer.reset();
                readOpcode = pkt.opcode;
            }
            if (pkt.fin) {
                byte[] payload;
                if (readBuffer.size() != 0) {
                    readBuffer.write(pkt.decoded);
                    payload = readBuffer.toByteArray();
                    readBuffer.reset();
                } else {
                    payload = pkt.decoded;
                }
                return new WebSocketMessage(readOpcode, payload);
            } else {
                readBuffer.write(pkt.decoded);
            }
        }
    }

    private WebSocketPacket read1() throws IOException {
        int opcode = in.read();
        if (opcode == -1) {
            return null;
        }
        boolean fin = (opcode & 0x80) != 0;
        boolean rsv1 = (opcode & 0x40) != 0;
        boolean rsv2 = (opcode & 0x20) != 0;
        boolean rsv3 = (opcode & 0x10) != 0;
        opcode = opcode & 0x0F;
        long lengthOfPayload = (long) in.read();
        if (lengthOfPayload == -1L) {
            return null;
        }
        boolean mask = (lengthOfPayload & 0x80L) != 0L;
        lengthOfPayload = lengthOfPayload & 0x7F;
        if (lengthOfPayload == 126L) {
            lengthOfPayload = (long) ((in.read() << 8) + in.read());
        } else if (lengthOfPayload == 127L) {
            lengthOfPayload = ((long) in.read() << 56)
                    + ((long) in.read() << 48)
                    + ((long) in.read() << 40)
                    + ((long) in.read() << 32)
                    + ((long) in.read() << 24)
                    + ((long) in.read() << 16)
                    + ((long) in.read() << 8)
                    + (long) in.read();
        }
        // Check the limits before allocating anything. A 64-bit length with the high bit set is negative.
        long messageSizeSoFar = opcode == WebSocketMessage.OPCODE_CONTINUATION ? readBuffer.size() : 0L;
        if (lengthOfPayload < 0L
                || lengthOfPayload > maxPayloadLength
                || (opcode < 0x8 && messageSizeSoFar + lengthOfPayload > maxMessageSize)) {
            closeWithStatus(CLOSE_MESSAGE_TOO_BIG);
            return null;
        }
        byte[] maskKey = new byte[4];
        int amountRead = 0;
        int c;
        if (mask) {
            while (amountRead < 4) {
                c = in.read(maskKey, amountRead, 4 - amountRead);
                if (c == -1) {
                    return null;
                }
                amountRead += c;
            }
        }
        byte[] message = new byte[(int) lengthOfPayload];
        amountRead = 0;
        while (amountRead < lengthOfPayload) {
            c = in.read(message, amountRead, message.length - amountRead);
            if (c == -1) {
                return null;
            }
            amountRead += c;
        }
        byte[] decoded = new byte[message.length];
        if (mask) {
            for (int i = 0; i < message.length; i++) {
                decoded[i] = (byte) ((((int) message[i]) & 0xff) ^ (((int) maskKey[i % 4]) & 0xff));
            }
        } else {
            System.arraycopy(message, 0, decoded, 0, message.length);
        }
        return new WebSocketPacket(fin, rsv1, rsv2, rsv3, opcode, mask, maskKey, lengthOfPayload, message, decoded);
    }

    public void send(WebSocketMessage msg) throws IOException {
        boolean isClose = msg.getOpcode() == WebSocketMessage.OPCODE_CLOSE;
        if (nonBlockingMode) {
            synchronized (sendQueueLock) {
                if (closeQueued) {
                    if (isClose) return;
                    throw new IllegalStateException("Already sent close frame!");
                }
                if (isClose) closeQueued = true;
                sendQueue.add(msg);
                sendQueueLock.notifyAll();
            }
            return;
        }
        writeLock.lock();
        try {
            if (sentCloseFrame) {
                if (isClose) return;
                throw new IllegalStateException("Already sent close frame!");
            }
            writeFrame(msg);
        } finally {
            writeLock.unlock();
        }
    }

    private final byte[] headerBuffer = new byte[14];

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
        send1(msg);
    }

    private void send1(WebSocketMessage msg) throws IOException {
        int headerLength = 2;
        headerBuffer[0] = (byte) (0x80 + (msg.getOpcode() & 0xF));
        int len = msg.getLength();
        if (len >= 126 && len <= 65535) {
            headerLength = 4;
            headerBuffer[1] = (byte) (126);
            headerBuffer[2] = (byte) ((len >> 8) & 0xff);
            headerBuffer[3] = (byte) (len & 0xff);
        } else if (len >= 65536) {
            headerLength = 10;
            headerBuffer[1] = (byte) 127;
            headerBuffer[2] = (byte) 0;
            headerBuffer[3] = (byte) 0;
            headerBuffer[4] = (byte) 0;
            headerBuffer[5] = (byte) 0;
            headerBuffer[6] = (byte) ((len >> 24) & 0xff);
            headerBuffer[7] = (byte) ((len >> 16) & 0xff);
            headerBuffer[8] = (byte) ((len >> 8) & 0xff);
            headerBuffer[9] = (byte) (len & 0xff);
        } else {
            headerBuffer[1] = (byte) (len);
        }
        byte[] mask;
        if (isClient) {
            mask = new byte[4];
            random.nextBytes(mask);
            headerBuffer[1] |= (byte) 0x80;
            System.arraycopy(mask, 0, headerBuffer, headerLength, 4);
            headerLength += 4;
        } else {
            mask = null;
        }
        out.write(headerBuffer, 0, headerLength);
        out.write(maskMessage(mask, msg.getBytes()));
        out.flush();
    }

    public byte[] maskMessage(byte[] maskKey, byte[] message) {
        if (maskKey != null) {
            for (int i = 0; i < message.length; i++) {
                message[i] = (byte) ((((int) message[i]) & 0xff) ^ (((int) maskKey[i % 4]) & 0xff));
            }
        }
        return message;
    }

    /**
     * Send a close frame with the given status code (best effort, written immediately, bypassing the send queue)
     * and close the connection.
     */
    private void closeWithStatus(int statusCode) {
        synchronized (sendQueueLock) {
            closed = true;
            closeQueued = true;
            sendQueue.clear();
            sendQueueLock.notifyAll();
        }
        byte[] payload = new byte[]{(byte) ((statusCode >> 8) & 0xff), (byte) (statusCode & 0xff)};
        closeNow(new WebSocketMessage(WebSocketMessage.OPCODE_CLOSE, payload));
    }

    /**
     * Close the connection, sending a close frame first.
     * <p>
     * In non-blocking mode this returns immediately: messages already queued are sent, followed by the close frame,
     * and then the socket is closed. If that takes longer than 5 seconds, the socket is closed anyway.
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
        if (letOutgoingThreadFinish) {
            // The outgoing thread sends what's queued, then closes the socket.
            scheduleForceClose();
            return;
        }
        closeNow(WebSocketMessage.create(WebSocketMessage.OPCODE_CLOSE));
    }

    /**
     * Write the close frame and close the socket. If another thread is stuck writing to a peer that isn't reading,
     * the socket is closed after {@link #CLOSE_TIMEOUT} anyway, which also unblocks that thread.
     */
    private void closeNow(WebSocketMessage closeFrame) {
        ScheduledFuture<?> forceClose = scheduleForceClose();
        try {
            if (writeLock.tryLock(CLOSE_TIMEOUT, TimeUnit.MILLISECONDS)) {
                try {
                    writeFrame(closeFrame);
                } catch (IOException ignored) {
                } finally {
                    writeLock.unlock();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            forceClose.cancel(false);
            closeSocket();
        }
    }

    private ScheduledFuture<?> scheduleForceClose() {
        return closeTimer().schedule(this::closeSocket, CLOSE_TIMEOUT, TimeUnit.MILLISECONDS);
    }

    private void closeSocket() {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    private static synchronized ScheduledExecutorService closeTimer() {
        if (closeTimer == null) {
            closeTimer = new ScheduledThreadPoolExecutor(1, r -> {
                Thread t = new Thread(r, "SimpleWebsocket-CloseTimer");
                t.setDaemon(true);
                return t;
            });
            closeTimer.setRemoveOnCancelPolicy(true);
        }
        return closeTimer;
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
                            break;
                        }
                        if (closed) {
                            // Everything queued before close() has been sent.
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
        } finally {
            synchronized (sendQueueLock) {
                closed = true;
                closeQueued = true;
                sendQueue.clear();
                sendQueueLock.notifyAll();
            }
            closeSocket();
        }
    }

    private static class WebSocketPacket {

        private final boolean fin;
        private final boolean rsv1;
        private final boolean rsv2;
        private final boolean rsv3;
        private final int opcode;
        private final boolean mask;
        private final byte[] maskKey;
        private final long lengthOfPayload;
        private final byte[] message;
        private final byte[] decoded;

        private WebSocketPacket(boolean fin, boolean rsv1, boolean rsv2, boolean rsv3, int opcode, boolean mask, byte[] maskKey, long lengthOfPayload, byte[] message, byte[] decoded) {
            this.fin = fin;
            this.rsv1 = rsv1;
            this.rsv2 = rsv2;
            this.rsv3 = rsv3;
            this.opcode = opcode;
            this.mask = mask;
            this.maskKey = maskKey;
            this.lengthOfPayload = lengthOfPayload;
            this.message = message;
            this.decoded = decoded;
        }

    }
}
