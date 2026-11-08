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
import java.util.concurrent.ThreadFactory;

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
    private final Object writeLock = new Object();
    private long pingFrequency = 5000L;
    private boolean sentCloseFrame = false;
    private boolean nonBlockingMode = false;
    private boolean handleIncomingPingsAutomatically = true;
    private final Object sendQueueLock = new Object();
    private boolean closed = false;
    private final List<WebSocketMessage> sendQueue = new LinkedList<>();

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
        synchronized (sendQueueLock) {
            if (msg.getOpcode() == WebSocketMessage.OPCODE_CLOSE) {
                if (sentCloseFrame) {
                    return;
                }
                sentCloseFrame = true;
            } else {
                if (sentCloseFrame) {
                    throw new IllegalStateException("Already sent close frame!");
                }
            }
            if (nonBlockingMode) {
                sendQueue.add(msg);
                sendQueueLock.notifyAll();
            } else {
                send0(msg);
            }
        }
    }

    private final byte[] headerBuffer = new byte[14];

    private void send0(WebSocketMessage msg) throws IOException {
        synchronized (writeLock) {
            send1(msg);
        }
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
        try {
            boolean sendFrame;
            synchronized (sendQueueLock) {
                sendFrame = !sentCloseFrame;
                sentCloseFrame = true;
            }
            if (sendFrame) {
                byte[] payload = new byte[]{(byte) ((statusCode >> 8) & 0xff), (byte) (statusCode & 0xff)};
                send0(new WebSocketMessage(WebSocketMessage.OPCODE_CLOSE, payload));
            }
        } catch (IOException ignored) {
        }
        try {
            close();
        } catch (IOException ignored) {
        }
    }

    @Override
    public void close() throws IOException {
        synchronized (sendQueueLock) {
            if (closed) {
                return;
            }
            closed = true;
            sendQueueLock.notifyAll();
        }
        send(WebSocketMessage.create(WebSocketMessage.OPCODE_CLOSE));
        socket.close();
    }

    private final Set<WebSocketListener> listeners = new HashSet<>();

    public void addListener(WebSocketListener listener) {
        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    public void removeListener(WebSocketListener listener) {
        synchronized (listeners) {
            listeners.remove(listener);
        }
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
                synchronized (listeners) {
                    for (WebSocketListener listener : listeners) {
                        try {
                            listener.receivedMessage(this, msg);
                        } catch (Exception e) {
                        }
                    }
                }
            }
        } catch (IOException e) {
        }
        try {
            close();
        } catch (Exception e) {
        }
        synchronized (listeners) {
            for (WebSocketListener listener : listeners) {
                listener.socketClosed(this);
            }
        }
    }

    private void outgoingThread() {
        long lastSentPing = System.currentTimeMillis();
        try {
            a:
            while (true) {
                WebSocketMessage msg;
                synchronized (sendQueueLock) {
                    if (closed) {
                        break;
                    }
                    while (sendQueue.isEmpty()) {
                        if (closed) {
                            break a;
                        }
                        long now = System.currentTimeMillis();
                        boolean needToSendPing = pingFrequency > 0L && (now - lastSentPing) >= pingFrequency;
                        long nextPing;
                        if (needToSendPing) {
                            lastSentPing = now;
                            send0(WebSocketMessage.create(WebSocketMessage.OPCODE_PING));
                            nextPing = pingFrequency;
                        } else {
                            nextPing = pingFrequency - (now - lastSentPing);
                        }
                        try {
                            sendQueueLock.wait(nextPing);
                        } catch (InterruptedException e) {
                            break a;
                        }
                        now = System.currentTimeMillis();
                        needToSendPing = (now - lastSentPing) >= pingFrequency;
                        if (needToSendPing) {
                            lastSentPing = now;
                            send0(WebSocketMessage.create(WebSocketMessage.OPCODE_PING));
                        }
                    }
                    msg = sendQueue.remove(0);
                }
                if (msg != null) {
                    send0(msg);
                }
            }
        } catch (IOException e) {
        }
        try {
            close();
        } catch (Exception e) {
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
