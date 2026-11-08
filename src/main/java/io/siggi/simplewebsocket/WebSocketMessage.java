package io.siggi.simplewebsocket;

import java.nio.charset.StandardCharsets;

public class WebSocketMessage {

    public static final int OPCODE_CONTINUATION = 0;
    public static final int OPCODE_TEXT = 1;
    public static final int OPCODE_BINARY = 2;
    public static final int OPCODE_CLOSE = 8;
    public static final int OPCODE_PING = 9;
    public static final int OPCODE_PONG = 10;

    private static final byte[] zeroBytes = new byte[0];

    WebSocketMessage(int opcode, byte[] bytes) {
        this.opcode = opcode;
        this.bytes = bytes;
    }

    /**
     * Create a text message
     *
     * @param message the text message
     * @return the message
     */
    public static WebSocketMessage create(String message) {
        return new WebSocketMessage(OPCODE_TEXT, message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Create a binary message
     *
     * @param message the bytes
     * @return the message
     */
    public static WebSocketMessage create(byte[] message) {
        byte[] msg = new byte[message.length];
        System.arraycopy(message, 0, msg, 0, message.length);
        return new WebSocketMessage(OPCODE_BINARY, msg);
    }

    /**
     * Create a control message
     *
     * @param opcode the opcode
     * @return the message
     * @throws IllegalArgumentException if the passed opcode is not a control
     *                                  opcode
     */
    public static WebSocketMessage create(int opcode) {
        if (opcode < 0x08) {
            throw new IllegalArgumentException("This is not a control opcode!");
        }
        return new WebSocketMessage(opcode, zeroBytes);
    }

    /**
     * Create a pong in response to a ping
     *
     * @param ping the ping message
     * @return the message
     * @throws IllegalArgumentException if the passed WebSocketMessage is not a ping message
     */
    public static WebSocketMessage createPong(WebSocketMessage ping) {
        if (ping.getOpcode() != OPCODE_PING) {
            throw new IllegalArgumentException("This is not a ping message!");
        }
        return new WebSocketMessage(OPCODE_PONG, ping.bytes);
    }

    private final int opcode;
    private final byte[] bytes;

    public boolean isText() {
        return opcode == OPCODE_TEXT;
    }

    public boolean isBinary() {
        return opcode == OPCODE_BINARY;
    }

    public boolean isControlMessage() {
        return opcode >= 0x8;
    }

    public int getOpcode() {
        return opcode;
    }

    public int getLength() {
        return bytes.length;
    }

    public byte[] getBytes() {
        byte[] b = new byte[bytes.length];
        System.arraycopy(bytes, 0, b, 0, bytes.length);
        return b;
    }

    public void getBytes(byte[] b) {
        System.arraycopy(bytes, 0, b, 0, Math.min(bytes.length, b.length));
    }

    void copyTo(byte[] destination, int offset) {
        System.arraycopy(bytes, 0, destination, offset, bytes.length);
    }

    public String getText() {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
