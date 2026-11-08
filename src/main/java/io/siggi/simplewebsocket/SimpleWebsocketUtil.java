package io.siggi.simplewebsocket;

import io.siggi.http.HTTPRequest;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class SimpleWebsocketUtil {
    static SimpleWebsocket connect(URI uri, WebsocketHeaders requestHeaders) throws IOException {
        if (requestHeaders == null) requestHeaders = new WebsocketHeaders();
        String scheme = uri.getScheme().toLowerCase();
        if (!scheme.equals("ws") && !scheme.equals("wss"))
            throw new IllegalArgumentException("Scheme must be ws or wss.");
        boolean secure = scheme.equals("wss");
        String host = uri.getHost();
        int port = uri.getPort();
        int defaultPort = secure ? 443 : 80;
        if (port == -1)
            port = defaultPort;
        String path = uri.getPath();

        Socket socket;

        if (secure) {
            socket = SSLSocketFactory.getDefault().createSocket(host, port);
        } else {
            socket = new Socket(host, port);
        }

        boolean success = false;
        try {
            if (socket instanceof SSLSocket) {
                // SSLSocket only checks the certificate chain, not that the certificate is for this host.
                SSLSocket sslSocket = (SSLSocket) socket;
                SSLParameters parameters = sslSocket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                sslSocket.setSSLParameters(parameters);
                sslSocket.startHandshake();
            }

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            String nonce = Util.generateNonce();
            String expectedResponse = Util.generateExpectedResponse(nonce);

            String requestPath = uri.toString();
            int position = requestPath.indexOf("/", requestPath.indexOf("//") + 2);
            requestPath = position == -1 ? "/" : requestPath.substring(position);
            if (requestPath.contains("#")) requestPath = requestPath.substring(0, requestPath.indexOf("#"));

            writeLine(out, "GET " + requestPath + " HTTP/1.1");
            writeLine(out, "Host: " + host + (port == defaultPort ? "" : (":" + port)));
            writeLine(out, "Sec-WebSocket-Key: " + nonce);
            writeLine(out, "Sec-WebSocket-Version: 13");
            for (Map.Entry<String, List<String>> entry : requestHeaders.getHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    writeLine(out, entry.getKey() + ": " + value);
                }
            }
            writeLine(out, "");

            String firstLine = readLine(in);
            if (!firstLine.contains("101")) {
                throw new IOException("Server does not support WebSocket");
            }
            Map<String, String> headers = readHeaders(in);

            String response = headers.get("sec-websocket-accept");
            if (!expectedResponse.equals(response)) {
                throw new IOException("Server does not support WebSocket");
            }
            success = true;
            return new SimpleWebsocket(socket, true);
        } finally {
            if (!success) {
                try {
                    socket.close();
                } catch (Exception e) {
                }
            }
        }
    }

    static SimpleWebsocket accept(HTTPRequest request) throws IOException {
        if (!isWebsocketRequest(request))
            throw new IOException("Not a Websocket request.");
        String webSocketKey = request.getHeader("Sec-WebSocket-Key");

        request.response.setHeader("Sec-WebSocket-Accept", Util.generateExpectedResponse(webSocketKey));

        return new SimpleWebsocket(request.response.upgradeConnection("websocket"), false);
    }

    static boolean isWebsocketRequest(HTTPRequest request) {
        // Connection and Upgrade are comma separated lists, e.g. Firefox sends "Connection: keep-alive, Upgrade".
        return hasToken(request.getHeader("Connection"), "Upgrade")
                && hasToken(request.getHeader("Upgrade"), "websocket")
                && request.getHeader("Sec-WebSocket-Key") != null;
    }

    private static boolean hasToken(String headerValue, String token) {
        if (headerValue == null) return false;
        for (String part : headerValue.split(",")) {
            if (part.trim().equalsIgnoreCase(token)) return true;
        }
        return false;
    }

    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        HashMap<String, String> map = new HashMap<>();
        String line;
        while ((line = readLine(in)) != null) {
            if (line.isEmpty())
                break;
            int colonPos = line.indexOf(":");
            if (colonPos >= 0) {
                String key = line.substring(0, colonPos).trim();
                String value = line.substring(colonPos + 1).trim();
                map.put(key.toLowerCase(), value);
            }
        }
        return map;
    }

    private static String readLine(InputStream in) throws IOException {
        byte[] bytes = new byte[256];
        int c;
        int read = 0;
        boolean readSomething = false;
        while ((c = in.read()) != -1) {
            readSomething = true;
            if (c == 0x0A) {
                if (read > 0 && bytes[read - 1] == (byte) 0x0D) {
                    read -= 1;
                }
                break;
            }
            if (read >= bytes.length) {
                bytes = Arrays.copyOf(bytes, bytes.length * 2);
            }
            bytes[read++] = (byte) c;
        }
        if (!readSomething) {
            return null;
        }
        return new String(bytes, 0, read, StandardCharsets.UTF_8);
    }

    private static void writeLine(OutputStream out, String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
    }
}
