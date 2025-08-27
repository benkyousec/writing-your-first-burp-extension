import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

class PaymentGatewayHttpHandler implements HttpHandler {
    private static final String SECRET_KEY = "mambo-mambo-omatsuri-mambo";
    
    private final Logging logging;
    private final ObjectMapper objectMapper;
    private final Base64.Encoder base64Encoder;

    private String timestamp;

    public PaymentGatewayHttpHandler(MontoyaApi api) {
        this.logging = api.logging();
        this.objectMapper = new ObjectMapper();
        this.base64Encoder = Base64.getEncoder().withoutPadding();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!requestToBeSent.headers().stream().map(HttpHeader::name).anyMatch(h -> h.trim().equals("Signature") || h.trim().equals("Timestamp"))) {
            return continueWith(requestToBeSent);
        }
        
        try {
            setTimestamp();
            HttpRequest modifiedRequest = requestToBeSent.withUpdatedHeader("Timestamp", getTimestamp());
            
            String signature = generateSignature(requestToBeSent);
            modifiedRequest = modifiedRequest.withUpdatedHeader("Signature", signature);

            String ref = "PT1" + generateRef();
            modifiedRequest = modifiedRequest.withUpdatedHeader("Ref", ref);
            
            return continueWith(modifiedRequest);
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                logging.logToError(element.toString());
            }
            return continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return continueWith(responseReceived);
    }

    private String generateSignature(HttpRequestToBeSent request) throws Exception {
        String headers = generateHeaders(request.path());
        String body = encodeBody(request.body());
        String signingInput = String.format("%s.%s", headers, body);
        String hmacSignature = generateHmacSignature(signingInput);
        return String.format("%s.%s", signingInput, hmacSignature);
    }

    private String generateHeaders(String path) throws JsonProcessingException {
        Map<String, String> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("type", "JWT");
        headers.put("uri", path);
        headers.put("iat", getTimestamp());

        byte[] headerBytes = objectMapper.writeValueAsBytes(headers);
        return base64Encoder.encodeToString(headerBytes);
    }

    private static String generateRef() {
        // Play around with this to get n bits that you want
        BigInteger b = new BigInteger(46, new Random());
        return String.valueOf(b);
    }
    
    private String encodeBody(ByteArray body) {
        byte[] bodyBytes = body.getBytes();
        return base64Encoder.encodeToString(bodyBytes);
    }

    private String getTimestamp() {
        return this.timestamp;
    }

    private void setTimestamp() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("ddMMyyyyHHmmss");
        String timestamp = now.format(dateTimeFormatter);
        this.timestamp = timestamp;
    }
    
    private String generateHmacSignature(String signingInput) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256");
        sha256Hmac.init(secretKey);
        
        byte[] digest = sha256Hmac.doFinal(signingInput.getBytes());
        return base64Encoder.encodeToString(digest);
    }
}