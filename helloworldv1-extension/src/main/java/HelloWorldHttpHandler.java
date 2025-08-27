import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import java.math.BigInteger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;

public class HelloWorldHttpHandler implements HttpHandler {
    private final Logging logging;
    private final MontoyaApi api;

    public HelloWorldHttpHandler(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // If Signature header is set
        if (requestToBeSent.headers().stream().map(HttpHeader::name).anyMatch(h -> h.trim().equals("Signature"))) {
            ByteArray body = requestToBeSent.body();
            CryptoUtils cryptoUtils = api.utilities().cryptoUtils();
            ByteArray sha256hash = cryptoUtils.generateDigest(body, DigestAlgorithm.SHA_256);
            // format hexstring https://stackoverflow.com/a/3103722/17064199
            String digest = String.format("%064x", new BigInteger(1, sha256hash.getBytes()));
            logging.logToOutput("Calculated signature: " + digest);
            HttpRequest modifiedRequest = requestToBeSent.withUpdatedHeader("Signature", digest);
            return continueWith(modifiedRequest);
        }
        return continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return continueWith(responseReceived);
    }
    
}
