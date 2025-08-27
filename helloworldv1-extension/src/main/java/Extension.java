import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("HelloWorld-v1 Extension");

        // TODO Add your code here
        montoyaApi.http().registerHttpHandler(new HelloWorldHttpHandler(montoyaApi));
    }
}