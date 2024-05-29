package com.trifork.unsealed;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Helper class for testing with OpenID Connect.
 */
public class OIDC {
     static final Logger log = Logger.getLogger(OIDC.class.getName());

    private static String AUTHORIZATION_ENDPOINT = "https://oidc-test.hosted.trifork.com/auth/realms/sds/protocol/openid-connect/auth";
    private static String TOKEN_ENDPOINT = "https://oidc-test.hosted.trifork.com/auth/realms/sds/protocol/openid-connect/token";

    private static String CLIENT_ID = "fmk_mock";
    private static String REDIRECT_URL = "medicinkortetapp://fmk-test1";
    private static String SCOPE = "openid fmk sosi-sts profile eventbox";


    public static String authenticate(String cpr) {
        return OIDC.authenticate(cpr, "pid" + cpr, "Mokey Mick");
    }

    public static String authenticate(String cpr, String pid, String name) {
        try {
            CookieManager cookieManager = new CookieManager();
            HttpClient httpClient = HttpClient.newBuilder().cookieHandler(cookieManager).build();

            String postActionUrl = codeflow_step1a_authenticationRequest(httpClient, CLIENT_ID, REDIRECT_URL, SCOPE);
            String code = codeflow_step1b_authenticationResponse(httpClient, postActionUrl, cpr, pid, name);
            String accessToken = codeflow_step2_getAccessTokenFromCode(httpClient, REDIRECT_URL, CLIENT_ID, code);

            return accessToken;
        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }

    private static String codeflow_step1a_authenticationRequest(HttpClient httpClient, String clientID,
                                                                String redirectUrl, String scope) throws IOException, InterruptedException {

        long nonce = (long) (Math.random() * 10000000L);
        String url = AUTHORIZATION_ENDPOINT + "?response_type=code" + "&client_id="
                + URLEncoder.encode(clientID, "UTF-8") + "&redirect_uri=" + redirectUrl + "&scope="
                + URLEncoder.encode(scope, "UTF-8") + "&state=state-1234" + "&nonce=" + nonce;
        log.info("Authenticating using url : " + url);

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 400) {
            throw new RuntimeException("Auth request failed with status=" + response.statusCode());
        }

        String responseBody = response.body();
        String postActionUrl = extractFormAction(responseBody);
        System.out.println("Step1a - postActionUrl=" + postActionUrl);
        return postActionUrl;
    }

    private static String codeflow_step1b_authenticationResponse(HttpClient httpClient, String postActionUrl,
                                                                 String cpr, String pid, String name) throws IOException, InterruptedException, URISyntaxException {

        String subdnOld = "CN=" + name + " + SERIALNUMBER=PID:" + pid
                + ",O=Ingen organisatorisk tilknytning, C=DK";

        String uuid = "47ac10b-58cc-4372-a567-0e02b2c3d479";
        String subdn = "CN=" + name + ", SERIALNUMBER=UI:DK-P:G:" + uuid;

        String responseJsonValue = constructMockAuthResponse(name, pid, cpr, subdn);

        List<NameValuePair> form = new ArrayList<>();
        form.add(new NameValuePair("response", responseJsonValue));
        String formBody = form.stream()
                .map(p -> URLEncoder.encode(p.getName(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(p.getValue(), StandardCharsets.UTF_8))
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(postActionUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody)).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 400) {
            throw new RuntimeException("Auth response failed with status=" + response.statusCode());
        }

        String locationHeader = response.headers().firstValue("Location").orElse(null);

        if (locationHeader != null && locationHeader.contains("execution=OAUTH_GRANT")) {
            response = grantPrivileges(httpClient, locationHeader);
        }

        String code = getAuthCodeFromReponse(response);
        log.info("Step1b - code=" + code);
        return code;
    }

    private static HttpResponse<String> grantPrivileges(HttpClient httpClient, String location)
            throws IOException, URISyntaxException, InterruptedException {

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(location)).build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String html = response.body();
        String postActionFromForm = extractFormAction(html);
        URI postActionURI = new URL(new URL(location), postActionFromForm).toURI();
        String codeFromForm = extractFormValue(html, "code");

        List<NameValuePair> form3 = new ArrayList<>();
        form3.add(new NameValuePair("code", codeFromForm));
        form3.add(new NameValuePair("accept", "Yes"));
        String formBody = form3.stream()
                .map(p -> URLEncoder.encode(p.getName(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(p.getValue(), StandardCharsets.UTF_8))
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");
        HttpRequest request3 = HttpRequest.newBuilder().uri(postActionURI)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody)).build();
        response = httpClient.send(request3, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 400) {
            throw new RuntimeException("Grant privileges request failed with status=" + response.statusCode());
        }

        return response;
    }

    private static String codeflow_step2_getAccessTokenFromCode(HttpClient httpClient, String redirect_uri,
            String client_id, String code) throws IOException, InterruptedException {

        List<NameValuePair> form = new ArrayList<>();
        form.add(new NameValuePair("grant_type", "authorization_code"));
        form.add(new NameValuePair("code", code));
        form.add(new NameValuePair("redirect_uri", redirect_uri));
        form.add(new NameValuePair("client_id", client_id));
        String formBody = form.stream()
                .map(p -> URLEncoder.encode(p.getName(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(p.getValue(), StandardCharsets.UTF_8))
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody)).build();

        HttpResponse<String> tokenResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        var pattern = Pattern.compile("\"access_token\":\"([^\"]*)\"");
        var matcher = pattern.matcher(tokenResponse.body());
        if (matcher.find()) {
            var accessToken = matcher.group(1);
            if (accessToken != null) {
                return accessToken;
            }
        }

        return null;
        // JsonReader jsonReader = Json.createReader(new StringReader(tokenResponse.body()));
        // var jsonObject = jsonReader.readObject();
        // var accessToken = jsonObject.getString("access_token");

        // log.debug("Tokens: " + jsonObject.toString());
        // return accessToken;
    }

    private static String getAuthCodeFromReponse(HttpResponse<String> response) {
        int status = response.statusCode();
        String location = response.headers().firstValue("Location").orElse(null);

        if (status >= 200 && status <= 400 && location != null) {
            String returnUrl = location;
            return getCodeFromReturnUrl(returnUrl);
        } else {
            throw new RuntimeException("No location header in response, " + "status=" + status);
        }
    }

    private static String getCodeFromReturnUrl(String returnUrl) {
        try {
            var code = getQueryParameters(new URI(returnUrl)).get("code");
            log.fine("Code : " + code);
            if (code == null) {
                throw new RuntimeException("No code in returnuri : " + returnUrl);
            }
            return code;
        } catch (URISyntaxException e) {
            throw new RuntimeException("Unable to parse : " + returnUrl, e);
        }
    }

    private static Map<String, String> getQueryParameters(URI uri) {
        String query = uri.getQuery();
        // Split the query string into individual parameters
        String[] pairs = query.split("&");

        // Create a Map to store the parameter key-value pairs
        Map<String, String> params = Arrays.stream(pairs)
                .map(s -> s.split("="))
                .collect(Collectors.toMap(
                        arr -> decode(arr[0]),
                        arr -> decode(arr.length > 1 ? arr[1] : "")
                ));

        return params;
    }

    private static String decode(String value) {
        try {
            // URL decode the parameter values
            return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            // Handle the exception according to your requirements
            throw new RuntimeException("Error decoding URL parameter", e);
        }
    }

    private static Pattern actionPattern = Pattern.compile("action=\"([^\"]+)\"");
    private static String extractFormAction(String html) {
        Matcher m = actionPattern.matcher(html);
        if (m.find()) {
            String postBackUrl = m.group(1);
            //postBackUrl = Jsoup.parse(postBackUrl).text();
            return postBackUrl;
        }
        throw new IllegalStateException("Expected to find an 'action' in a form in this html: " + html);
    }

    private static Pattern codePattern = Pattern.compile(
            "<input type=\"hidden\" name=\"code\" value=\"([^\"]+)\">");
    private static String extractFormValue(String html, String name) {
        Matcher m = codePattern.matcher(html);
        if (m.find()) {
            return m.group(1);
        }
        throw new IllegalStateException("Expected to find a 'code' in a form in this html: " + html);
    }

    private static String constructMockAuthResponse(String name, String pid, String cpr, String subdn) {
        return "{\"result\":\"ok\", " + "\"name\":\"" + name + "\", " + "\"pid\":\"" + pid + "\", "
                + "\"cpr\":\"" + cpr + "\", " + "\"subdn\":\"" + subdn + "\", " + "\"desc\":\"\", "
                + "\"techdesc\":\"\"}";
    }

    private static class NameValuePair {
        private final String name;
        private final String value;

        public NameValuePair(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }
    }
}
