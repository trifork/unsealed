package com.trifork.unsealed;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;

public class WSHelper {
    public static String post(String body, String url, String action) throws IOException, InterruptedException {

        HttpClient client = HttpClient.newBuilder().version(Version.HTTP_1_1).followRedirects(Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20)).build();

        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
                .header("Content-Type", "text/xml; charset=utf-8").header("SOAPAction", "\"" + action + "\"")
                .POST(BodyPublishers.ofString(body)).build();

        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
        return response.body();
    }

}