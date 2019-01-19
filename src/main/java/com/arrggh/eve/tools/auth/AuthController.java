/*
 * The MIT License
 *
 * Copyright 2019 Andrew Norman.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.arrggh.eve.tools.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * @author Andrew Norman
 */
@RestController
public class AuthController {
    private Log log = LogFactory.getLog(AuthController.class);

    private static final String REDIRECT_URL = System.getenv("AUTH_SERVER_URL") + "/callback";

    private static final String CLIENT_ID = System.getenv("EVE_OAUTH_CLIENT_ID");
    private static final String SECRET_KEY = System.getenv("EVE_OAUTH_SECRET_KEY");

    private static final String SCOPE = "publicData esi-skills.read_skills.v1 esi-skills.read_skillqueue.v1 esi-wallet.read_character_wallet.v1 esi-universe.read_structures.v1 esi-assets.read_assets.v1 esi-markets.structure_markets.v1 esi-characters.read_standings.v1 esi-industry.read_character_jobs.v1 esi-markets.read_character_orders.v1 esi-characters.read_blueprints.v1 esi-contracts.read_character_contracts.v1 esi-clones.read_implants.v1";

    private final ObjectMapper mapper = new ObjectMapper();

    @RequestMapping(value = "/authorise", method = RequestMethod.GET)
    public ResponseEntity<Token> authorise(@RequestParam("state") String state) {
        log.info("Authorisation Request Received");
        try {
            URI uri = new URIBuilder() //
                    .setScheme("https") //
                    .setHost("login.eveonline.com") //
                    .setPath("oauth/authorize") //
                    .addParameter("response_type", "code") //
                    .addParameter("redirect_uri", REDIRECT_URL) //
                    .addParameter("client_id", CLIENT_ID) //
                    .addParameter("scope", SCOPE) //
                    .addParameter("state", state) //
                    .build();

            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(uri);

            log.info("Redirecting " + uri);

            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        } catch (URISyntaxException e) {
            log.error(e);
        }
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @RequestMapping(value = "/callback", method = RequestMethod.GET)
    public ResponseEntity<Token> callback(@RequestParam("code") String code, @RequestParam("state") String state) {
        log.info("Callback " + state);
        try {
            return executeTokenRequest(code, state, "authorization_code");
        } catch (Exception e) {
            log.error(e);
        }
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @RequestMapping("/refresh")
    public ResponseEntity<Token> refresh(@RequestParam("token") String oldToken, @RequestParam("state") String state) {
        log.info("Refreshing " + oldToken);
        try {
            return executeTokenRequest(oldToken, state, "refresh_token");
        } catch (Exception e) {
            log.error(e);
        }
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private ResponseEntity<Token> executeTokenRequest(@RequestParam("code") String code, @RequestParam("state") String state, String authorization_code) throws IOException, URISyntaxException {
        State clientState = mapper.readValue(Base64.getDecoder().decode(state), State.class);

        String pass = CLIENT_ID + ":" + SECRET_KEY;

        CloseableHttpClient httpclient = HttpClients.createDefault();

        HttpPost httpPost = new HttpPost("https://login.eveonline.com/oauth/token");
        httpPost.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(pass.getBytes()));
        List<NameValuePair> nvps = new ArrayList<>();
        nvps.add(new BasicNameValuePair("grant_type", authorization_code));
        nvps.add(new BasicNameValuePair("code", code));
        httpPost.setEntity(new UrlEncodedFormEntity(nvps));

        log.info("POST: " + httpPost);
        for (Header header : httpPost.getAllHeaders())
            log.info("H: " + header);

        Token token;
        CloseableHttpResponse response2 = httpclient.execute(httpPost);
        try {
            log.info("StatusLine: " + response2.getStatusLine());
            HttpEntity entity1 = response2.getEntity();
            String tokenStr = EntityUtils.toString(entity1);
            log.info("Token String: " + tokenStr);
            token = mapper.readValue(tokenStr, Token.class);
            EntityUtils.consume(entity1);
        } finally {
            response2.close();
        }

        String encodedToken = Base64.getEncoder().encodeToString(mapper.writeValueAsBytes(token));

        URI uri = new URIBuilder() //
                .setScheme("http") //
                .setHost("localhost") //
                .setPort(clientState.getPort()) //
                .addParameter("state", state) //
                .addParameter("token", encodedToken) //
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(uri);
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
}
