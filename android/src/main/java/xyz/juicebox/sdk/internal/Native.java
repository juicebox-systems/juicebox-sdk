package xyz.juicebox.sdk.internal;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.InputStream;
import xyz.juicebox.sdk.*;

public final class Native {

    static {
        System.loadLibrary("juicebox_sdk_jni");
    }

    public static native long clientCreate(
            @NotNull Configuration configuration,
            @NotNull Configuration[] previousConfigurations,
            @NotNull GetAuthTokenFn getAuthToken,
            @NotNull HttpSendFn httpSend);

    public static native void clientDestroy(long client);

    public static native void clientRegister(
            long client,
            @NotNull byte[] pin,
            @NotNull byte[] secret,
            short numGuesses) throws RegisterException;

    public static native @NotNull byte[] clientRecover(
            long client,
            @NotNull byte[] pin) throws RecoverException;

    public static native void clientDelete(
            long client) throws DeleteException;

    public static native void httpClientRequestComplete(
            long httpClient,
            @NotNull HttpResponse response);

    public static native void authTokenGetComplete(
            long context,
            long contextId,
            @Nullable String authToken);

    public static class HttpHeader {
        @NotNull
        public String name;
        @NotNull
        public String value;

        public HttpHeader(@NotNull String name, @NotNull String value) {
            this.name = name;
            this.value = value;
        }
    }

    public static class HttpRequest {
        @NotNull
        public byte[] id;
        @NotNull
        public String method;
        @NotNull
        public String url;
        @Nullable
        public HttpHeader[] headers;
        @Nullable
        public byte[] body;
    }

    public static class HttpResponse {
        @NotNull
        public byte[] id;
        @NotNull
        public short statusCode;
        @NotNull
        public HttpHeader[] headers;
        @NotNull
        public byte[] body;
    }

    public interface HttpSendFn {
        void send(long httpClient, @NotNull HttpRequest request);
    }

    public interface GetAuthTokenFn {
        void get(long context, long contextId, @NotNull byte[] realmId);
    }
}
