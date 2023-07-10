package xyz.juicebox.sdk.internal;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import xyz.juicebox.sdk.DeleteException;
import xyz.juicebox.sdk.PinHashingMode;
import xyz.juicebox.sdk.Realm;
import xyz.juicebox.sdk.RealmId;
import xyz.juicebox.sdk.RecoverException;
import xyz.juicebox.sdk.RegisterException;

public final class Native {

    static {
        System.loadLibrary("juicebox_sdk_jni");
    }

    public static native long clientCreate(
            long configuration,
            @NotNull long[] previousConfigurations,
            @NotNull GetAuthTokenFn getAuthToken,
            @NotNull HttpSendFn httpSend);

    public static native void clientDestroy(long client);

    public static native long configurationCreate(
            @NotNull Realm[] realms,
            int registerThreshold,
            int recoverThreshold,
            @NotNull PinHashingMode pinHashingMode);

    public static native boolean configurationsAreEqual(long configuration1, long configuration2);

    public static native long configurationCreateFromJson(String json);

    public static native void configurationDestroy(long configuration);

    public static native void clientRegister(
            long client,
            @NotNull byte[] pin,
            @NotNull byte[] secret,
            @NotNull byte[] info,
            short numGuesses) throws RegisterException;

    public static native @NotNull byte[] clientRecover(
            long client,
            @NotNull byte[] pin,
            @NotNull byte[] info) throws RecoverException;

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
        void get(long context, long contextId, @NotNull RealmId realmId);
    }
}
