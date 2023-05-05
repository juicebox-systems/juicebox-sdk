package me.loam.sdk.internal;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.InputStream;
import me.loam.sdk.*;

public final class Native {

   static {
       System.loadLibrary("loam_sdk_jni");
   }

   public static native @NotNull long clientCreate(
       @NotNull Configuration configuration,
       @NotNull Configuration[] previousConfigurations,
       @NotNull String authToken,
       @NotNull HttpSendFn httpSend
   );

   public static native void clientDestroy(@NotNull long client);

   public static native void clientRegister(
       @NotNull long client,
       @NotNull byte[] pin,
       @NotNull byte[] secret,
       @NotNull short numGuesses
   ) throws RegisterException;

   public static native @NotNull byte[] clientRecover(
       @NotNull long client,
       @NotNull byte[] pin
   ) throws RecoverException;

   public static native void clientDelete(
       @NotNull long client
   ) throws DeleteException;

   public static native void httpClientRequestComplete(
       @NotNull long httpClient,
       @NotNull HttpResponse response
   );

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
       void send(@NotNull long httpClient, @NotNull HttpRequest request);
   }
}
