# Tapo Camera Node.js Client

A TypeScript/Node.js client for controlling Tapo cameras. Based on [pytapo](https://github.com/JurajNyiri/pytapo).

## Features

- Full TypeScript support
- Secure connection handling
- Comprehensive camera control API
- Event monitoring
- Video quality management
- LED control
- Privacy mode management
- Motor control for PTZ cameras
- SD card status
- Time and timezone management

## Installation

```bash
npm install tapo-camera-client-expo
```

## Usage

```typescript
import { TapoCamera } from 'tapo-camera-client-expo';

const camera = new TapoCamera({
    host: 'camera-ip',
    user: 'your-username',
    password: 'your-password'
});

await camera.init();

// Get LED status
const ledStatus = await camera.getLED();
console.log('LED Status:', ledStatus);

// Control camera movement (PTZ)
await camera.moveMotor(10, 20);

// Get privacy mode status
const privacyMode = await camera.getPrivacyMode();
console.log('Privacy Mode:', privacyMode);
```

## API Documentation

### Constructor Options

```typescript
{
    host: string;           // Camera IP address
    user: string;          // Username
    password: string;      // Password
    childID?: string;      // Optional child device ID
    reuseSession?: boolean; // Reuse session (default: true)
    printDebugInformation?: boolean; // Print debug info (default: false)
    controlPort?: number;  // Control port (default: 443)
    retryStok?: boolean;  // Retry authentication (default: true)
}
```

### Available Methods

- `init()`: Initialize the camera connection
- `getLED()`: Get LED status
- `setLEDEnabled(enabled: boolean)`: Set LED status
- `getPrivacyMode()`: Get privacy mode status
- `setPrivacyMode(enabled: boolean)`: Set privacy mode
- `moveMotor(x: number, y: number)`: Move camera to specific coordinates
- `getEvents()`: Get camera events
- `getVideoQualities()`: Get available video qualities
- `getSDCard()`: Get SD card information
- And many more...

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Test
npm test

# Lint
npm run lint
```

## Modify your `android` project

In order to make it work with self-signed Tapo API requests, it is needed to add these two files in:

`android/app/src/main/java/[your-app-id]/UnsafeHttpPackage.kt`
```kotlin
package com.displaynone.taponfc

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class UnsafeHttpPackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> {
        return listOf(UnsafeHttpModule(reactContext))
    }

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
        return emptyList()
    }
}
```

`android/app/src/main/java/[your-app-id]/UnsafeHttpModule.kt`
```kotlin
package com.displaynone.taponfc

import org.json.JSONObject
import org.json.JSONArray
import com.facebook.react.bridge.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Callback
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

class UnsafeHttpModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "UnsafeHttp"

    private fun getUnsafeOkHttpClient(): OkHttpClient {
        val trustAllCerts = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
        )

        val sslContext = SSLContext.getInstance("SSL")
        sslContext.init(null, trustAllCerts, SecureRandom())
        val sslSocketFactory = sslContext.socketFactory

        return OkHttpClient.Builder()
            .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    @ReactMethod
    fun getJson(url: String, options: ReadableMap, promise: Promise) {
        try {
            val method = options.getString("method") ?: "GET"
            val headersMap = options.getMap("headers")
            var bodyContent: String? = null

            if (options.hasKey("body")) {
                val bodyType = options.getType("body")
                bodyContent = when (bodyType) {
                    ReadableType.Map -> JSONObject(options.getMap("body")!!.toHashMap() as Map<*, *>).toString()
                    ReadableType.Array -> JSONArray(options.getArray("body")!!.toArrayList()).toString()
                    ReadableType.String -> options.getString("body")
                    else -> null
                }
            }

            val builder = Request.Builder().url(url).method(
                method.uppercase(),
                when {
                    method.equals("GET", ignoreCase = true) || method.equals("DELETE", ignoreCase = true) -> null
                    bodyContent != null -> RequestBody.create("application/json".toMediaTypeOrNull(), bodyContent)
                    else -> RequestBody.create(null, ByteArray(0))
                }
            )

            headersMap?.entryIterator?.forEach { entry ->
                builder.addHeader(entry.key, entry.value.toString())
            }

            val request = builder.build()
            val client = getUnsafeOkHttpClient()

            client.newCall(request).enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    promise.reject("NETWORK_ERROR", e.message)
                }

                override fun onResponse(call: Call, response: Response) {
                    val bodyStr = response.body?.string()
                    val resultMap = Arguments.createMap()
                    resultMap.putInt("status", response.code)

                    try {
                        if (bodyStr != null) {
                            val json = JSONObject(bodyStr)
                            val parsed = jsonToWritableMap(json)
                            resultMap.putMap("result", parsed)
                        } else {
                            resultMap.putNull("result")
                        }
                        promise.resolve(resultMap)
                    } catch (e: Exception) {
                        promise.reject("JSON_PARSE_ERROR", e.message)
                    }
                }
            })
        } catch (e: Exception) {
            promise.reject("INTERNAL_ERROR", e.message)
        }
    }

    private fun jsonToWritableMap(jsonObject: JSONObject): WritableMap {
        val map = Arguments.createMap()
        val keys = jsonObject.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            when (val value = jsonObject.get(key)) {
                is Boolean -> map.putBoolean(key, value)
                is Int -> map.putInt(key, value)
                is Double -> map.putDouble(key, value)
                is Long -> map.putDouble(key, value.toDouble())
                is String -> map.putString(key, value)
                is JSONObject -> map.putMap(key, jsonToWritableMap(value))
                is JSONArray -> map.putArray(key, jsonToWritableArray(value))
                else -> map.putString(key, value.toString())
            }
        }
        return map
    }

    private fun jsonToWritableArray(jsonArray: JSONArray): WritableArray {
        val array = Arguments.createArray()
        for (i in 0 until jsonArray.length()) {
            when (val value = jsonArray.get(i)) {
                is Boolean -> array.pushBoolean(value)
                is Int -> array.pushInt(value)
                is Double -> array.pushDouble(value)
                is Long -> array.pushDouble(value.toDouble())
                is String -> array.pushString(value)
                is JSONObject -> array.pushMap(jsonToWritableMap(value))
                is JSONArray -> array.pushArray(jsonToWritableArray(value))
                else -> array.pushString(value.toString())
            }
        }
        return array
    }
}
```
## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
