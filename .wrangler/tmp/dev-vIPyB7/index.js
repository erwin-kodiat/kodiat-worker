// .wrangler/tmp/bundle-kFIJB6/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}

// node_modules/@tsndr/cloudflare-worker-jwt/index.js
if (typeof crypto === "undefined" || !crypto.subtle)
  throw new Error("SubtleCrypto not supported!");
var algorithms = {
  ES256: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
  ES384: { name: "ECDSA", namedCurve: "P-384", hash: { name: "SHA-384" } },
  ES512: { name: "ECDSA", namedCurve: "P-521", hash: { name: "SHA-512" } },
  HS256: { name: "HMAC", hash: { name: "SHA-256" } },
  HS384: { name: "HMAC", hash: { name: "SHA-384" } },
  HS512: { name: "HMAC", hash: { name: "SHA-512" } },
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
  RS384: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-384" } },
  RS512: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-512" } }
};
function bytesToByteString(bytes) {
  let byteStr = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    byteStr += String.fromCharCode(bytes[i]);
  }
  return byteStr;
}
function byteStringToBytes(byteStr) {
  let bytes = new Uint8Array(byteStr.length);
  for (let i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes;
}
function arrayBufferToBase64String(arrayBuffer) {
  return btoa(bytesToByteString(new Uint8Array(arrayBuffer)));
}
function base64StringToArrayBuffer(b64str) {
  return byteStringToBytes(atob(b64str)).buffer;
}
function textToArrayBuffer(str) {
  return byteStringToBytes(decodeURI(encodeURIComponent(str)));
}
function arrayBufferToBase64Url(arrayBuffer) {
  return arrayBufferToBase64String(arrayBuffer).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function base64UrlToArrayBuffer(b64url) {
  return base64StringToArrayBuffer(b64url.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
}
function textToBase64Url(str) {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function pemToBinary(pem) {
  return base64StringToArrayBuffer(pem.replace(/-+(BEGIN|END).*/g, "").replace(/\s/g, ""));
}
async function importTextSecret(key, algorithm) {
  return await crypto.subtle.importKey("raw", textToArrayBuffer(key), algorithm, true, ["verify", "sign"]);
}
async function importJwk(key, algorithm) {
  return await crypto.subtle.importKey("jwk", key, algorithm, true, ["verify", "sign"]);
}
async function importPublicKey(key, algorithm) {
  return await crypto.subtle.importKey("spki", pemToBinary(key), algorithm, true, ["verify"]);
}
async function importPrivateKey(key, algorithm) {
  return await crypto.subtle.importKey("pkcs8", pemToBinary(key), algorithm, true, ["sign"]);
}
async function importKey(key, algorithm) {
  if (typeof key === "object")
    return importJwk(key, algorithm);
  if (typeof key !== "string")
    throw new Error("Unsupported key type!");
  if (key.includes("PUBLIC"))
    return importPublicKey(key, algorithm);
  if (key.includes("PRIVATE"))
    return importPrivateKey(key, algorithm);
  return importTextSecret(key, algorithm);
}
function decodePayload(raw) {
  try {
    return JSON.parse(atob(raw));
  } catch {
    return;
  }
}
async function sign(payload, secret, options = "HS256") {
  if (typeof options === "string")
    options = { algorithm: options };
  options = { algorithm: "HS256", header: { typ: "JWT" }, ...options };
  if (!payload || typeof payload !== "object")
    throw new Error("payload must be an object");
  if (!secret || typeof secret !== "string" && typeof secret !== "object")
    throw new Error("secret must be a string or a JWK object");
  if (typeof options.algorithm !== "string")
    throw new Error("options.algorithm must be a string");
  const algorithm = algorithms[options.algorithm];
  if (!algorithm)
    throw new Error("algorithm not found");
  if (!payload.iat)
    payload.iat = Math.floor(Date.now() / 1e3);
  const partialToken = `${textToBase64Url(JSON.stringify({ ...options.header, alg: options.algorithm }))}.${textToBase64Url(JSON.stringify(payload))}`;
  const key = await importKey(secret, algorithm);
  const signature = await crypto.subtle.sign(algorithm, key, textToArrayBuffer(partialToken));
  return `${partialToken}.${arrayBufferToBase64Url(signature)}`;
}
async function verify(token, secret, options = { algorithm: "HS256", throwError: false }) {
  if (typeof options === "string")
    options = { algorithm: options, throwError: false };
  options = { algorithm: "HS256", throwError: false, ...options };
  if (typeof token !== "string")
    throw new Error("token must be a string");
  if (typeof secret !== "string" && typeof secret !== "object")
    throw new Error("secret must be a string or a JWK object");
  if (typeof options.algorithm !== "string")
    throw new Error("options.algorithm must be a string");
  const tokenParts = token.split(".");
  if (tokenParts.length !== 3)
    throw new Error("token must consist of 3 parts");
  const algorithm = algorithms[options.algorithm];
  if (!algorithm)
    throw new Error("algorithm not found");
  const { payload } = decode(token);
  try {
    if (!payload)
      throw new Error("PARSE_ERROR");
    if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1e3))
      throw new Error("NOT_YET_VALID");
    if (payload.exp && payload.exp <= Math.floor(Date.now() / 1e3))
      throw new Error("EXPIRED");
    const key = await importKey(secret, algorithm);
    return await crypto.subtle.verify(algorithm, key, base64UrlToArrayBuffer(tokenParts[2]), textToArrayBuffer(`${tokenParts[0]}.${tokenParts[1]}`));
  } catch (err) {
    if (options.throwError)
      throw err;
    return false;
  }
}
function decode(token) {
  return {
    header: decodePayload(token.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")),
    payload: decodePayload(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))
  };
}
var cloudflare_worker_jwt_default = {
  sign,
  verify,
  decode
};

// src/budi.js
var budi_default = {
  name: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFmZjJlOWI5NWY1YmEwYjJlNjhlYzZmMGY0ZDllMzJmMjE2YjU4MWMzMzAyNjNlYWE3NjM2ODg4YmFjNGQxZmYifQ.eyJhdWQiOlsiMTg0NmZkNmU0NWMzMmVkNDQzMjI0NmYxZTRiMWMyNmM0M2U0ZDI1ZmI4YTIyMTU3MWNlMzBiNGVhOGJjNDQ1ZCJdLCJlbWFpbCI6ImVyd2luLmtvZGlhdEBnbWFpbC5jb20iLCJleHAiOjE3MDE2OTAyMzMsImlhdCI6MTcwMTYwMzgzMywibmJmIjoxNzAxNjAzODMzLCJpc3MiOiJodHRwczovL2tvZGlhdC5jbG91ZGZsYXJlYWNjZXNzLmNvbSIsInR5cGUiOiJhcHAiLCJpZGVudGl0eV9ub25jZSI6IlBhWUgyNkEwNE5GUUJCOUkiLCJzdWIiOiI5NDc5NmE5NS0zZGQzLTU0YTYtOTEzMC00OGIzZDBkYTMyY2MiLCJjb3VudHJ5IjoiSUQifQ.dw6vzA6OcFiSh6EqptvFyTsTEOG8SfheJkM_Ow7IHBvki6KoIgx9K5BVSBK1t7Ms7vTPX7s1WQuBrn7-6kS-0xIH5NAgjjOcxpV5OyDLG1CIThkoP9Yi5NqpKZ5FvyuL2AJ8wmZ2SgyuWs0lGfDV8ZjAslAtQC8J9cRF4nUlhaYdJwJoeErRMee3VGYe7mLgZgP34ec-IFzXDofZNskyWLHx4nTYAV94dl_3bOYQzvSt24FWYcrOqewls8T5MIusk9K330JHrX8XwXSSwt4VdnlVSHxx5PZLtmwRCtFNNsL-WPnNZInM_J8_HpKJp9ycbivCvhxaBsIyT-9oYCTs2Q"
};

// src/index.js
var src_default = {
  async fetch(request, env, ctx) {
    let userJwt = budi_default.name;
    const { payload } = cloudflare_worker_jwt_default.decode(userJwt);
    const dateTimestamp = new Date(payload.iat * 1e3).toISOString();
    const url = "https://restcountries.com/v3.1/alpha/" + payload.country;
    console.log("14");
    const response = await fetch(url, {
      headers: {
        "content-type": "application/json;charset=UTF-8"
      }
    });
    console.log("20");
    const namanya = await response.json();
    const countryName = namanya[0].name.common;
    console.log("countryName: " + countryName);
    const strCountry = '<a href="/secure/' + payload.country + '" class="text-blue-400 hover:underline">' + countryName + "</a>";
    var html = "<!DOCTYPE html>";
    html += "<head>";
    html += '<script src="https://cdn.tailwindcss.com"><\/script>';
    html += "</head>";
    html += "<body>";
    html += '<div class="h-screen flex items-center justify-center text-3xl text-gray-500">';
    html += `<p><span class="font-bold">${payload.email}</span> authenticated at <span class="font-bold">${dateTimestamp}</span> from <span class="font-bold">${strCountry}</span>`;
    html += '<br /><br />Go back <a href="/" class="text-blue-400 hover:underline">home</a>';
    html += "</p></div>";
    html += "</body>";
    return new Response(html, {
      headers: {
        "content-type": "text/html;charset=UTF-8"
      }
    });
  }
};

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
var jsonError = async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
};
var middleware_miniflare3_json_error_default = jsonError;
var wrap = void 0;

// .wrangler/tmp/bundle-kFIJB6/middleware-insertion-facade.js
var envWrappers = [wrap].filter(Boolean);
var facade = {
  ...src_default,
  envWrappers,
  middleware: [
    middleware_miniflare3_json_error_default,
    ...src_default.middleware ? src_default.middleware : []
  ].filter(Boolean)
};
var middleware_insertion_facade_default = facade;

// .wrangler/tmp/bundle-kFIJB6/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
var __facade_modules_fetch__ = function(request, env, ctx) {
  if (middleware_insertion_facade_default.fetch === void 0)
    throw new Error("Handler does not export a fetch() function.");
  return middleware_insertion_facade_default.fetch(request, env, ctx);
};
function getMaskedEnv(rawEnv) {
  let env = rawEnv;
  if (middleware_insertion_facade_default.envWrappers && middleware_insertion_facade_default.envWrappers.length > 0) {
    for (const wrapFn of middleware_insertion_facade_default.envWrappers) {
      env = wrapFn(env);
    }
  }
  return env;
}
var registeredMiddleware = false;
var facade2 = {
  ...middleware_insertion_facade_default.tail && {
    tail: maskHandlerEnv(middleware_insertion_facade_default.tail)
  },
  ...middleware_insertion_facade_default.trace && {
    trace: maskHandlerEnv(middleware_insertion_facade_default.trace)
  },
  ...middleware_insertion_facade_default.scheduled && {
    scheduled: maskHandlerEnv(middleware_insertion_facade_default.scheduled)
  },
  ...middleware_insertion_facade_default.queue && {
    queue: maskHandlerEnv(middleware_insertion_facade_default.queue)
  },
  ...middleware_insertion_facade_default.test && {
    test: maskHandlerEnv(middleware_insertion_facade_default.test)
  },
  ...middleware_insertion_facade_default.email && {
    email: maskHandlerEnv(middleware_insertion_facade_default.email)
  },
  fetch(request, rawEnv, ctx) {
    const env = getMaskedEnv(rawEnv);
    if (middleware_insertion_facade_default.middleware && middleware_insertion_facade_default.middleware.length > 0) {
      if (!registeredMiddleware) {
        registeredMiddleware = true;
        for (const middleware of middleware_insertion_facade_default.middleware) {
          __facade_register__(middleware);
        }
      }
      const __facade_modules_dispatch__ = function(type, init) {
        if (type === "scheduled" && middleware_insertion_facade_default.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return middleware_insertion_facade_default.scheduled(controller, env, ctx);
        }
      };
      return __facade_invoke__(
        request,
        env,
        ctx,
        __facade_modules_dispatch__,
        __facade_modules_fetch__
      );
    } else {
      return __facade_modules_fetch__(request, env, ctx);
    }
  }
};
function maskHandlerEnv(handler) {
  return (data, env, ctx) => handler(data, getMaskedEnv(env), ctx);
}
var middleware_loader_entry_default = facade2;
export {
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
