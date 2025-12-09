import crypto$2 from "crypto";
import bcrypt from "bcrypt";
import require$$0 from "buffer";
import require$$3 from "stream";
import require$$5 from "util";
import _ from "lodash";
import path from "path";
import fs from "fs";
import { factories } from "@strapi/strapi";
import utils from "@strapi/utils";
import { UnauthorizedError as UnauthorizedError$2 } from "@strapi/utils/dist/errors";
import qs from "qs";
function getDefaultExportFromCjs(x) {
  return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, "default") ? x["default"] : x;
}
var jsonwebtoken = { exports: {} };
var JsonWebTokenError$3 = function(message, error) {
  Error.call(this, message);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  }
  this.name = "JsonWebTokenError";
  this.message = message;
  if (error) this.inner = error;
};
JsonWebTokenError$3.prototype = Object.create(Error.prototype);
JsonWebTokenError$3.prototype.constructor = JsonWebTokenError$3;
var JsonWebTokenError_1 = JsonWebTokenError$3;
var JsonWebTokenError$2 = JsonWebTokenError_1;
var NotBeforeError$1 = function(message, date) {
  JsonWebTokenError$2.call(this, message);
  this.name = "NotBeforeError";
  this.date = date;
};
NotBeforeError$1.prototype = Object.create(JsonWebTokenError$2.prototype);
NotBeforeError$1.prototype.constructor = NotBeforeError$1;
var NotBeforeError_1 = NotBeforeError$1;
var JsonWebTokenError$1 = JsonWebTokenError_1;
var TokenExpiredError$1 = function(message, expiredAt) {
  JsonWebTokenError$1.call(this, message);
  this.name = "TokenExpiredError";
  this.expiredAt = expiredAt;
};
TokenExpiredError$1.prototype = Object.create(JsonWebTokenError$1.prototype);
TokenExpiredError$1.prototype.constructor = TokenExpiredError$1;
var TokenExpiredError_1 = TokenExpiredError$1;
var jws$3 = {};
var safeBuffer = { exports: {} };
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
(function(module, exports$1) {
  var buffer = require$$0;
  var Buffer2 = buffer.Buffer;
  function copyProps(src, dst) {
    for (var key in src) {
      dst[key] = src[key];
    }
  }
  if (Buffer2.from && Buffer2.alloc && Buffer2.allocUnsafe && Buffer2.allocUnsafeSlow) {
    module.exports = buffer;
  } else {
    copyProps(buffer, exports$1);
    exports$1.Buffer = SafeBuffer;
  }
  function SafeBuffer(arg, encodingOrOffset, length) {
    return Buffer2(arg, encodingOrOffset, length);
  }
  SafeBuffer.prototype = Object.create(Buffer2.prototype);
  copyProps(Buffer2, SafeBuffer);
  SafeBuffer.from = function(arg, encodingOrOffset, length) {
    if (typeof arg === "number") {
      throw new TypeError("Argument must not be a number");
    }
    return Buffer2(arg, encodingOrOffset, length);
  };
  SafeBuffer.alloc = function(size, fill, encoding) {
    if (typeof size !== "number") {
      throw new TypeError("Argument must be a number");
    }
    var buf = Buffer2(size);
    if (fill !== void 0) {
      if (typeof encoding === "string") {
        buf.fill(fill, encoding);
      } else {
        buf.fill(fill);
      }
    } else {
      buf.fill(0);
    }
    return buf;
  };
  SafeBuffer.allocUnsafe = function(size) {
    if (typeof size !== "number") {
      throw new TypeError("Argument must be a number");
    }
    return Buffer2(size);
  };
  SafeBuffer.allocUnsafeSlow = function(size) {
    if (typeof size !== "number") {
      throw new TypeError("Argument must be a number");
    }
    return buffer.SlowBuffer(size);
  };
})(safeBuffer, safeBuffer.exports);
var safeBufferExports = safeBuffer.exports;
var Buffer$6 = safeBufferExports.Buffer;
var Stream$2 = require$$3;
var util$3 = require$$5;
function DataStream$2(data) {
  this.buffer = null;
  this.writable = true;
  this.readable = true;
  if (!data) {
    this.buffer = Buffer$6.alloc(0);
    return this;
  }
  if (typeof data.pipe === "function") {
    this.buffer = Buffer$6.alloc(0);
    data.pipe(this);
    return this;
  }
  if (data.length || typeof data === "object") {
    this.buffer = data;
    this.writable = false;
    process.nextTick(function() {
      this.emit("end", data);
      this.readable = false;
      this.emit("close");
    }.bind(this));
    return this;
  }
  throw new TypeError("Unexpected data type (" + typeof data + ")");
}
util$3.inherits(DataStream$2, Stream$2);
DataStream$2.prototype.write = function write(data) {
  this.buffer = Buffer$6.concat([this.buffer, Buffer$6.from(data)]);
  this.emit("data", data);
};
DataStream$2.prototype.end = function end(data) {
  if (data)
    this.write(data);
  this.emit("end", data);
  this.emit("close");
  this.writable = false;
  this.readable = false;
};
var dataStream = DataStream$2;
function getParamSize(keySize) {
  var result = (keySize / 8 | 0) + (keySize % 8 === 0 ? 0 : 1);
  return result;
}
var paramBytesForAlg = {
  ES256: getParamSize(256),
  ES384: getParamSize(384),
  ES512: getParamSize(521)
};
function getParamBytesForAlg$1(alg) {
  var paramBytes = paramBytesForAlg[alg];
  if (paramBytes) {
    return paramBytes;
  }
  throw new Error('Unknown algorithm "' + alg + '"');
}
var paramBytesForAlg_1 = getParamBytesForAlg$1;
var Buffer$5 = safeBufferExports.Buffer;
var getParamBytesForAlg = paramBytesForAlg_1;
var MAX_OCTET = 128, CLASS_UNIVERSAL = 0, PRIMITIVE_BIT = 32, TAG_SEQ = 16, TAG_INT = 2, ENCODED_TAG_SEQ = TAG_SEQ | PRIMITIVE_BIT | CLASS_UNIVERSAL << 6, ENCODED_TAG_INT = TAG_INT | CLASS_UNIVERSAL << 6;
function base64Url(base64) {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function signatureAsBuffer(signature) {
  if (Buffer$5.isBuffer(signature)) {
    return signature;
  } else if ("string" === typeof signature) {
    return Buffer$5.from(signature, "base64");
  }
  throw new TypeError("ECDSA signature must be a Base64 string or a Buffer");
}
function derToJose(signature, alg) {
  signature = signatureAsBuffer(signature);
  var paramBytes = getParamBytesForAlg(alg);
  var maxEncodedParamLength = paramBytes + 1;
  var inputLength = signature.length;
  var offset = 0;
  if (signature[offset++] !== ENCODED_TAG_SEQ) {
    throw new Error('Could not find expected "seq"');
  }
  var seqLength = signature[offset++];
  if (seqLength === (MAX_OCTET | 1)) {
    seqLength = signature[offset++];
  }
  if (inputLength - offset < seqLength) {
    throw new Error('"seq" specified length of "' + seqLength + '", only "' + (inputLength - offset) + '" remaining');
  }
  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "r"');
  }
  var rLength = signature[offset++];
  if (inputLength - offset - 2 < rLength) {
    throw new Error('"r" specified length of "' + rLength + '", only "' + (inputLength - offset - 2) + '" available');
  }
  if (maxEncodedParamLength < rLength) {
    throw new Error('"r" specified length of "' + rLength + '", max of "' + maxEncodedParamLength + '" is acceptable');
  }
  var rOffset = offset;
  offset += rLength;
  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "s"');
  }
  var sLength = signature[offset++];
  if (inputLength - offset !== sLength) {
    throw new Error('"s" specified length of "' + sLength + '", expected "' + (inputLength - offset) + '"');
  }
  if (maxEncodedParamLength < sLength) {
    throw new Error('"s" specified length of "' + sLength + '", max of "' + maxEncodedParamLength + '" is acceptable');
  }
  var sOffset = offset;
  offset += sLength;
  if (offset !== inputLength) {
    throw new Error('Expected to consume entire buffer, but "' + (inputLength - offset) + '" bytes remain');
  }
  var rPadding = paramBytes - rLength, sPadding = paramBytes - sLength;
  var dst = Buffer$5.allocUnsafe(rPadding + rLength + sPadding + sLength);
  for (offset = 0; offset < rPadding; ++offset) {
    dst[offset] = 0;
  }
  signature.copy(dst, offset, rOffset + Math.max(-rPadding, 0), rOffset + rLength);
  offset = paramBytes;
  for (var o = offset; offset < o + sPadding; ++offset) {
    dst[offset] = 0;
  }
  signature.copy(dst, offset, sOffset + Math.max(-sPadding, 0), sOffset + sLength);
  dst = dst.toString("base64");
  dst = base64Url(dst);
  return dst;
}
function countPadding(buf, start, stop) {
  var padding = 0;
  while (start + padding < stop && buf[start + padding] === 0) {
    ++padding;
  }
  var needsSign = buf[start + padding] >= MAX_OCTET;
  if (needsSign) {
    --padding;
  }
  return padding;
}
function joseToDer(signature, alg) {
  signature = signatureAsBuffer(signature);
  var paramBytes = getParamBytesForAlg(alg);
  var signatureBytes = signature.length;
  if (signatureBytes !== paramBytes * 2) {
    throw new TypeError('"' + alg + '" signatures must be "' + paramBytes * 2 + '" bytes, saw "' + signatureBytes + '"');
  }
  var rPadding = countPadding(signature, 0, paramBytes);
  var sPadding = countPadding(signature, paramBytes, signature.length);
  var rLength = paramBytes - rPadding;
  var sLength = paramBytes - sPadding;
  var rsBytes = 1 + 1 + rLength + 1 + 1 + sLength;
  var shortLength = rsBytes < MAX_OCTET;
  var dst = Buffer$5.allocUnsafe((shortLength ? 2 : 3) + rsBytes);
  var offset = 0;
  dst[offset++] = ENCODED_TAG_SEQ;
  if (shortLength) {
    dst[offset++] = rsBytes;
  } else {
    dst[offset++] = MAX_OCTET | 1;
    dst[offset++] = rsBytes & 255;
  }
  dst[offset++] = ENCODED_TAG_INT;
  dst[offset++] = rLength;
  if (rPadding < 0) {
    dst[offset++] = 0;
    offset += signature.copy(dst, offset, 0, paramBytes);
  } else {
    offset += signature.copy(dst, offset, rPadding, paramBytes);
  }
  dst[offset++] = ENCODED_TAG_INT;
  dst[offset++] = sLength;
  if (sPadding < 0) {
    dst[offset++] = 0;
    signature.copy(dst, offset, paramBytes);
  } else {
    signature.copy(dst, offset, paramBytes + sPadding);
  }
  return dst;
}
var ecdsaSigFormatter = {
  derToJose,
  joseToDer
};
var bufferEqualConstantTime;
var hasRequiredBufferEqualConstantTime;
function requireBufferEqualConstantTime() {
  if (hasRequiredBufferEqualConstantTime) return bufferEqualConstantTime;
  hasRequiredBufferEqualConstantTime = 1;
  var Buffer2 = require$$0.Buffer;
  var SlowBuffer = require$$0.SlowBuffer;
  bufferEqualConstantTime = bufferEq;
  function bufferEq(a, b) {
    if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b)) {
      return false;
    }
    if (a.length !== b.length) {
      return false;
    }
    var c = 0;
    for (var i = 0; i < a.length; i++) {
      c |= a[i] ^ b[i];
    }
    return c === 0;
  }
  bufferEq.install = function() {
    Buffer2.prototype.equal = SlowBuffer.prototype.equal = function equal(that) {
      return bufferEq(this, that);
    };
  };
  var origBufEqual = Buffer2.prototype.equal;
  var origSlowBufEqual = SlowBuffer.prototype.equal;
  bufferEq.restore = function() {
    Buffer2.prototype.equal = origBufEqual;
    SlowBuffer.prototype.equal = origSlowBufEqual;
  };
  return bufferEqualConstantTime;
}
var Buffer$4 = safeBufferExports.Buffer;
var crypto$1 = crypto$2;
var formatEcdsa = ecdsaSigFormatter;
var util$2 = require$$5;
var MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';
var MSG_INVALID_SECRET = "secret must be a string or buffer";
var MSG_INVALID_VERIFIER_KEY = "key must be a string or a buffer";
var MSG_INVALID_SIGNER_KEY = "key must be a string, a buffer or an object";
var supportsKeyObjects = typeof crypto$1.createPublicKey === "function";
if (supportsKeyObjects) {
  MSG_INVALID_VERIFIER_KEY += " or a KeyObject";
  MSG_INVALID_SECRET += "or a KeyObject";
}
function checkIsPublicKey(key) {
  if (Buffer$4.isBuffer(key)) {
    return;
  }
  if (typeof key === "string") {
    return;
  }
  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
  if (typeof key !== "object") {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
  if (typeof key.type !== "string") {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
  if (typeof key.asymmetricKeyType !== "string") {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
  if (typeof key.export !== "function") {
    throw typeError(MSG_INVALID_VERIFIER_KEY);
  }
}
function checkIsPrivateKey(key) {
  if (Buffer$4.isBuffer(key)) {
    return;
  }
  if (typeof key === "string") {
    return;
  }
  if (typeof key === "object") {
    return;
  }
  throw typeError(MSG_INVALID_SIGNER_KEY);
}
function checkIsSecretKey(key) {
  if (Buffer$4.isBuffer(key)) {
    return;
  }
  if (typeof key === "string") {
    return key;
  }
  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_SECRET);
  }
  if (typeof key !== "object") {
    throw typeError(MSG_INVALID_SECRET);
  }
  if (key.type !== "secret") {
    throw typeError(MSG_INVALID_SECRET);
  }
  if (typeof key.export !== "function") {
    throw typeError(MSG_INVALID_SECRET);
  }
}
function fromBase64(base64) {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function toBase64(base64url2) {
  base64url2 = base64url2.toString();
  var padding = 4 - base64url2.length % 4;
  if (padding !== 4) {
    for (var i = 0; i < padding; ++i) {
      base64url2 += "=";
    }
  }
  return base64url2.replace(/\-/g, "+").replace(/_/g, "/");
}
function typeError(template) {
  var args = [].slice.call(arguments, 1);
  var errMsg = util$2.format.bind(util$2, template).apply(null, args);
  return new TypeError(errMsg);
}
function bufferOrString(obj) {
  return Buffer$4.isBuffer(obj) || typeof obj === "string";
}
function normalizeInput(thing) {
  if (!bufferOrString(thing))
    thing = JSON.stringify(thing);
  return thing;
}
function createHmacSigner(bits) {
  return function sign3(thing, secret) {
    checkIsSecretKey(secret);
    thing = normalizeInput(thing);
    var hmac = crypto$1.createHmac("sha" + bits, secret);
    var sig = (hmac.update(thing), hmac.digest("base64"));
    return fromBase64(sig);
  };
}
var bufferEqual;
var timingSafeEqual = "timingSafeEqual" in crypto$1 ? function timingSafeEqual2(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto$1.timingSafeEqual(a, b);
} : function timingSafeEqual3(a, b) {
  if (!bufferEqual) {
    bufferEqual = requireBufferEqualConstantTime();
  }
  return bufferEqual(a, b);
};
function createHmacVerifier(bits) {
  return function verify3(thing, signature, secret) {
    var computedSig = createHmacSigner(bits)(thing, secret);
    return timingSafeEqual(Buffer$4.from(signature), Buffer$4.from(computedSig));
  };
}
function createKeySigner(bits) {
  return function sign3(thing, privateKey) {
    checkIsPrivateKey(privateKey);
    thing = normalizeInput(thing);
    var signer = crypto$1.createSign("RSA-SHA" + bits);
    var sig = (signer.update(thing), signer.sign(privateKey, "base64"));
    return fromBase64(sig);
  };
}
function createKeyVerifier(bits) {
  return function verify3(thing, signature, publicKey) {
    checkIsPublicKey(publicKey);
    thing = normalizeInput(thing);
    signature = toBase64(signature);
    var verifier = crypto$1.createVerify("RSA-SHA" + bits);
    verifier.update(thing);
    return verifier.verify(publicKey, signature, "base64");
  };
}
function createPSSKeySigner(bits) {
  return function sign3(thing, privateKey) {
    checkIsPrivateKey(privateKey);
    thing = normalizeInput(thing);
    var signer = crypto$1.createSign("RSA-SHA" + bits);
    var sig = (signer.update(thing), signer.sign({
      key: privateKey,
      padding: crypto$1.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto$1.constants.RSA_PSS_SALTLEN_DIGEST
    }, "base64"));
    return fromBase64(sig);
  };
}
function createPSSKeyVerifier(bits) {
  return function verify3(thing, signature, publicKey) {
    checkIsPublicKey(publicKey);
    thing = normalizeInput(thing);
    signature = toBase64(signature);
    var verifier = crypto$1.createVerify("RSA-SHA" + bits);
    verifier.update(thing);
    return verifier.verify({
      key: publicKey,
      padding: crypto$1.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto$1.constants.RSA_PSS_SALTLEN_DIGEST
    }, signature, "base64");
  };
}
function createECDSASigner(bits) {
  var inner = createKeySigner(bits);
  return function sign3() {
    var signature = inner.apply(null, arguments);
    signature = formatEcdsa.derToJose(signature, "ES" + bits);
    return signature;
  };
}
function createECDSAVerifer(bits) {
  var inner = createKeyVerifier(bits);
  return function verify3(thing, signature, publicKey) {
    signature = formatEcdsa.joseToDer(signature, "ES" + bits).toString("base64");
    var result = inner(thing, signature, publicKey);
    return result;
  };
}
function createNoneSigner() {
  return function sign3() {
    return "";
  };
}
function createNoneVerifier() {
  return function verify3(thing, signature) {
    return signature === "";
  };
}
var jwa$2 = function jwa(algorithm) {
  var signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner
  };
  var verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier
  };
  var match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i);
  if (!match)
    throw typeError(MSG_INVALID_ALGORITHM, algorithm);
  var algo = (match[1] || match[3]).toLowerCase();
  var bits = match[2];
  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits)
  };
};
var Buffer$3 = require$$0.Buffer;
var tostring = function toString(obj) {
  if (typeof obj === "string")
    return obj;
  if (typeof obj === "number" || Buffer$3.isBuffer(obj))
    return obj.toString();
  return JSON.stringify(obj);
};
var Buffer$2 = safeBufferExports.Buffer;
var DataStream$1 = dataStream;
var jwa$1 = jwa$2;
var Stream$1 = require$$3;
var toString$1 = tostring;
var util$1 = require$$5;
function base64url(string, encoding) {
  return Buffer$2.from(string, encoding).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function jwsSecuredInput(header, payload, encoding) {
  encoding = encoding || "utf8";
  var encodedHeader = base64url(toString$1(header), "binary");
  var encodedPayload = base64url(toString$1(payload), encoding);
  return util$1.format("%s.%s", encodedHeader, encodedPayload);
}
function jwsSign(opts) {
  var header = opts.header;
  var payload = opts.payload;
  var secretOrKey = opts.secret || opts.privateKey;
  var encoding = opts.encoding;
  var algo = jwa$1(header.alg);
  var securedInput = jwsSecuredInput(header, payload, encoding);
  var signature = algo.sign(securedInput, secretOrKey);
  return util$1.format("%s.%s", securedInput, signature);
}
function SignStream$1(opts) {
  var secret = opts.secret;
  secret = secret == null ? opts.privateKey : secret;
  secret = secret == null ? opts.key : secret;
  if (/^hs/i.test(opts.header.alg) === true && secret == null) {
    throw new TypeError("secret must be a string or buffer or a KeyObject");
  }
  var secretStream = new DataStream$1(secret);
  this.readable = true;
  this.header = opts.header;
  this.encoding = opts.encoding;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new DataStream$1(opts.payload);
  this.secret.once("close", function() {
    if (!this.payload.writable && this.readable)
      this.sign();
  }.bind(this));
  this.payload.once("close", function() {
    if (!this.secret.writable && this.readable)
      this.sign();
  }.bind(this));
}
util$1.inherits(SignStream$1, Stream$1);
SignStream$1.prototype.sign = function sign() {
  try {
    var signature = jwsSign({
      header: this.header,
      payload: this.payload.buffer,
      secret: this.secret.buffer,
      encoding: this.encoding
    });
    this.emit("done", signature);
    this.emit("data", signature);
    this.emit("end");
    this.readable = false;
    return signature;
  } catch (e) {
    this.readable = false;
    this.emit("error", e);
    this.emit("close");
  }
};
SignStream$1.sign = jwsSign;
var signStream = SignStream$1;
var Buffer$1 = safeBufferExports.Buffer;
var DataStream = dataStream;
var jwa2 = jwa$2;
var Stream = require$$3;
var toString2 = tostring;
var util = require$$5;
var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
function isObject(thing) {
  return Object.prototype.toString.call(thing) === "[object Object]";
}
function safeJsonParse(thing) {
  if (isObject(thing))
    return thing;
  try {
    return JSON.parse(thing);
  } catch (e) {
    return void 0;
  }
}
function headerFromJWS(jwsSig) {
  var encodedHeader = jwsSig.split(".", 1)[0];
  return safeJsonParse(Buffer$1.from(encodedHeader, "base64").toString("binary"));
}
function securedInputFromJWS(jwsSig) {
  return jwsSig.split(".", 2).join(".");
}
function signatureFromJWS(jwsSig) {
  return jwsSig.split(".")[2];
}
function payloadFromJWS(jwsSig, encoding) {
  encoding = encoding || "utf8";
  var payload = jwsSig.split(".")[1];
  return Buffer$1.from(payload, "base64").toString(encoding);
}
function isValidJws(string) {
  return JWS_REGEX.test(string) && !!headerFromJWS(string);
}
function jwsVerify(jwsSig, algorithm, secretOrKey) {
  if (!algorithm) {
    var err = new Error("Missing algorithm parameter for jws.verify");
    err.code = "MISSING_ALGORITHM";
    throw err;
  }
  jwsSig = toString2(jwsSig);
  var signature = signatureFromJWS(jwsSig);
  var securedInput = securedInputFromJWS(jwsSig);
  var algo = jwa2(algorithm);
  return algo.verify(securedInput, signature, secretOrKey);
}
function jwsDecode(jwsSig, opts) {
  opts = opts || {};
  jwsSig = toString2(jwsSig);
  if (!isValidJws(jwsSig))
    return null;
  var header = headerFromJWS(jwsSig);
  if (!header)
    return null;
  var payload = payloadFromJWS(jwsSig);
  if (header.typ === "JWT" || opts.json)
    payload = JSON.parse(payload, opts.encoding);
  return {
    header,
    payload,
    signature: signatureFromJWS(jwsSig)
  };
}
function VerifyStream$1(opts) {
  opts = opts || {};
  var secretOrKey = opts.secret;
  secretOrKey = secretOrKey == null ? opts.publicKey : secretOrKey;
  secretOrKey = secretOrKey == null ? opts.key : secretOrKey;
  if (/^hs/i.test(opts.algorithm) === true && secretOrKey == null) {
    throw new TypeError("secret must be a string or buffer or a KeyObject");
  }
  var secretStream = new DataStream(secretOrKey);
  this.readable = true;
  this.algorithm = opts.algorithm;
  this.encoding = opts.encoding;
  this.secret = this.publicKey = this.key = secretStream;
  this.signature = new DataStream(opts.signature);
  this.secret.once("close", function() {
    if (!this.signature.writable && this.readable)
      this.verify();
  }.bind(this));
  this.signature.once("close", function() {
    if (!this.secret.writable && this.readable)
      this.verify();
  }.bind(this));
}
util.inherits(VerifyStream$1, Stream);
VerifyStream$1.prototype.verify = function verify() {
  try {
    var valid2 = jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
    var obj = jwsDecode(this.signature.buffer, this.encoding);
    this.emit("done", valid2, obj);
    this.emit("data", valid2);
    this.emit("end");
    this.readable = false;
    return valid2;
  } catch (e) {
    this.readable = false;
    this.emit("error", e);
    this.emit("close");
  }
};
VerifyStream$1.decode = jwsDecode;
VerifyStream$1.isValid = isValidJws;
VerifyStream$1.verify = jwsVerify;
var verifyStream = VerifyStream$1;
var SignStream = signStream;
var VerifyStream = verifyStream;
var ALGORITHMS = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512"
];
jws$3.ALGORITHMS = ALGORITHMS;
jws$3.sign = SignStream.sign;
jws$3.verify = VerifyStream.verify;
jws$3.decode = VerifyStream.decode;
jws$3.isValid = VerifyStream.isValid;
jws$3.createSign = function createSign(opts) {
  return new SignStream(opts);
};
jws$3.createVerify = function createVerify(opts) {
  return new VerifyStream(opts);
};
var jws$2 = jws$3;
var decode$1 = function(jwt2, options2) {
  options2 = options2 || {};
  var decoded = jws$2.decode(jwt2, options2);
  if (!decoded) {
    return null;
  }
  var payload = decoded.payload;
  if (typeof payload === "string") {
    try {
      var obj = JSON.parse(payload);
      if (obj !== null && typeof obj === "object") {
        payload = obj;
      }
    } catch (e) {
    }
  }
  if (options2.complete === true) {
    return {
      header: decoded.header,
      payload,
      signature: decoded.signature
    };
  }
  return payload;
};
var s = 1e3;
var m = s * 60;
var h = m * 60;
var d = h * 24;
var w = d * 7;
var y = d * 365.25;
var ms$1 = function(val, options2) {
  options2 = options2 || {};
  var type = typeof val;
  if (type === "string" && val.length > 0) {
    return parse$7(val);
  } else if (type === "number" && isFinite(val)) {
    return options2.long ? fmtLong(val) : fmtShort(val);
  }
  throw new Error(
    "val is not a non-empty string or a valid number. val=" + JSON.stringify(val)
  );
};
function parse$7(str) {
  str = String(str);
  if (str.length > 100) {
    return;
  }
  var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
    str
  );
  if (!match) {
    return;
  }
  var n = parseFloat(match[1]);
  var type = (match[2] || "ms").toLowerCase();
  switch (type) {
    case "years":
    case "year":
    case "yrs":
    case "yr":
    case "y":
      return n * y;
    case "weeks":
    case "week":
    case "w":
      return n * w;
    case "days":
    case "day":
    case "d":
      return n * d;
    case "hours":
    case "hour":
    case "hrs":
    case "hr":
    case "h":
      return n * h;
    case "minutes":
    case "minute":
    case "mins":
    case "min":
    case "m":
      return n * m;
    case "seconds":
    case "second":
    case "secs":
    case "sec":
    case "s":
      return n * s;
    case "milliseconds":
    case "millisecond":
    case "msecs":
    case "msec":
    case "ms":
      return n;
    default:
      return void 0;
  }
}
function fmtShort(ms2) {
  var msAbs = Math.abs(ms2);
  if (msAbs >= d) {
    return Math.round(ms2 / d) + "d";
  }
  if (msAbs >= h) {
    return Math.round(ms2 / h) + "h";
  }
  if (msAbs >= m) {
    return Math.round(ms2 / m) + "m";
  }
  if (msAbs >= s) {
    return Math.round(ms2 / s) + "s";
  }
  return ms2 + "ms";
}
function fmtLong(ms2) {
  var msAbs = Math.abs(ms2);
  if (msAbs >= d) {
    return plural(ms2, msAbs, d, "day");
  }
  if (msAbs >= h) {
    return plural(ms2, msAbs, h, "hour");
  }
  if (msAbs >= m) {
    return plural(ms2, msAbs, m, "minute");
  }
  if (msAbs >= s) {
    return plural(ms2, msAbs, s, "second");
  }
  return ms2 + " ms";
}
function plural(ms2, msAbs, n, name) {
  var isPlural = msAbs >= n * 1.5;
  return Math.round(ms2 / n) + " " + name + (isPlural ? "s" : "");
}
var ms = ms$1;
var timespan$2 = function(time, iat) {
  var timestamp = iat || Math.floor(Date.now() / 1e3);
  if (typeof time === "string") {
    var milliseconds = ms(time);
    if (typeof milliseconds === "undefined") {
      return;
    }
    return Math.floor(timestamp + milliseconds / 1e3);
  } else if (typeof time === "number") {
    return timestamp + time;
  } else {
    return;
  }
};
var re$2 = { exports: {} };
const SEMVER_SPEC_VERSION = "2.0.0";
const MAX_LENGTH$1 = 256;
const MAX_SAFE_INTEGER$1 = Number.MAX_SAFE_INTEGER || /* istanbul ignore next */
9007199254740991;
const MAX_SAFE_COMPONENT_LENGTH = 16;
const MAX_SAFE_BUILD_LENGTH = MAX_LENGTH$1 - 6;
const RELEASE_TYPES = [
  "major",
  "premajor",
  "minor",
  "preminor",
  "patch",
  "prepatch",
  "prerelease"
];
var constants$1 = {
  MAX_LENGTH: MAX_LENGTH$1,
  MAX_SAFE_COMPONENT_LENGTH,
  MAX_SAFE_BUILD_LENGTH,
  MAX_SAFE_INTEGER: MAX_SAFE_INTEGER$1,
  RELEASE_TYPES,
  SEMVER_SPEC_VERSION,
  FLAG_INCLUDE_PRERELEASE: 1,
  FLAG_LOOSE: 2
};
const debug$1 = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {
};
var debug_1 = debug$1;
(function(module, exports$1) {
  const {
    MAX_SAFE_COMPONENT_LENGTH: MAX_SAFE_COMPONENT_LENGTH2,
    MAX_SAFE_BUILD_LENGTH: MAX_SAFE_BUILD_LENGTH2,
    MAX_LENGTH: MAX_LENGTH2
  } = constants$1;
  const debug2 = debug_1;
  exports$1 = module.exports = {};
  const re2 = exports$1.re = [];
  const safeRe = exports$1.safeRe = [];
  const src = exports$1.src = [];
  const safeSrc = exports$1.safeSrc = [];
  const t2 = exports$1.t = {};
  let R = 0;
  const LETTERDASHNUMBER = "[a-zA-Z0-9-]";
  const safeRegexReplacements = [
    ["\\s", 1],
    ["\\d", MAX_LENGTH2],
    [LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH2]
  ];
  const makeSafeRegex = (value) => {
    for (const [token, max] of safeRegexReplacements) {
      value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
    }
    return value;
  };
  const createToken = (name, value, isGlobal) => {
    const safe = makeSafeRegex(value);
    const index2 = R++;
    debug2(name, index2, value);
    t2[name] = index2;
    src[index2] = value;
    safeSrc[index2] = safe;
    re2[index2] = new RegExp(value, isGlobal ? "g" : void 0);
    safeRe[index2] = new RegExp(safe, isGlobal ? "g" : void 0);
  };
  createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
  createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
  createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
  createToken("MAINVERSION", `(${src[t2.NUMERICIDENTIFIER]})\\.(${src[t2.NUMERICIDENTIFIER]})\\.(${src[t2.NUMERICIDENTIFIER]})`);
  createToken("MAINVERSIONLOOSE", `(${src[t2.NUMERICIDENTIFIERLOOSE]})\\.(${src[t2.NUMERICIDENTIFIERLOOSE]})\\.(${src[t2.NUMERICIDENTIFIERLOOSE]})`);
  createToken("PRERELEASEIDENTIFIER", `(?:${src[t2.NONNUMERICIDENTIFIER]}|${src[t2.NUMERICIDENTIFIER]})`);
  createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t2.NONNUMERICIDENTIFIER]}|${src[t2.NUMERICIDENTIFIERLOOSE]})`);
  createToken("PRERELEASE", `(?:-(${src[t2.PRERELEASEIDENTIFIER]}(?:\\.${src[t2.PRERELEASEIDENTIFIER]})*))`);
  createToken("PRERELEASELOOSE", `(?:-?(${src[t2.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t2.PRERELEASEIDENTIFIERLOOSE]})*))`);
  createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
  createToken("BUILD", `(?:\\+(${src[t2.BUILDIDENTIFIER]}(?:\\.${src[t2.BUILDIDENTIFIER]})*))`);
  createToken("FULLPLAIN", `v?${src[t2.MAINVERSION]}${src[t2.PRERELEASE]}?${src[t2.BUILD]}?`);
  createToken("FULL", `^${src[t2.FULLPLAIN]}$`);
  createToken("LOOSEPLAIN", `[v=\\s]*${src[t2.MAINVERSIONLOOSE]}${src[t2.PRERELEASELOOSE]}?${src[t2.BUILD]}?`);
  createToken("LOOSE", `^${src[t2.LOOSEPLAIN]}$`);
  createToken("GTLT", "((?:<|>)?=?)");
  createToken("XRANGEIDENTIFIERLOOSE", `${src[t2.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
  createToken("XRANGEIDENTIFIER", `${src[t2.NUMERICIDENTIFIER]}|x|X|\\*`);
  createToken("XRANGEPLAIN", `[v=\\s]*(${src[t2.XRANGEIDENTIFIER]})(?:\\.(${src[t2.XRANGEIDENTIFIER]})(?:\\.(${src[t2.XRANGEIDENTIFIER]})(?:${src[t2.PRERELEASE]})?${src[t2.BUILD]}?)?)?`);
  createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t2.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t2.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t2.XRANGEIDENTIFIERLOOSE]})(?:${src[t2.PRERELEASELOOSE]})?${src[t2.BUILD]}?)?)?`);
  createToken("XRANGE", `^${src[t2.GTLT]}\\s*${src[t2.XRANGEPLAIN]}$`);
  createToken("XRANGELOOSE", `^${src[t2.GTLT]}\\s*${src[t2.XRANGEPLAINLOOSE]}$`);
  createToken("COERCEPLAIN", `${"(^|[^\\d])(\\d{1,"}${MAX_SAFE_COMPONENT_LENGTH2}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH2}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH2}}))?`);
  createToken("COERCE", `${src[t2.COERCEPLAIN]}(?:$|[^\\d])`);
  createToken("COERCEFULL", src[t2.COERCEPLAIN] + `(?:${src[t2.PRERELEASE]})?(?:${src[t2.BUILD]})?(?:$|[^\\d])`);
  createToken("COERCERTL", src[t2.COERCE], true);
  createToken("COERCERTLFULL", src[t2.COERCEFULL], true);
  createToken("LONETILDE", "(?:~>?)");
  createToken("TILDETRIM", `(\\s*)${src[t2.LONETILDE]}\\s+`, true);
  exports$1.tildeTrimReplace = "$1~";
  createToken("TILDE", `^${src[t2.LONETILDE]}${src[t2.XRANGEPLAIN]}$`);
  createToken("TILDELOOSE", `^${src[t2.LONETILDE]}${src[t2.XRANGEPLAINLOOSE]}$`);
  createToken("LONECARET", "(?:\\^)");
  createToken("CARETTRIM", `(\\s*)${src[t2.LONECARET]}\\s+`, true);
  exports$1.caretTrimReplace = "$1^";
  createToken("CARET", `^${src[t2.LONECARET]}${src[t2.XRANGEPLAIN]}$`);
  createToken("CARETLOOSE", `^${src[t2.LONECARET]}${src[t2.XRANGEPLAINLOOSE]}$`);
  createToken("COMPARATORLOOSE", `^${src[t2.GTLT]}\\s*(${src[t2.LOOSEPLAIN]})$|^$`);
  createToken("COMPARATOR", `^${src[t2.GTLT]}\\s*(${src[t2.FULLPLAIN]})$|^$`);
  createToken("COMPARATORTRIM", `(\\s*)${src[t2.GTLT]}\\s*(${src[t2.LOOSEPLAIN]}|${src[t2.XRANGEPLAIN]})`, true);
  exports$1.comparatorTrimReplace = "$1$2$3";
  createToken("HYPHENRANGE", `^\\s*(${src[t2.XRANGEPLAIN]})\\s+-\\s+(${src[t2.XRANGEPLAIN]})\\s*$`);
  createToken("HYPHENRANGELOOSE", `^\\s*(${src[t2.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t2.XRANGEPLAINLOOSE]})\\s*$`);
  createToken("STAR", "(<|>)?=?\\s*\\*");
  createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
  createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
})(re$2, re$2.exports);
var reExports = re$2.exports;
const looseOption = Object.freeze({ loose: true });
const emptyOpts = Object.freeze({});
const parseOptions$1 = (options2) => {
  if (!options2) {
    return emptyOpts;
  }
  if (typeof options2 !== "object") {
    return looseOption;
  }
  return options2;
};
var parseOptions_1 = parseOptions$1;
const numeric = /^[0-9]+$/;
const compareIdentifiers$1 = (a, b) => {
  if (typeof a === "number" && typeof b === "number") {
    return a === b ? 0 : a < b ? -1 : 1;
  }
  const anum = numeric.test(a);
  const bnum = numeric.test(b);
  if (anum && bnum) {
    a = +a;
    b = +b;
  }
  return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
};
const rcompareIdentifiers = (a, b) => compareIdentifiers$1(b, a);
var identifiers$1 = {
  compareIdentifiers: compareIdentifiers$1,
  rcompareIdentifiers
};
const debug = debug_1;
const { MAX_LENGTH, MAX_SAFE_INTEGER } = constants$1;
const { safeRe: re$1, t: t$1 } = reExports;
const parseOptions = parseOptions_1;
const { compareIdentifiers } = identifiers$1;
let SemVer$d = class SemVer {
  constructor(version, options2) {
    options2 = parseOptions(options2);
    if (version instanceof SemVer) {
      if (version.loose === !!options2.loose && version.includePrerelease === !!options2.includePrerelease) {
        return version;
      } else {
        version = version.version;
      }
    } else if (typeof version !== "string") {
      throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version}".`);
    }
    if (version.length > MAX_LENGTH) {
      throw new TypeError(
        `version is longer than ${MAX_LENGTH} characters`
      );
    }
    debug("SemVer", version, options2);
    this.options = options2;
    this.loose = !!options2.loose;
    this.includePrerelease = !!options2.includePrerelease;
    const m2 = version.trim().match(options2.loose ? re$1[t$1.LOOSE] : re$1[t$1.FULL]);
    if (!m2) {
      throw new TypeError(`Invalid Version: ${version}`);
    }
    this.raw = version;
    this.major = +m2[1];
    this.minor = +m2[2];
    this.patch = +m2[3];
    if (this.major > MAX_SAFE_INTEGER || this.major < 0) {
      throw new TypeError("Invalid major version");
    }
    if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) {
      throw new TypeError("Invalid minor version");
    }
    if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) {
      throw new TypeError("Invalid patch version");
    }
    if (!m2[4]) {
      this.prerelease = [];
    } else {
      this.prerelease = m2[4].split(".").map((id) => {
        if (/^[0-9]+$/.test(id)) {
          const num = +id;
          if (num >= 0 && num < MAX_SAFE_INTEGER) {
            return num;
          }
        }
        return id;
      });
    }
    this.build = m2[5] ? m2[5].split(".") : [];
    this.format();
  }
  format() {
    this.version = `${this.major}.${this.minor}.${this.patch}`;
    if (this.prerelease.length) {
      this.version += `-${this.prerelease.join(".")}`;
    }
    return this.version;
  }
  toString() {
    return this.version;
  }
  compare(other) {
    debug("SemVer.compare", this.version, this.options, other);
    if (!(other instanceof SemVer)) {
      if (typeof other === "string" && other === this.version) {
        return 0;
      }
      other = new SemVer(other, this.options);
    }
    if (other.version === this.version) {
      return 0;
    }
    return this.compareMain(other) || this.comparePre(other);
  }
  compareMain(other) {
    if (!(other instanceof SemVer)) {
      other = new SemVer(other, this.options);
    }
    if (this.major < other.major) {
      return -1;
    }
    if (this.major > other.major) {
      return 1;
    }
    if (this.minor < other.minor) {
      return -1;
    }
    if (this.minor > other.minor) {
      return 1;
    }
    if (this.patch < other.patch) {
      return -1;
    }
    if (this.patch > other.patch) {
      return 1;
    }
    return 0;
  }
  comparePre(other) {
    if (!(other instanceof SemVer)) {
      other = new SemVer(other, this.options);
    }
    if (this.prerelease.length && !other.prerelease.length) {
      return -1;
    } else if (!this.prerelease.length && other.prerelease.length) {
      return 1;
    } else if (!this.prerelease.length && !other.prerelease.length) {
      return 0;
    }
    let i = 0;
    do {
      const a = this.prerelease[i];
      const b = other.prerelease[i];
      debug("prerelease compare", i, a, b);
      if (a === void 0 && b === void 0) {
        return 0;
      } else if (b === void 0) {
        return 1;
      } else if (a === void 0) {
        return -1;
      } else if (a === b) {
        continue;
      } else {
        return compareIdentifiers(a, b);
      }
    } while (++i);
  }
  compareBuild(other) {
    if (!(other instanceof SemVer)) {
      other = new SemVer(other, this.options);
    }
    let i = 0;
    do {
      const a = this.build[i];
      const b = other.build[i];
      debug("build compare", i, a, b);
      if (a === void 0 && b === void 0) {
        return 0;
      } else if (b === void 0) {
        return 1;
      } else if (a === void 0) {
        return -1;
      } else if (a === b) {
        continue;
      } else {
        return compareIdentifiers(a, b);
      }
    } while (++i);
  }
  // preminor will bump the version up to the next minor release, and immediately
  // down to pre-release. premajor and prepatch work the same way.
  inc(release, identifier, identifierBase) {
    if (release.startsWith("pre")) {
      if (!identifier && identifierBase === false) {
        throw new Error("invalid increment argument: identifier is empty");
      }
      if (identifier) {
        const match = `-${identifier}`.match(this.options.loose ? re$1[t$1.PRERELEASELOOSE] : re$1[t$1.PRERELEASE]);
        if (!match || match[1] !== identifier) {
          throw new Error(`invalid identifier: ${identifier}`);
        }
      }
    }
    switch (release) {
      case "premajor":
        this.prerelease.length = 0;
        this.patch = 0;
        this.minor = 0;
        this.major++;
        this.inc("pre", identifier, identifierBase);
        break;
      case "preminor":
        this.prerelease.length = 0;
        this.patch = 0;
        this.minor++;
        this.inc("pre", identifier, identifierBase);
        break;
      case "prepatch":
        this.prerelease.length = 0;
        this.inc("patch", identifier, identifierBase);
        this.inc("pre", identifier, identifierBase);
        break;
      case "prerelease":
        if (this.prerelease.length === 0) {
          this.inc("patch", identifier, identifierBase);
        }
        this.inc("pre", identifier, identifierBase);
        break;
      case "release":
        if (this.prerelease.length === 0) {
          throw new Error(`version ${this.raw} is not a prerelease`);
        }
        this.prerelease.length = 0;
        break;
      case "major":
        if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) {
          this.major++;
        }
        this.minor = 0;
        this.patch = 0;
        this.prerelease = [];
        break;
      case "minor":
        if (this.patch !== 0 || this.prerelease.length === 0) {
          this.minor++;
        }
        this.patch = 0;
        this.prerelease = [];
        break;
      case "patch":
        if (this.prerelease.length === 0) {
          this.patch++;
        }
        this.prerelease = [];
        break;
      case "pre": {
        const base = Number(identifierBase) ? 1 : 0;
        if (this.prerelease.length === 0) {
          this.prerelease = [base];
        } else {
          let i = this.prerelease.length;
          while (--i >= 0) {
            if (typeof this.prerelease[i] === "number") {
              this.prerelease[i]++;
              i = -2;
            }
          }
          if (i === -1) {
            if (identifier === this.prerelease.join(".") && identifierBase === false) {
              throw new Error("invalid increment argument: identifier already exists");
            }
            this.prerelease.push(base);
          }
        }
        if (identifier) {
          let prerelease2 = [identifier, base];
          if (identifierBase === false) {
            prerelease2 = [identifier];
          }
          if (compareIdentifiers(this.prerelease[0], identifier) === 0) {
            if (isNaN(this.prerelease[1])) {
              this.prerelease = prerelease2;
            }
          } else {
            this.prerelease = prerelease2;
          }
        }
        break;
      }
      default:
        throw new Error(`invalid increment argument: ${release}`);
    }
    this.raw = this.format();
    if (this.build.length) {
      this.raw += `+${this.build.join(".")}`;
    }
    return this;
  }
};
var semver$4 = SemVer$d;
const SemVer$c = semver$4;
const parse$6 = (version, options2, throwErrors = false) => {
  if (version instanceof SemVer$c) {
    return version;
  }
  try {
    return new SemVer$c(version, options2);
  } catch (er) {
    if (!throwErrors) {
      return null;
    }
    throw er;
  }
};
var parse_1 = parse$6;
const parse$5 = parse_1;
const valid$2 = (version, options2) => {
  const v = parse$5(version, options2);
  return v ? v.version : null;
};
var valid_1 = valid$2;
const parse$4 = parse_1;
const clean$1 = (version, options2) => {
  const s2 = parse$4(version.trim().replace(/^[=v]+/, ""), options2);
  return s2 ? s2.version : null;
};
var clean_1 = clean$1;
const SemVer$b = semver$4;
const inc$1 = (version, release, options2, identifier, identifierBase) => {
  if (typeof options2 === "string") {
    identifierBase = identifier;
    identifier = options2;
    options2 = void 0;
  }
  try {
    return new SemVer$b(
      version instanceof SemVer$b ? version.version : version,
      options2
    ).inc(release, identifier, identifierBase).version;
  } catch (er) {
    return null;
  }
};
var inc_1 = inc$1;
const parse$3 = parse_1;
const diff$1 = (version1, version2) => {
  const v1 = parse$3(version1, null, true);
  const v2 = parse$3(version2, null, true);
  const comparison = v1.compare(v2);
  if (comparison === 0) {
    return null;
  }
  const v1Higher = comparison > 0;
  const highVersion = v1Higher ? v1 : v2;
  const lowVersion = v1Higher ? v2 : v1;
  const highHasPre = !!highVersion.prerelease.length;
  const lowHasPre = !!lowVersion.prerelease.length;
  if (lowHasPre && !highHasPre) {
    if (!lowVersion.patch && !lowVersion.minor) {
      return "major";
    }
    if (lowVersion.compareMain(highVersion) === 0) {
      if (lowVersion.minor && !lowVersion.patch) {
        return "minor";
      }
      return "patch";
    }
  }
  const prefix = highHasPre ? "pre" : "";
  if (v1.major !== v2.major) {
    return prefix + "major";
  }
  if (v1.minor !== v2.minor) {
    return prefix + "minor";
  }
  if (v1.patch !== v2.patch) {
    return prefix + "patch";
  }
  return "prerelease";
};
var diff_1 = diff$1;
const SemVer$a = semver$4;
const major$1 = (a, loose) => new SemVer$a(a, loose).major;
var major_1 = major$1;
const SemVer$9 = semver$4;
const minor$1 = (a, loose) => new SemVer$9(a, loose).minor;
var minor_1 = minor$1;
const SemVer$8 = semver$4;
const patch$1 = (a, loose) => new SemVer$8(a, loose).patch;
var patch_1 = patch$1;
const parse$2 = parse_1;
const prerelease$1 = (version, options2) => {
  const parsed = parse$2(version, options2);
  return parsed && parsed.prerelease.length ? parsed.prerelease : null;
};
var prerelease_1 = prerelease$1;
const SemVer$7 = semver$4;
const compare$b = (a, b, loose) => new SemVer$7(a, loose).compare(new SemVer$7(b, loose));
var compare_1 = compare$b;
const compare$a = compare_1;
const rcompare$1 = (a, b, loose) => compare$a(b, a, loose);
var rcompare_1 = rcompare$1;
const compare$9 = compare_1;
const compareLoose$1 = (a, b) => compare$9(a, b, true);
var compareLoose_1 = compareLoose$1;
const SemVer$6 = semver$4;
const compareBuild$3 = (a, b, loose) => {
  const versionA = new SemVer$6(a, loose);
  const versionB = new SemVer$6(b, loose);
  return versionA.compare(versionB) || versionA.compareBuild(versionB);
};
var compareBuild_1 = compareBuild$3;
const compareBuild$2 = compareBuild_1;
const sort$1 = (list, loose) => list.sort((a, b) => compareBuild$2(a, b, loose));
var sort_1 = sort$1;
const compareBuild$1 = compareBuild_1;
const rsort$1 = (list, loose) => list.sort((a, b) => compareBuild$1(b, a, loose));
var rsort_1 = rsort$1;
const compare$8 = compare_1;
const gt$4 = (a, b, loose) => compare$8(a, b, loose) > 0;
var gt_1 = gt$4;
const compare$7 = compare_1;
const lt$3 = (a, b, loose) => compare$7(a, b, loose) < 0;
var lt_1 = lt$3;
const compare$6 = compare_1;
const eq$2 = (a, b, loose) => compare$6(a, b, loose) === 0;
var eq_1 = eq$2;
const compare$5 = compare_1;
const neq$2 = (a, b, loose) => compare$5(a, b, loose) !== 0;
var neq_1 = neq$2;
const compare$4 = compare_1;
const gte$3 = (a, b, loose) => compare$4(a, b, loose) >= 0;
var gte_1 = gte$3;
const compare$3 = compare_1;
const lte$3 = (a, b, loose) => compare$3(a, b, loose) <= 0;
var lte_1 = lte$3;
const eq$1 = eq_1;
const neq$1 = neq_1;
const gt$3 = gt_1;
const gte$2 = gte_1;
const lt$2 = lt_1;
const lte$2 = lte_1;
const cmp$1 = (a, op, b, loose) => {
  switch (op) {
    case "===":
      if (typeof a === "object") {
        a = a.version;
      }
      if (typeof b === "object") {
        b = b.version;
      }
      return a === b;
    case "!==":
      if (typeof a === "object") {
        a = a.version;
      }
      if (typeof b === "object") {
        b = b.version;
      }
      return a !== b;
    case "":
    case "=":
    case "==":
      return eq$1(a, b, loose);
    case "!=":
      return neq$1(a, b, loose);
    case ">":
      return gt$3(a, b, loose);
    case ">=":
      return gte$2(a, b, loose);
    case "<":
      return lt$2(a, b, loose);
    case "<=":
      return lte$2(a, b, loose);
    default:
      throw new TypeError(`Invalid operator: ${op}`);
  }
};
var cmp_1 = cmp$1;
const SemVer$5 = semver$4;
const parse$1 = parse_1;
const { safeRe: re, t } = reExports;
const coerce$1 = (version, options2) => {
  if (version instanceof SemVer$5) {
    return version;
  }
  if (typeof version === "number") {
    version = String(version);
  }
  if (typeof version !== "string") {
    return null;
  }
  options2 = options2 || {};
  let match = null;
  if (!options2.rtl) {
    match = version.match(options2.includePrerelease ? re[t.COERCEFULL] : re[t.COERCE]);
  } else {
    const coerceRtlRegex = options2.includePrerelease ? re[t.COERCERTLFULL] : re[t.COERCERTL];
    let next;
    while ((next = coerceRtlRegex.exec(version)) && (!match || match.index + match[0].length !== version.length)) {
      if (!match || next.index + next[0].length !== match.index + match[0].length) {
        match = next;
      }
      coerceRtlRegex.lastIndex = next.index + next[1].length + next[2].length;
    }
    coerceRtlRegex.lastIndex = -1;
  }
  if (match === null) {
    return null;
  }
  const major2 = match[2];
  const minor2 = match[3] || "0";
  const patch2 = match[4] || "0";
  const prerelease2 = options2.includePrerelease && match[5] ? `-${match[5]}` : "";
  const build = options2.includePrerelease && match[6] ? `+${match[6]}` : "";
  return parse$1(`${major2}.${minor2}.${patch2}${prerelease2}${build}`, options2);
};
var coerce_1 = coerce$1;
class LRUCache {
  constructor() {
    this.max = 1e3;
    this.map = /* @__PURE__ */ new Map();
  }
  get(key) {
    const value = this.map.get(key);
    if (value === void 0) {
      return void 0;
    } else {
      this.map.delete(key);
      this.map.set(key, value);
      return value;
    }
  }
  delete(key) {
    return this.map.delete(key);
  }
  set(key, value) {
    const deleted = this.delete(key);
    if (!deleted && value !== void 0) {
      if (this.map.size >= this.max) {
        const firstKey = this.map.keys().next().value;
        this.delete(firstKey);
      }
      this.map.set(key, value);
    }
    return this;
  }
}
var lrucache = LRUCache;
var range;
var hasRequiredRange;
function requireRange() {
  if (hasRequiredRange) return range;
  hasRequiredRange = 1;
  const SPACE_CHARACTERS = /\s+/g;
  class Range2 {
    constructor(range2, options2) {
      options2 = parseOptions2(options2);
      if (range2 instanceof Range2) {
        if (range2.loose === !!options2.loose && range2.includePrerelease === !!options2.includePrerelease) {
          return range2;
        } else {
          return new Range2(range2.raw, options2);
        }
      }
      if (range2 instanceof Comparator2) {
        this.raw = range2.value;
        this.set = [[range2]];
        this.formatted = void 0;
        return this;
      }
      this.options = options2;
      this.loose = !!options2.loose;
      this.includePrerelease = !!options2.includePrerelease;
      this.raw = range2.trim().replace(SPACE_CHARACTERS, " ");
      this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
      if (!this.set.length) {
        throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
      }
      if (this.set.length > 1) {
        const first = this.set[0];
        this.set = this.set.filter((c) => !isNullSet(c[0]));
        if (this.set.length === 0) {
          this.set = [first];
        } else if (this.set.length > 1) {
          for (const c of this.set) {
            if (c.length === 1 && isAny(c[0])) {
              this.set = [c];
              break;
            }
          }
        }
      }
      this.formatted = void 0;
    }
    get range() {
      if (this.formatted === void 0) {
        this.formatted = "";
        for (let i = 0; i < this.set.length; i++) {
          if (i > 0) {
            this.formatted += "||";
          }
          const comps = this.set[i];
          for (let k = 0; k < comps.length; k++) {
            if (k > 0) {
              this.formatted += " ";
            }
            this.formatted += comps[k].toString().trim();
          }
        }
      }
      return this.formatted;
    }
    format() {
      return this.range;
    }
    toString() {
      return this.range;
    }
    parseRange(range2) {
      const memoOpts = (this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE);
      const memoKey = memoOpts + ":" + range2;
      const cached = cache.get(memoKey);
      if (cached) {
        return cached;
      }
      const loose = this.options.loose;
      const hr = loose ? re2[t2.HYPHENRANGELOOSE] : re2[t2.HYPHENRANGE];
      range2 = range2.replace(hr, hyphenReplace(this.options.includePrerelease));
      debug2("hyphen replace", range2);
      range2 = range2.replace(re2[t2.COMPARATORTRIM], comparatorTrimReplace);
      debug2("comparator trim", range2);
      range2 = range2.replace(re2[t2.TILDETRIM], tildeTrimReplace);
      debug2("tilde trim", range2);
      range2 = range2.replace(re2[t2.CARETTRIM], caretTrimReplace);
      debug2("caret trim", range2);
      let rangeList = range2.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
      if (loose) {
        rangeList = rangeList.filter((comp) => {
          debug2("loose invalid filter", comp, this.options);
          return !!comp.match(re2[t2.COMPARATORLOOSE]);
        });
      }
      debug2("range list", rangeList);
      const rangeMap = /* @__PURE__ */ new Map();
      const comparators = rangeList.map((comp) => new Comparator2(comp, this.options));
      for (const comp of comparators) {
        if (isNullSet(comp)) {
          return [comp];
        }
        rangeMap.set(comp.value, comp);
      }
      if (rangeMap.size > 1 && rangeMap.has("")) {
        rangeMap.delete("");
      }
      const result = [...rangeMap.values()];
      cache.set(memoKey, result);
      return result;
    }
    intersects(range2, options2) {
      if (!(range2 instanceof Range2)) {
        throw new TypeError("a Range is required");
      }
      return this.set.some((thisComparators) => {
        return isSatisfiable(thisComparators, options2) && range2.set.some((rangeComparators) => {
          return isSatisfiable(rangeComparators, options2) && thisComparators.every((thisComparator) => {
            return rangeComparators.every((rangeComparator) => {
              return thisComparator.intersects(rangeComparator, options2);
            });
          });
        });
      });
    }
    // if ANY of the sets match ALL of its comparators, then pass
    test(version) {
      if (!version) {
        return false;
      }
      if (typeof version === "string") {
        try {
          version = new SemVer3(version, this.options);
        } catch (er) {
          return false;
        }
      }
      for (let i = 0; i < this.set.length; i++) {
        if (testSet(this.set[i], version, this.options)) {
          return true;
        }
      }
      return false;
    }
  }
  range = Range2;
  const LRU = lrucache;
  const cache = new LRU();
  const parseOptions2 = parseOptions_1;
  const Comparator2 = requireComparator();
  const debug2 = debug_1;
  const SemVer3 = semver$4;
  const {
    safeRe: re2,
    t: t2,
    comparatorTrimReplace,
    tildeTrimReplace,
    caretTrimReplace
  } = reExports;
  const { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = constants$1;
  const isNullSet = (c) => c.value === "<0.0.0-0";
  const isAny = (c) => c.value === "";
  const isSatisfiable = (comparators, options2) => {
    let result = true;
    const remainingComparators = comparators.slice();
    let testComparator = remainingComparators.pop();
    while (result && remainingComparators.length) {
      result = remainingComparators.every((otherComparator) => {
        return testComparator.intersects(otherComparator, options2);
      });
      testComparator = remainingComparators.pop();
    }
    return result;
  };
  const parseComparator = (comp, options2) => {
    comp = comp.replace(re2[t2.BUILD], "");
    debug2("comp", comp, options2);
    comp = replaceCarets(comp, options2);
    debug2("caret", comp);
    comp = replaceTildes(comp, options2);
    debug2("tildes", comp);
    comp = replaceXRanges(comp, options2);
    debug2("xrange", comp);
    comp = replaceStars(comp, options2);
    debug2("stars", comp);
    return comp;
  };
  const isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
  const replaceTildes = (comp, options2) => {
    return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options2)).join(" ");
  };
  const replaceTilde = (comp, options2) => {
    const r = options2.loose ? re2[t2.TILDELOOSE] : re2[t2.TILDE];
    return comp.replace(r, (_2, M, m2, p, pr) => {
      debug2("tilde", comp, _2, M, m2, p, pr);
      let ret;
      if (isX(M)) {
        ret = "";
      } else if (isX(m2)) {
        ret = `>=${M}.0.0 <${+M + 1}.0.0-0`;
      } else if (isX(p)) {
        ret = `>=${M}.${m2}.0 <${M}.${+m2 + 1}.0-0`;
      } else if (pr) {
        debug2("replaceTilde pr", pr);
        ret = `>=${M}.${m2}.${p}-${pr} <${M}.${+m2 + 1}.0-0`;
      } else {
        ret = `>=${M}.${m2}.${p} <${M}.${+m2 + 1}.0-0`;
      }
      debug2("tilde return", ret);
      return ret;
    });
  };
  const replaceCarets = (comp, options2) => {
    return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options2)).join(" ");
  };
  const replaceCaret = (comp, options2) => {
    debug2("caret", comp, options2);
    const r = options2.loose ? re2[t2.CARETLOOSE] : re2[t2.CARET];
    const z = options2.includePrerelease ? "-0" : "";
    return comp.replace(r, (_2, M, m2, p, pr) => {
      debug2("caret", comp, _2, M, m2, p, pr);
      let ret;
      if (isX(M)) {
        ret = "";
      } else if (isX(m2)) {
        ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
      } else if (isX(p)) {
        if (M === "0") {
          ret = `>=${M}.${m2}.0${z} <${M}.${+m2 + 1}.0-0`;
        } else {
          ret = `>=${M}.${m2}.0${z} <${+M + 1}.0.0-0`;
        }
      } else if (pr) {
        debug2("replaceCaret pr", pr);
        if (M === "0") {
          if (m2 === "0") {
            ret = `>=${M}.${m2}.${p}-${pr} <${M}.${m2}.${+p + 1}-0`;
          } else {
            ret = `>=${M}.${m2}.${p}-${pr} <${M}.${+m2 + 1}.0-0`;
          }
        } else {
          ret = `>=${M}.${m2}.${p}-${pr} <${+M + 1}.0.0-0`;
        }
      } else {
        debug2("no pr");
        if (M === "0") {
          if (m2 === "0") {
            ret = `>=${M}.${m2}.${p}${z} <${M}.${m2}.${+p + 1}-0`;
          } else {
            ret = `>=${M}.${m2}.${p}${z} <${M}.${+m2 + 1}.0-0`;
          }
        } else {
          ret = `>=${M}.${m2}.${p} <${+M + 1}.0.0-0`;
        }
      }
      debug2("caret return", ret);
      return ret;
    });
  };
  const replaceXRanges = (comp, options2) => {
    debug2("replaceXRanges", comp, options2);
    return comp.split(/\s+/).map((c) => replaceXRange(c, options2)).join(" ");
  };
  const replaceXRange = (comp, options2) => {
    comp = comp.trim();
    const r = options2.loose ? re2[t2.XRANGELOOSE] : re2[t2.XRANGE];
    return comp.replace(r, (ret, gtlt, M, m2, p, pr) => {
      debug2("xRange", comp, ret, gtlt, M, m2, p, pr);
      const xM = isX(M);
      const xm = xM || isX(m2);
      const xp = xm || isX(p);
      const anyX = xp;
      if (gtlt === "=" && anyX) {
        gtlt = "";
      }
      pr = options2.includePrerelease ? "-0" : "";
      if (xM) {
        if (gtlt === ">" || gtlt === "<") {
          ret = "<0.0.0-0";
        } else {
          ret = "*";
        }
      } else if (gtlt && anyX) {
        if (xm) {
          m2 = 0;
        }
        p = 0;
        if (gtlt === ">") {
          gtlt = ">=";
          if (xm) {
            M = +M + 1;
            m2 = 0;
            p = 0;
          } else {
            m2 = +m2 + 1;
            p = 0;
          }
        } else if (gtlt === "<=") {
          gtlt = "<";
          if (xm) {
            M = +M + 1;
          } else {
            m2 = +m2 + 1;
          }
        }
        if (gtlt === "<") {
          pr = "-0";
        }
        ret = `${gtlt + M}.${m2}.${p}${pr}`;
      } else if (xm) {
        ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
      } else if (xp) {
        ret = `>=${M}.${m2}.0${pr} <${M}.${+m2 + 1}.0-0`;
      }
      debug2("xRange return", ret);
      return ret;
    });
  };
  const replaceStars = (comp, options2) => {
    debug2("replaceStars", comp, options2);
    return comp.trim().replace(re2[t2.STAR], "");
  };
  const replaceGTE0 = (comp, options2) => {
    debug2("replaceGTE0", comp, options2);
    return comp.trim().replace(re2[options2.includePrerelease ? t2.GTE0PRE : t2.GTE0], "");
  };
  const hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr) => {
    if (isX(fM)) {
      from = "";
    } else if (isX(fm)) {
      from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
    } else if (isX(fp)) {
      from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
    } else if (fpr) {
      from = `>=${from}`;
    } else {
      from = `>=${from}${incPr ? "-0" : ""}`;
    }
    if (isX(tM)) {
      to = "";
    } else if (isX(tm)) {
      to = `<${+tM + 1}.0.0-0`;
    } else if (isX(tp)) {
      to = `<${tM}.${+tm + 1}.0-0`;
    } else if (tpr) {
      to = `<=${tM}.${tm}.${tp}-${tpr}`;
    } else if (incPr) {
      to = `<${tM}.${tm}.${+tp + 1}-0`;
    } else {
      to = `<=${to}`;
    }
    return `${from} ${to}`.trim();
  };
  const testSet = (set, version, options2) => {
    for (let i = 0; i < set.length; i++) {
      if (!set[i].test(version)) {
        return false;
      }
    }
    if (version.prerelease.length && !options2.includePrerelease) {
      for (let i = 0; i < set.length; i++) {
        debug2(set[i].semver);
        if (set[i].semver === Comparator2.ANY) {
          continue;
        }
        if (set[i].semver.prerelease.length > 0) {
          const allowed = set[i].semver;
          if (allowed.major === version.major && allowed.minor === version.minor && allowed.patch === version.patch) {
            return true;
          }
        }
      }
      return false;
    }
    return true;
  };
  return range;
}
var comparator;
var hasRequiredComparator;
function requireComparator() {
  if (hasRequiredComparator) return comparator;
  hasRequiredComparator = 1;
  const ANY2 = Symbol("SemVer ANY");
  class Comparator2 {
    static get ANY() {
      return ANY2;
    }
    constructor(comp, options2) {
      options2 = parseOptions2(options2);
      if (comp instanceof Comparator2) {
        if (comp.loose === !!options2.loose) {
          return comp;
        } else {
          comp = comp.value;
        }
      }
      comp = comp.trim().split(/\s+/).join(" ");
      debug2("comparator", comp, options2);
      this.options = options2;
      this.loose = !!options2.loose;
      this.parse(comp);
      if (this.semver === ANY2) {
        this.value = "";
      } else {
        this.value = this.operator + this.semver.version;
      }
      debug2("comp", this);
    }
    parse(comp) {
      const r = this.options.loose ? re2[t2.COMPARATORLOOSE] : re2[t2.COMPARATOR];
      const m2 = comp.match(r);
      if (!m2) {
        throw new TypeError(`Invalid comparator: ${comp}`);
      }
      this.operator = m2[1] !== void 0 ? m2[1] : "";
      if (this.operator === "=") {
        this.operator = "";
      }
      if (!m2[2]) {
        this.semver = ANY2;
      } else {
        this.semver = new SemVer3(m2[2], this.options.loose);
      }
    }
    toString() {
      return this.value;
    }
    test(version) {
      debug2("Comparator.test", version, this.options.loose);
      if (this.semver === ANY2 || version === ANY2) {
        return true;
      }
      if (typeof version === "string") {
        try {
          version = new SemVer3(version, this.options);
        } catch (er) {
          return false;
        }
      }
      return cmp2(version, this.operator, this.semver, this.options);
    }
    intersects(comp, options2) {
      if (!(comp instanceof Comparator2)) {
        throw new TypeError("a Comparator is required");
      }
      if (this.operator === "") {
        if (this.value === "") {
          return true;
        }
        return new Range2(comp.value, options2).test(this.value);
      } else if (comp.operator === "") {
        if (comp.value === "") {
          return true;
        }
        return new Range2(this.value, options2).test(comp.semver);
      }
      options2 = parseOptions2(options2);
      if (options2.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) {
        return false;
      }
      if (!options2.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) {
        return false;
      }
      if (this.operator.startsWith(">") && comp.operator.startsWith(">")) {
        return true;
      }
      if (this.operator.startsWith("<") && comp.operator.startsWith("<")) {
        return true;
      }
      if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) {
        return true;
      }
      if (cmp2(this.semver, "<", comp.semver, options2) && this.operator.startsWith(">") && comp.operator.startsWith("<")) {
        return true;
      }
      if (cmp2(this.semver, ">", comp.semver, options2) && this.operator.startsWith("<") && comp.operator.startsWith(">")) {
        return true;
      }
      return false;
    }
  }
  comparator = Comparator2;
  const parseOptions2 = parseOptions_1;
  const { safeRe: re2, t: t2 } = reExports;
  const cmp2 = cmp_1;
  const debug2 = debug_1;
  const SemVer3 = semver$4;
  const Range2 = requireRange();
  return comparator;
}
const Range$9 = requireRange();
const satisfies$4 = (version, range2, options2) => {
  try {
    range2 = new Range$9(range2, options2);
  } catch (er) {
    return false;
  }
  return range2.test(version);
};
var satisfies_1 = satisfies$4;
const Range$8 = requireRange();
const toComparators$1 = (range2, options2) => new Range$8(range2, options2).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
var toComparators_1 = toComparators$1;
const SemVer$4 = semver$4;
const Range$7 = requireRange();
const maxSatisfying$1 = (versions, range2, options2) => {
  let max = null;
  let maxSV = null;
  let rangeObj = null;
  try {
    rangeObj = new Range$7(range2, options2);
  } catch (er) {
    return null;
  }
  versions.forEach((v) => {
    if (rangeObj.test(v)) {
      if (!max || maxSV.compare(v) === -1) {
        max = v;
        maxSV = new SemVer$4(max, options2);
      }
    }
  });
  return max;
};
var maxSatisfying_1 = maxSatisfying$1;
const SemVer$3 = semver$4;
const Range$6 = requireRange();
const minSatisfying$1 = (versions, range2, options2) => {
  let min = null;
  let minSV = null;
  let rangeObj = null;
  try {
    rangeObj = new Range$6(range2, options2);
  } catch (er) {
    return null;
  }
  versions.forEach((v) => {
    if (rangeObj.test(v)) {
      if (!min || minSV.compare(v) === 1) {
        min = v;
        minSV = new SemVer$3(min, options2);
      }
    }
  });
  return min;
};
var minSatisfying_1 = minSatisfying$1;
const SemVer$2 = semver$4;
const Range$5 = requireRange();
const gt$2 = gt_1;
const minVersion$1 = (range2, loose) => {
  range2 = new Range$5(range2, loose);
  let minver = new SemVer$2("0.0.0");
  if (range2.test(minver)) {
    return minver;
  }
  minver = new SemVer$2("0.0.0-0");
  if (range2.test(minver)) {
    return minver;
  }
  minver = null;
  for (let i = 0; i < range2.set.length; ++i) {
    const comparators = range2.set[i];
    let setMin = null;
    comparators.forEach((comparator2) => {
      const compver = new SemVer$2(comparator2.semver.version);
      switch (comparator2.operator) {
        case ">":
          if (compver.prerelease.length === 0) {
            compver.patch++;
          } else {
            compver.prerelease.push(0);
          }
          compver.raw = compver.format();
        case "":
        case ">=":
          if (!setMin || gt$2(compver, setMin)) {
            setMin = compver;
          }
          break;
        case "<":
        case "<=":
          break;
        default:
          throw new Error(`Unexpected operation: ${comparator2.operator}`);
      }
    });
    if (setMin && (!minver || gt$2(minver, setMin))) {
      minver = setMin;
    }
  }
  if (minver && range2.test(minver)) {
    return minver;
  }
  return null;
};
var minVersion_1 = minVersion$1;
const Range$4 = requireRange();
const validRange$1 = (range2, options2) => {
  try {
    return new Range$4(range2, options2).range || "*";
  } catch (er) {
    return null;
  }
};
var valid$1 = validRange$1;
const SemVer$1 = semver$4;
const Comparator$2 = requireComparator();
const { ANY: ANY$1 } = Comparator$2;
const Range$3 = requireRange();
const satisfies$3 = satisfies_1;
const gt$1 = gt_1;
const lt$1 = lt_1;
const lte$1 = lte_1;
const gte$1 = gte_1;
const outside$3 = (version, range2, hilo, options2) => {
  version = new SemVer$1(version, options2);
  range2 = new Range$3(range2, options2);
  let gtfn, ltefn, ltfn, comp, ecomp;
  switch (hilo) {
    case ">":
      gtfn = gt$1;
      ltefn = lte$1;
      ltfn = lt$1;
      comp = ">";
      ecomp = ">=";
      break;
    case "<":
      gtfn = lt$1;
      ltefn = gte$1;
      ltfn = gt$1;
      comp = "<";
      ecomp = "<=";
      break;
    default:
      throw new TypeError('Must provide a hilo val of "<" or ">"');
  }
  if (satisfies$3(version, range2, options2)) {
    return false;
  }
  for (let i = 0; i < range2.set.length; ++i) {
    const comparators = range2.set[i];
    let high = null;
    let low = null;
    comparators.forEach((comparator2) => {
      if (comparator2.semver === ANY$1) {
        comparator2 = new Comparator$2(">=0.0.0");
      }
      high = high || comparator2;
      low = low || comparator2;
      if (gtfn(comparator2.semver, high.semver, options2)) {
        high = comparator2;
      } else if (ltfn(comparator2.semver, low.semver, options2)) {
        low = comparator2;
      }
    });
    if (high.operator === comp || high.operator === ecomp) {
      return false;
    }
    if ((!low.operator || low.operator === comp) && ltefn(version, low.semver)) {
      return false;
    } else if (low.operator === ecomp && ltfn(version, low.semver)) {
      return false;
    }
  }
  return true;
};
var outside_1 = outside$3;
const outside$2 = outside_1;
const gtr$1 = (version, range2, options2) => outside$2(version, range2, ">", options2);
var gtr_1 = gtr$1;
const outside$1 = outside_1;
const ltr$1 = (version, range2, options2) => outside$1(version, range2, "<", options2);
var ltr_1 = ltr$1;
const Range$2 = requireRange();
const intersects$1 = (r1, r2, options2) => {
  r1 = new Range$2(r1, options2);
  r2 = new Range$2(r2, options2);
  return r1.intersects(r2, options2);
};
var intersects_1 = intersects$1;
const satisfies$2 = satisfies_1;
const compare$2 = compare_1;
var simplify = (versions, range2, options2) => {
  const set = [];
  let first = null;
  let prev = null;
  const v = versions.sort((a, b) => compare$2(a, b, options2));
  for (const version of v) {
    const included = satisfies$2(version, range2, options2);
    if (included) {
      prev = version;
      if (!first) {
        first = version;
      }
    } else {
      if (prev) {
        set.push([first, prev]);
      }
      prev = null;
      first = null;
    }
  }
  if (first) {
    set.push([first, null]);
  }
  const ranges = [];
  for (const [min, max] of set) {
    if (min === max) {
      ranges.push(min);
    } else if (!max && min === v[0]) {
      ranges.push("*");
    } else if (!max) {
      ranges.push(`>=${min}`);
    } else if (min === v[0]) {
      ranges.push(`<=${max}`);
    } else {
      ranges.push(`${min} - ${max}`);
    }
  }
  const simplified = ranges.join(" || ");
  const original = typeof range2.raw === "string" ? range2.raw : String(range2);
  return simplified.length < original.length ? simplified : range2;
};
const Range$1 = requireRange();
const Comparator$1 = requireComparator();
const { ANY } = Comparator$1;
const satisfies$1 = satisfies_1;
const compare$1 = compare_1;
const subset$1 = (sub, dom, options2 = {}) => {
  if (sub === dom) {
    return true;
  }
  sub = new Range$1(sub, options2);
  dom = new Range$1(dom, options2);
  let sawNonNull = false;
  OUTER: for (const simpleSub of sub.set) {
    for (const simpleDom of dom.set) {
      const isSub = simpleSubset(simpleSub, simpleDom, options2);
      sawNonNull = sawNonNull || isSub !== null;
      if (isSub) {
        continue OUTER;
      }
    }
    if (sawNonNull) {
      return false;
    }
  }
  return true;
};
const minimumVersionWithPreRelease = [new Comparator$1(">=0.0.0-0")];
const minimumVersion = [new Comparator$1(">=0.0.0")];
const simpleSubset = (sub, dom, options2) => {
  if (sub === dom) {
    return true;
  }
  if (sub.length === 1 && sub[0].semver === ANY) {
    if (dom.length === 1 && dom[0].semver === ANY) {
      return true;
    } else if (options2.includePrerelease) {
      sub = minimumVersionWithPreRelease;
    } else {
      sub = minimumVersion;
    }
  }
  if (dom.length === 1 && dom[0].semver === ANY) {
    if (options2.includePrerelease) {
      return true;
    } else {
      dom = minimumVersion;
    }
  }
  const eqSet = /* @__PURE__ */ new Set();
  let gt2, lt2;
  for (const c of sub) {
    if (c.operator === ">" || c.operator === ">=") {
      gt2 = higherGT(gt2, c, options2);
    } else if (c.operator === "<" || c.operator === "<=") {
      lt2 = lowerLT(lt2, c, options2);
    } else {
      eqSet.add(c.semver);
    }
  }
  if (eqSet.size > 1) {
    return null;
  }
  let gtltComp;
  if (gt2 && lt2) {
    gtltComp = compare$1(gt2.semver, lt2.semver, options2);
    if (gtltComp > 0) {
      return null;
    } else if (gtltComp === 0 && (gt2.operator !== ">=" || lt2.operator !== "<=")) {
      return null;
    }
  }
  for (const eq2 of eqSet) {
    if (gt2 && !satisfies$1(eq2, String(gt2), options2)) {
      return null;
    }
    if (lt2 && !satisfies$1(eq2, String(lt2), options2)) {
      return null;
    }
    for (const c of dom) {
      if (!satisfies$1(eq2, String(c), options2)) {
        return false;
      }
    }
    return true;
  }
  let higher, lower;
  let hasDomLT, hasDomGT;
  let needDomLTPre = lt2 && !options2.includePrerelease && lt2.semver.prerelease.length ? lt2.semver : false;
  let needDomGTPre = gt2 && !options2.includePrerelease && gt2.semver.prerelease.length ? gt2.semver : false;
  if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt2.operator === "<" && needDomLTPre.prerelease[0] === 0) {
    needDomLTPre = false;
  }
  for (const c of dom) {
    hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
    hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
    if (gt2) {
      if (needDomGTPre) {
        if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) {
          needDomGTPre = false;
        }
      }
      if (c.operator === ">" || c.operator === ">=") {
        higher = higherGT(gt2, c, options2);
        if (higher === c && higher !== gt2) {
          return false;
        }
      } else if (gt2.operator === ">=" && !satisfies$1(gt2.semver, String(c), options2)) {
        return false;
      }
    }
    if (lt2) {
      if (needDomLTPre) {
        if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) {
          needDomLTPre = false;
        }
      }
      if (c.operator === "<" || c.operator === "<=") {
        lower = lowerLT(lt2, c, options2);
        if (lower === c && lower !== lt2) {
          return false;
        }
      } else if (lt2.operator === "<=" && !satisfies$1(lt2.semver, String(c), options2)) {
        return false;
      }
    }
    if (!c.operator && (lt2 || gt2) && gtltComp !== 0) {
      return false;
    }
  }
  if (gt2 && hasDomLT && !lt2 && gtltComp !== 0) {
    return false;
  }
  if (lt2 && hasDomGT && !gt2 && gtltComp !== 0) {
    return false;
  }
  if (needDomGTPre || needDomLTPre) {
    return false;
  }
  return true;
};
const higherGT = (a, b, options2) => {
  if (!a) {
    return b;
  }
  const comp = compare$1(a.semver, b.semver, options2);
  return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
};
const lowerLT = (a, b, options2) => {
  if (!a) {
    return b;
  }
  const comp = compare$1(a.semver, b.semver, options2);
  return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
};
var subset_1 = subset$1;
const internalRe = reExports;
const constants = constants$1;
const SemVer2 = semver$4;
const identifiers = identifiers$1;
const parse = parse_1;
const valid = valid_1;
const clean = clean_1;
const inc = inc_1;
const diff = diff_1;
const major = major_1;
const minor = minor_1;
const patch = patch_1;
const prerelease = prerelease_1;
const compare = compare_1;
const rcompare = rcompare_1;
const compareLoose = compareLoose_1;
const compareBuild = compareBuild_1;
const sort = sort_1;
const rsort = rsort_1;
const gt = gt_1;
const lt = lt_1;
const eq = eq_1;
const neq = neq_1;
const gte = gte_1;
const lte = lte_1;
const cmp = cmp_1;
const coerce = coerce_1;
const Comparator = requireComparator();
const Range = requireRange();
const satisfies = satisfies_1;
const toComparators = toComparators_1;
const maxSatisfying = maxSatisfying_1;
const minSatisfying = minSatisfying_1;
const minVersion = minVersion_1;
const validRange = valid$1;
const outside = outside_1;
const gtr = gtr_1;
const ltr = ltr_1;
const intersects = intersects_1;
const simplifyRange = simplify;
const subset = subset_1;
var semver$3 = {
  parse,
  valid,
  clean,
  inc,
  diff,
  major,
  minor,
  patch,
  prerelease,
  compare,
  rcompare,
  compareLoose,
  compareBuild,
  sort,
  rsort,
  gt,
  lt,
  eq,
  neq,
  gte,
  lte,
  cmp,
  coerce,
  Comparator,
  Range,
  satisfies,
  toComparators,
  maxSatisfying,
  minSatisfying,
  minVersion,
  validRange,
  outside,
  gtr,
  ltr,
  intersects,
  simplifyRange,
  subset,
  SemVer: SemVer2,
  re: internalRe.re,
  src: internalRe.src,
  tokens: internalRe.t,
  SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
  RELEASE_TYPES: constants.RELEASE_TYPES,
  compareIdentifiers: identifiers.compareIdentifiers,
  rcompareIdentifiers: identifiers.rcompareIdentifiers
};
const semver$2 = semver$3;
var asymmetricKeyDetailsSupported = semver$2.satisfies(process.version, ">=15.7.0");
const semver$1 = semver$3;
var rsaPssKeyDetailsSupported = semver$1.satisfies(process.version, ">=16.9.0");
const ASYMMETRIC_KEY_DETAILS_SUPPORTED = asymmetricKeyDetailsSupported;
const RSA_PSS_KEY_DETAILS_SUPPORTED = rsaPssKeyDetailsSupported;
const allowedAlgorithmsForKeys = {
  "ec": ["ES256", "ES384", "ES512"],
  "rsa": ["RS256", "PS256", "RS384", "PS384", "RS512", "PS512"],
  "rsa-pss": ["PS256", "PS384", "PS512"]
};
const allowedCurves = {
  ES256: "prime256v1",
  ES384: "secp384r1",
  ES512: "secp521r1"
};
var validateAsymmetricKey$2 = function(algorithm, key) {
  if (!algorithm || !key) return;
  const keyType = key.asymmetricKeyType;
  if (!keyType) return;
  const allowedAlgorithms = allowedAlgorithmsForKeys[keyType];
  if (!allowedAlgorithms) {
    throw new Error(`Unknown key type "${keyType}".`);
  }
  if (!allowedAlgorithms.includes(algorithm)) {
    throw new Error(`"alg" parameter for "${keyType}" key type must be one of: ${allowedAlgorithms.join(", ")}.`);
  }
  if (ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
    switch (keyType) {
      case "ec":
        const keyCurve = key.asymmetricKeyDetails.namedCurve;
        const allowedCurve = allowedCurves[algorithm];
        if (keyCurve !== allowedCurve) {
          throw new Error(`"alg" parameter "${algorithm}" requires curve "${allowedCurve}".`);
        }
        break;
      case "rsa-pss":
        if (RSA_PSS_KEY_DETAILS_SUPPORTED) {
          const length = parseInt(algorithm.slice(-3), 10);
          const { hashAlgorithm, mgf1HashAlgorithm, saltLength } = key.asymmetricKeyDetails;
          if (hashAlgorithm !== `sha${length}` || mgf1HashAlgorithm !== hashAlgorithm) {
            throw new Error(`Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${algorithm}.`);
          }
          if (saltLength !== void 0 && saltLength > length >> 3) {
            throw new Error(`Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" ${algorithm}.`);
          }
        }
        break;
    }
  }
};
var semver = semver$3;
var psSupported = semver.satisfies(process.version, "^6.12.0 || >=8.0.0");
const JsonWebTokenError = JsonWebTokenError_1;
const NotBeforeError = NotBeforeError_1;
const TokenExpiredError = TokenExpiredError_1;
const decode = decode$1;
const timespan$1 = timespan$2;
const validateAsymmetricKey$1 = validateAsymmetricKey$2;
const PS_SUPPORTED$1 = psSupported;
const jws$1 = jws$3;
const { KeyObject: KeyObject$1, createSecretKey: createSecretKey$1, createPublicKey } = crypto$2;
const PUB_KEY_ALGS = ["RS256", "RS384", "RS512"];
const EC_KEY_ALGS = ["ES256", "ES384", "ES512"];
const RSA_KEY_ALGS = ["RS256", "RS384", "RS512"];
const HS_ALGS = ["HS256", "HS384", "HS512"];
if (PS_SUPPORTED$1) {
  PUB_KEY_ALGS.splice(PUB_KEY_ALGS.length, 0, "PS256", "PS384", "PS512");
  RSA_KEY_ALGS.splice(RSA_KEY_ALGS.length, 0, "PS256", "PS384", "PS512");
}
var verify2 = function(jwtString, secretOrPublicKey, options2, callback) {
  if (typeof options2 === "function" && !callback) {
    callback = options2;
    options2 = {};
  }
  if (!options2) {
    options2 = {};
  }
  options2 = Object.assign({}, options2);
  let done;
  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }
  if (options2.clockTimestamp && typeof options2.clockTimestamp !== "number") {
    return done(new JsonWebTokenError("clockTimestamp must be a number"));
  }
  if (options2.nonce !== void 0 && (typeof options2.nonce !== "string" || options2.nonce.trim() === "")) {
    return done(new JsonWebTokenError("nonce must be a non-empty string"));
  }
  if (options2.allowInvalidAsymmetricKeyTypes !== void 0 && typeof options2.allowInvalidAsymmetricKeyTypes !== "boolean") {
    return done(new JsonWebTokenError("allowInvalidAsymmetricKeyTypes must be a boolean"));
  }
  const clockTimestamp = options2.clockTimestamp || Math.floor(Date.now() / 1e3);
  if (!jwtString) {
    return done(new JsonWebTokenError("jwt must be provided"));
  }
  if (typeof jwtString !== "string") {
    return done(new JsonWebTokenError("jwt must be a string"));
  }
  const parts = jwtString.split(".");
  if (parts.length !== 3) {
    return done(new JsonWebTokenError("jwt malformed"));
  }
  let decodedToken;
  try {
    decodedToken = decode(jwtString, { complete: true });
  } catch (err) {
    return done(err);
  }
  if (!decodedToken) {
    return done(new JsonWebTokenError("invalid token"));
  }
  const header = decodedToken.header;
  let getSecret;
  if (typeof secretOrPublicKey === "function") {
    if (!callback) {
      return done(new JsonWebTokenError("verify must be called asynchronous if secret or public key is provided as a callback"));
    }
    getSecret = secretOrPublicKey;
  } else {
    getSecret = function(header2, secretCallback) {
      return secretCallback(null, secretOrPublicKey);
    };
  }
  return getSecret(header, function(err, secretOrPublicKey2) {
    if (err) {
      return done(new JsonWebTokenError("error in secret or public key callback: " + err.message));
    }
    const hasSignature = parts[2].trim() !== "";
    if (!hasSignature && secretOrPublicKey2) {
      return done(new JsonWebTokenError("jwt signature is required"));
    }
    if (hasSignature && !secretOrPublicKey2) {
      return done(new JsonWebTokenError("secret or public key must be provided"));
    }
    if (!hasSignature && !options2.algorithms) {
      return done(new JsonWebTokenError('please specify "none" in "algorithms" to verify unsigned tokens'));
    }
    if (secretOrPublicKey2 != null && !(secretOrPublicKey2 instanceof KeyObject$1)) {
      try {
        secretOrPublicKey2 = createPublicKey(secretOrPublicKey2);
      } catch (_2) {
        try {
          secretOrPublicKey2 = createSecretKey$1(typeof secretOrPublicKey2 === "string" ? Buffer.from(secretOrPublicKey2) : secretOrPublicKey2);
        } catch (_3) {
          return done(new JsonWebTokenError("secretOrPublicKey is not valid key material"));
        }
      }
    }
    if (!options2.algorithms) {
      if (secretOrPublicKey2.type === "secret") {
        options2.algorithms = HS_ALGS;
      } else if (["rsa", "rsa-pss"].includes(secretOrPublicKey2.asymmetricKeyType)) {
        options2.algorithms = RSA_KEY_ALGS;
      } else if (secretOrPublicKey2.asymmetricKeyType === "ec") {
        options2.algorithms = EC_KEY_ALGS;
      } else {
        options2.algorithms = PUB_KEY_ALGS;
      }
    }
    if (options2.algorithms.indexOf(decodedToken.header.alg) === -1) {
      return done(new JsonWebTokenError("invalid algorithm"));
    }
    if (header.alg.startsWith("HS") && secretOrPublicKey2.type !== "secret") {
      return done(new JsonWebTokenError(`secretOrPublicKey must be a symmetric key when using ${header.alg}`));
    } else if (/^(?:RS|PS|ES)/.test(header.alg) && secretOrPublicKey2.type !== "public") {
      return done(new JsonWebTokenError(`secretOrPublicKey must be an asymmetric key when using ${header.alg}`));
    }
    if (!options2.allowInvalidAsymmetricKeyTypes) {
      try {
        validateAsymmetricKey$1(header.alg, secretOrPublicKey2);
      } catch (e) {
        return done(e);
      }
    }
    let valid2;
    try {
      valid2 = jws$1.verify(jwtString, decodedToken.header.alg, secretOrPublicKey2);
    } catch (e) {
      return done(e);
    }
    if (!valid2) {
      return done(new JsonWebTokenError("invalid signature"));
    }
    const payload = decodedToken.payload;
    if (typeof payload.nbf !== "undefined" && !options2.ignoreNotBefore) {
      if (typeof payload.nbf !== "number") {
        return done(new JsonWebTokenError("invalid nbf value"));
      }
      if (payload.nbf > clockTimestamp + (options2.clockTolerance || 0)) {
        return done(new NotBeforeError("jwt not active", new Date(payload.nbf * 1e3)));
      }
    }
    if (typeof payload.exp !== "undefined" && !options2.ignoreExpiration) {
      if (typeof payload.exp !== "number") {
        return done(new JsonWebTokenError("invalid exp value"));
      }
      if (clockTimestamp >= payload.exp + (options2.clockTolerance || 0)) {
        return done(new TokenExpiredError("jwt expired", new Date(payload.exp * 1e3)));
      }
    }
    if (options2.audience) {
      const audiences = Array.isArray(options2.audience) ? options2.audience : [options2.audience];
      const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const match = target.some(function(targetAudience) {
        return audiences.some(function(audience) {
          return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
        });
      });
      if (!match) {
        return done(new JsonWebTokenError("jwt audience invalid. expected: " + audiences.join(" or ")));
      }
    }
    if (options2.issuer) {
      const invalid_issuer = typeof options2.issuer === "string" && payload.iss !== options2.issuer || Array.isArray(options2.issuer) && options2.issuer.indexOf(payload.iss) === -1;
      if (invalid_issuer) {
        return done(new JsonWebTokenError("jwt issuer invalid. expected: " + options2.issuer));
      }
    }
    if (options2.subject) {
      if (payload.sub !== options2.subject) {
        return done(new JsonWebTokenError("jwt subject invalid. expected: " + options2.subject));
      }
    }
    if (options2.jwtid) {
      if (payload.jti !== options2.jwtid) {
        return done(new JsonWebTokenError("jwt jwtid invalid. expected: " + options2.jwtid));
      }
    }
    if (options2.nonce) {
      if (payload.nonce !== options2.nonce) {
        return done(new JsonWebTokenError("jwt nonce invalid. expected: " + options2.nonce));
      }
    }
    if (options2.maxAge) {
      if (typeof payload.iat !== "number") {
        return done(new JsonWebTokenError("iat required when maxAge is specified"));
      }
      const maxAgeTimestamp = timespan$1(options2.maxAge, payload.iat);
      if (typeof maxAgeTimestamp === "undefined") {
        return done(new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
      if (clockTimestamp >= maxAgeTimestamp + (options2.clockTolerance || 0)) {
        return done(new TokenExpiredError("maxAge exceeded", new Date(maxAgeTimestamp * 1e3)));
      }
    }
    if (options2.complete === true) {
      const signature = decodedToken.signature;
      return done(null, {
        header,
        payload,
        signature
      });
    }
    return done(null, payload);
  });
};
const timespan = timespan$2;
const PS_SUPPORTED = psSupported;
const validateAsymmetricKey = validateAsymmetricKey$2;
const jws = jws$3;
const { includes, isBoolean, isInteger, isNumber, isPlainObject, isString, once } = _;
const { KeyObject, createSecretKey, createPrivateKey } = crypto$2;
const SUPPORTED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "none"];
if (PS_SUPPORTED) {
  SUPPORTED_ALGS.splice(3, 0, "PS256", "PS384", "PS512");
}
const sign_options_schema = {
  expiresIn: { isValid: function(value) {
    return isInteger(value) || isString(value) && value;
  }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
  notBefore: { isValid: function(value) {
    return isInteger(value) || isString(value) && value;
  }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
  audience: { isValid: function(value) {
    return isString(value) || Array.isArray(value);
  }, message: '"audience" must be a string or array' },
  algorithm: { isValid: includes.bind(null, SUPPORTED_ALGS), message: '"algorithm" must be a valid string enum value' },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  mutatePayload: { isValid: isBoolean, message: '"mutatePayload" must be a boolean' },
  allowInsecureKeySizes: { isValid: isBoolean, message: '"allowInsecureKeySizes" must be a boolean' },
  allowInvalidAsymmetricKeyTypes: { isValid: isBoolean, message: '"allowInvalidAsymmetricKeyTypes" must be a boolean' }
};
const registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
};
function validate$1(schema, allowUnknown, object, parameterName) {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.');
  }
  Object.keys(object).forEach(function(key) {
    const validator = schema[key];
    if (!validator) {
      if (!allowUnknown) {
        throw new Error('"' + key + '" is not allowed in "' + parameterName + '"');
      }
      return;
    }
    if (!validator.isValid(object[key])) {
      throw new Error(validator.message);
    }
  });
}
function validateOptions(options2) {
  return validate$1(sign_options_schema, false, options2, "options");
}
function validatePayload(payload) {
  return validate$1(registered_claims_schema, true, payload, "payload");
}
const options_to_payload = {
  "audience": "aud",
  "issuer": "iss",
  "subject": "sub",
  "jwtid": "jti"
};
const options_for_objects = [
  "expiresIn",
  "notBefore",
  "noTimestamp",
  "audience",
  "issuer",
  "subject",
  "jwtid"
];
var sign2 = function(payload, secretOrPrivateKey, options2, callback) {
  if (typeof options2 === "function") {
    callback = options2;
    options2 = {};
  } else {
    options2 = options2 || {};
  }
  const isObjectPayload = typeof payload === "object" && !Buffer.isBuffer(payload);
  const header = Object.assign({
    alg: options2.algorithm || "HS256",
    typ: isObjectPayload ? "JWT" : void 0,
    kid: options2.keyid
  }, options2.header);
  function failure(err) {
    if (callback) {
      return callback(err);
    }
    throw err;
  }
  if (!secretOrPrivateKey && options2.algorithm !== "none") {
    return failure(new Error("secretOrPrivateKey must have a value"));
  }
  if (secretOrPrivateKey != null && !(secretOrPrivateKey instanceof KeyObject)) {
    try {
      secretOrPrivateKey = createPrivateKey(secretOrPrivateKey);
    } catch (_2) {
      try {
        secretOrPrivateKey = createSecretKey(typeof secretOrPrivateKey === "string" ? Buffer.from(secretOrPrivateKey) : secretOrPrivateKey);
      } catch (_3) {
        return failure(new Error("secretOrPrivateKey is not valid key material"));
      }
    }
  }
  if (header.alg.startsWith("HS") && secretOrPrivateKey.type !== "secret") {
    return failure(new Error(`secretOrPrivateKey must be a symmetric key when using ${header.alg}`));
  } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
    if (secretOrPrivateKey.type !== "private") {
      return failure(new Error(`secretOrPrivateKey must be an asymmetric key when using ${header.alg}`));
    }
    if (!options2.allowInsecureKeySizes && !header.alg.startsWith("ES") && secretOrPrivateKey.asymmetricKeyDetails !== void 0 && //KeyObject.asymmetricKeyDetails is supported in Node 15+
    secretOrPrivateKey.asymmetricKeyDetails.modulusLength < 2048) {
      return failure(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
    }
  }
  if (typeof payload === "undefined") {
    return failure(new Error("payload is required"));
  } else if (isObjectPayload) {
    try {
      validatePayload(payload);
    } catch (error) {
      return failure(error);
    }
    if (!options2.mutatePayload) {
      payload = Object.assign({}, payload);
    }
  } else {
    const invalid_options = options_for_objects.filter(function(opt) {
      return typeof options2[opt] !== "undefined";
    });
    if (invalid_options.length > 0) {
      return failure(new Error("invalid " + invalid_options.join(",") + " option for " + typeof payload + " payload"));
    }
  }
  if (typeof payload.exp !== "undefined" && typeof options2.expiresIn !== "undefined") {
    return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
  }
  if (typeof payload.nbf !== "undefined" && typeof options2.notBefore !== "undefined") {
    return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
  }
  try {
    validateOptions(options2);
  } catch (error) {
    return failure(error);
  }
  if (!options2.allowInvalidAsymmetricKeyTypes) {
    try {
      validateAsymmetricKey(header.alg, secretOrPrivateKey);
    } catch (error) {
      return failure(error);
    }
  }
  const timestamp = payload.iat || Math.floor(Date.now() / 1e3);
  if (options2.noTimestamp) {
    delete payload.iat;
  } else if (isObjectPayload) {
    payload.iat = timestamp;
  }
  if (typeof options2.notBefore !== "undefined") {
    try {
      payload.nbf = timespan(options2.notBefore, timestamp);
    } catch (err) {
      return failure(err);
    }
    if (typeof payload.nbf === "undefined") {
      return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }
  if (typeof options2.expiresIn !== "undefined" && typeof payload === "object") {
    try {
      payload.exp = timespan(options2.expiresIn, timestamp);
    } catch (err) {
      return failure(err);
    }
    if (typeof payload.exp === "undefined") {
      return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }
  Object.keys(options_to_payload).forEach(function(key) {
    const claim = options_to_payload[key];
    if (typeof options2[key] !== "undefined") {
      if (typeof payload[claim] !== "undefined") {
        return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
      }
      payload[claim] = options2[key];
    }
  });
  const encoding = options2.encoding || "utf8";
  if (typeof callback === "function") {
    callback = callback && once(callback);
    jws.createSign({
      header,
      privateKey: secretOrPrivateKey,
      payload,
      encoding
    }).once("error", callback).once("done", function(signature) {
      if (!options2.allowInsecureKeySizes && /^(?:RS|PS)/.test(header.alg) && signature.length < 256) {
        return callback(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
      }
      callback(null, signature);
    });
  } else {
    let signature = jws.sign({ header, payload, secret: secretOrPrivateKey, encoding });
    if (!options2.allowInsecureKeySizes && /^(?:RS|PS)/.test(header.alg) && signature.length < 256) {
      throw new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`);
    }
    return signature;
  }
};
(function(module) {
  module.exports = {
    verify: verify2,
    sign: sign2,
    JsonWebTokenError: JsonWebTokenError_1,
    NotBeforeError: NotBeforeError_1,
    TokenExpiredError: TokenExpiredError_1
  };
  Object.defineProperty(module.exports, "decode", {
    enumerable: false,
    value: decode$1
  });
})(jsonwebtoken);
var jsonwebtokenExports = jsonwebtoken.exports;
const jwt = /* @__PURE__ */ getDefaultExportFromCjs(jsonwebtokenExports);
var getRandomValues;
var rnds8 = new Uint8Array(16);
function rng() {
  if (!getRandomValues) {
    getRandomValues = typeof crypto !== "undefined" && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== "undefined" && typeof msCrypto.getRandomValues === "function" && msCrypto.getRandomValues.bind(msCrypto);
    if (!getRandomValues) {
      throw new Error("crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported");
    }
  }
  return getRandomValues(rnds8);
}
const REGEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
function validate(uuid) {
  return typeof uuid === "string" && REGEX.test(uuid);
}
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).substr(1));
}
function stringify(arr) {
  var offset = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
  var uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
function v4(options2, buf, offset) {
  options2 = options2 || {};
  var rnds = options2.random || (options2.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  return stringify(rnds);
}
function getOAuthConfig() {
  const jwtAlg = strapi.plugin("oauth2").config("jwtAlg") || "HS256";
  const jwtSignKey = strapi.plugin("oauth2").config("jwtSignKey");
  const accessTokenTTL = strapi.plugin("oauth2").config("accessTokenTTL") || 3600;
  const audience = strapi.plugin("oauth2").config("audience");
  const authCodeTtlSeconds = strapi.plugin("oauth2").config("authCodeTtlSeconds") || 300;
  const loginUrl = strapi.plugin("oauth2").config("loginUrl");
  const maxAssertionTtl = strapi.plugin("oauth2").config("maxAssertionTtl") || 300;
  let jwtPublicKeyPath = strapi.plugin("oauth2").config("jwtPublicKey") || "./assets/oauth2/public.key";
  let jwtPrivateKeyPath = strapi.plugin("oauth2").config("jwtPrivateKey") || "./assets/oauth2/private.key";
  const jwtRS256Bits = strapi.plugin("oauth2").config("jwtRS256Bits") || 2048;
  jwtPublicKeyPath = path.join(process.cwd(), jwtPublicKeyPath);
  jwtPrivateKeyPath = path.join(process.cwd(), jwtPrivateKeyPath);
  if (jwtAlg === "RS256" && !fs.existsSync(jwtPublicKeyPath)) {
    throw new Error(`OAuth2 plugin: JWT public key file not found at path: ${jwtPublicKeyPath}`);
  } else if (jwtAlg === "RS256" && !fs.existsSync(jwtPrivateKeyPath)) {
    throw new Error(`OAuth2 plugin: JWT private key file not found at path: ${jwtPrivateKeyPath}`);
  }
  const jwtPublicKey = fs.readFileSync(jwtPublicKeyPath, "utf8");
  const jwtPrivateKey = fs.readFileSync(jwtPrivateKeyPath, "utf8");
  return {
    jwtAlg,
    jwtSignKey,
    accessTokenTTL,
    jwtPublicKey,
    jwtPrivateKey,
    audience,
    authCodeTtlSeconds,
    loginUrl,
    maxAssertionTtl,
    jwtRS256Bits
  };
}
async function hashSecret(secret) {
  const saltRounds = 12;
  return await bcrypt.hash(secret, saltRounds);
}
async function verifySecret(secret, hash) {
  return await bcrypt.compare(secret, hash);
}
function generateClientId() {
  return v4().replace(/-/g, "");
}
function generateRawSecret(bytes = 32) {
  return crypto$2.randomBytes(bytes).toString("hex");
}
function signJWT(payload, opts = {}) {
  const { jwtAlg, jwtSignKey, jwtPrivateKey, accessTokenTTL } = getOAuthConfig();
  const signKey = jwtAlg === "RS256" ? jwtPrivateKey : jwtSignKey;
  const signOpts = {
    algorithm: jwtAlg
  };
  if (opts.expiresIn !== void 0) {
    signOpts.expiresIn = Number(opts.expiresIn);
  } else {
    signOpts.expiresIn = accessTokenTTL;
  }
  return jwt.sign(payload, signKey, signOpts);
}
function verifyJWT(token, {
  jwtAlgOverride,
  verifyKeyOverride
} = {}) {
  const {
    jwtAlg: _jwtAlg,
    jwtSignKey: _jwtSignKey,
    jwtPublicKey: _jwtPublicKey
  } = getOAuthConfig();
  const jwtAlg = jwtAlgOverride || _jwtAlg;
  const jwtSignKey = verifyKeyOverride || _jwtSignKey;
  const jwtPublicKey = verifyKeyOverride || _jwtPublicKey;
  const verifyKey = jwtAlg === "RS256" ? jwtPublicKey : jwtSignKey;
  try {
    const decoded = jwt.verify(token, verifyKey, { algorithms: [jwtAlg] });
    return { ok: true, decoded };
  } catch (err) {
    return { ok: false, err };
  }
}
function generateJti() {
  return v4();
}
function generateAuthCode(bytes = 32) {
  return crypto$2.randomBytes(bytes).toString("hex");
}
function hashValue(value) {
  return crypto$2.createHash("sha256").update(value).digest("hex");
}
function verifyPkce(codeVerifier, codeChallenge, method = "S256") {
  if (!codeVerifier) return false;
  if (method === "plain") {
    return codeVerifier === codeChallenge;
  }
  if (method === "S256") {
    const hash = crypto$2.createHash("sha256").update(codeVerifier).digest();
    const b64 = hash.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return b64 === codeChallenge;
  }
  return false;
}
function generateRSAKeyPair() {
  const { jwtRS256Bits } = getOAuthConfig();
  const { publicKey, privateKey } = crypto$2.generateKeyPairSync("rsa", {
    modulusLength: jwtRS256Bits,
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem"
    }
  });
  return { publicKey, privateKey };
}
const bootstrap = async ({ strapi: strapi2 }) => {
  const config2 = getOAuthConfig();
  if (!["HS256", "RS256"].includes(config2?.jwtAlg)) {
    throw new Error("OAuth2 plugin: Unsupported JWT algorithm (OAUTH_JWT_ALG) configured");
  } else if (!config2.audience) {
    throw new Error("OAuth2 plugin: JWT audience (OAUTH_AUD) is not configured");
  } else if (!config2.loginUrl) {
    throw new Error("OAuth2 plugin: Login URL (OAUTH_LOGIN_URL) is not configured");
  } else if (config2.jwtAlg === "RS256" && !config2.jwtPublicKey && !config2.jwtPrivateKey) {
    throw new Error(
      "OAuth2 plugin: RSA public/private key pair is not configured for RS256 algorithm (OAUTH_JWT_PUBLIC_KEY and OAUTH_JWT_PRIVATE_KEY)"
    );
  } else if (config2.jwtAlg === "HS256" && !config2.jwtSignKey) {
    throw new Error(
      "OAuth2 plugin: JWT sign key (OAUTH_JWT_SIGN_KEY) is not configured for HS256 algorithm"
    );
  }
  const actions = [
    {
      section: "plugins",
      displayName: "Read global settings",
      uid: "oauth-global-setting.read",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Update global settings",
      uid: "oauth-global-setting.update",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Read available scopes",
      uid: "oauth.read",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Create client",
      uid: "oauth-client.create",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Rotate client secret",
      uid: "oauth-client.rotate",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Read clients",
      uid: "oauth-client.read",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Update client",
      uid: "oauth-client.update",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Delete client",
      uid: "oauth-client.delete",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Read access tokens",
      uid: "oauth-access-token.read",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Revoke access token",
      uid: "oauth-access-token.revoke",
      pluginName: "oauth2"
    },
    {
      section: "plugins",
      displayName: "Generate client keypair",
      uid: "oauth-client.generate-keypair",
      pluginName: "oauth2"
    }
  ];
  strapi2.admin.services.permission.actionProvider.registerMany(actions);
  let accessKey;
  const tokenExists = await strapi2.service("admin::api-token").exists({
    name: "OAuth2 Plugin System Token"
  });
  if (!tokenExists) {
    const result = await strapi2.service("admin::api-token").create({
      name: "OAuth2 Plugin System Token",
      description: "System token for Strapi OAuth2 plugin to access internal APIs",
      type: "custom",
      lifespan: null,
      permissions: []
    });
    accessKey = result.accessKey;
  }
  const globalSettings = await strapi2.documents("plugin::oauth2.oauth-global-setting").findFirst();
  if (!globalSettings) {
    await strapi2.documents("plugin::oauth2.oauth-global-setting").create({
      data: {
        systemAccessKey: accessKey,
        scopes: []
      }
    });
  } else if (accessKey && !globalSettings.systemAccessKey) {
    await strapi2.documents("plugin::oauth2.oauth-global-setting").update({
      documentId: globalSettings.documentId,
      data: {
        systemAccessKey: accessKey
      }
    });
  }
};
const destroy = ({ strapi: strapi2 }) => {
};
const register = ({ strapi: strapi2 }) => {
};
const config = ({ env }) => ({
  default: {},
  validator() {
  }
});
const kind$4 = "collectionType";
const collectionName$4 = "oauth-access-tokens";
const info$4 = {
  singularName: "oauth-access-token",
  pluralName: "oauth-access-tokens",
  displayName: "OAuth Access Token"
};
const options$4 = {
  draftAndPublish: false
};
const pluginOptions$4 = {};
const attributes$4 = {
  accessToken: {
    type: "string",
    required: true,
    "private": true
  },
  jti: {
    type: "string",
    required: true,
    unique: true
  },
  client: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::oauth2.oauth-client",
    required: true
  },
  expiresAt: {
    type: "datetime",
    required: true
  },
  scope: {
    type: "string"
  },
  revokedAt: {
    type: "datetime"
  },
  grantType: {
    type: "string",
    required: true,
    "enum": [
      "authorization_code",
      "client_credentials"
    ]
  },
  user: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::users-permissions.user",
    required: true
  }
};
const oauthAccessToken$3 = {
  kind: kind$4,
  collectionName: collectionName$4,
  info: info$4,
  options: options$4,
  pluginOptions: pluginOptions$4,
  attributes: attributes$4
};
const kind$3 = "collectionType";
const collectionName$3 = "oauth-clients";
const info$3 = {
  singularName: "oauth-client",
  pluralName: "oauth-clients",
  displayName: "OAuth Client"
};
const options$3 = {
  draftAndPublish: false
};
const pluginOptions$3 = {};
const attributes$3 = {
  clientId: {
    type: "string",
    unique: true
  },
  clientSecretHash: {
    type: "string",
    "private": true
  },
  jwtAlg: {
    type: "enumeration",
    required: true,
    "enum": [
      "HS256",
      "RS256",
      "ES256"
    ]
  },
  publicKey: {
    type: "string"
  },
  name: {
    type: "string",
    required: true
  },
  scopes: {
    type: "json"
  },
  redirectUris: {
    type: "json"
  },
  active: {
    type: "boolean",
    "default": true
  },
  meta: {
    type: "json"
  },
  user: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::users-permissions.user"
  },
  clientType: {
    type: "enumeration",
    required: true,
    "enum": [
      "CONFIDENTIAL",
      "PUBLIC"
    ]
  },
  createdType: {
    type: "enumeration",
    required: true,
    "enum": [
      "USER",
      "BACK_OFFICE"
    ]
  }
};
const oauthClient$3 = {
  kind: kind$3,
  collectionName: collectionName$3,
  info: info$3,
  options: options$3,
  pluginOptions: pluginOptions$3,
  attributes: attributes$3
};
const kind$2 = "collectionType";
const collectionName$2 = "oauth-users";
const info$2 = {
  singularName: "oauth-user",
  pluralName: "oauth-users",
  displayName: "OAuth User"
};
const options$2 = {
  draftAndPublish: false
};
const pluginOptions$2 = {};
const attributes$2 = {
  userDocumentId: {
    type: "string",
    required: true
  },
  clientId: {
    type: "string",
    required: true
  },
  scopes: {
    type: "json"
  },
  apiTokenId: {
    type: "integer",
    min: 1,
    required: true
  },
  apiTokenAccessKey: {
    type: "string",
    required: true,
    "private": true,
    searchable: false
  },
  client: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::oauth2.oauth-client"
  },
  user: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::users-permissions.user"
  }
};
const oauthUser = {
  kind: kind$2,
  collectionName: collectionName$2,
  info: info$2,
  options: options$2,
  pluginOptions: pluginOptions$2,
  attributes: attributes$2
};
const kind$1 = "singleType";
const collectionName$1 = "oauth-global-settings";
const info$1 = {
  singularName: "oauth-global-setting",
  pluralName: "oauth-global-settings",
  displayName: "OAuth Global Setting"
};
const options$1 = {
  draftAndPublish: false
};
const pluginOptions$1 = {};
const attributes$1 = {
  systemAccessKey: {
    type: "password",
    required: true,
    "private": true,
    searchable: false
  },
  scopes: {
    type: "json"
  }
};
const oauthGlobalSetting$3 = {
  kind: kind$1,
  collectionName: collectionName$1,
  info: info$1,
  options: options$1,
  pluginOptions: pluginOptions$1,
  attributes: attributes$1
};
const kind = "collectionType";
const collectionName = "oauth-authorization-codes";
const info = {
  singularName: "oauth-authorization-code",
  pluralName: "oauth-authorization-codes",
  displayName: "OAuth Authorization Code"
};
const options = {
  draftAndPublish: false
};
const pluginOptions = {};
const attributes = {
  codeHash: {
    type: "string",
    "private": true
  },
  client: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::oauth2.oauth-client"
  },
  user: {
    type: "relation",
    relation: "manyToOne",
    target: "plugin::users-permissions.user"
  },
  scopes: {
    type: "json"
  },
  redirectUri: {
    type: "string",
    required: true
  },
  codeChallenge: {
    type: "string"
  },
  codeChallengeMethod: {
    type: "string"
  },
  expiresAt: {
    type: "datetime",
    required: true
  },
  usedAt: {
    type: "datetime"
  },
  meta: {
    type: "json"
  }
};
const oauthAuthorizationCode$3 = {
  kind,
  collectionName,
  info,
  options,
  pluginOptions,
  attributes
};
const contentTypes = {
  "oauth-access-token": {
    schema: oauthAccessToken$3
  },
  "oauth-client": {
    schema: oauthClient$3
  },
  "oauth-user": {
    schema: oauthUser
  },
  "oauth-global-setting": {
    schema: oauthGlobalSetting$3
  },
  "oauth-authorization-code": {
    schema: oauthAuthorizationCode$3
  }
};
const controller = ({ strapi: strapi2 }) => ({
  async getAvailableScopes(ctx) {
    const scopes = {};
    const actions = await strapi2.plugin("users-permissions").service("users-permissions").getActions();
    for (const [k, v] of Object.entries(actions)) {
      let key = k;
      for (const [k2, v2] of Object.entries(v.controllers || {})) {
        key = `${k}.${k2}`;
        if (!scopes[key]) {
          scopes[key] = [];
        }
        for (const action in v2) {
          scopes[key].push({
            name: `${key}.${action}`,
            action
          });
        }
      }
    }
    ctx.send(scopes);
  }
});
const { ValidationError: ValidationError$6, NotFoundError: NotFoundError$4, UnauthorizedError: UnauthorizedError$1 } = utils.errors;
const handleError = (ctx, error) => {
  let title = "other error";
  let details = {
    code: 9999,
    message: "other error"
  };
  if (error.details) {
    title = error.message ? error.message : title;
    details = error.details;
  }
  if (error instanceof NotFoundError$4) {
    ctx.notFound(title, details);
  } else if (error instanceof ValidationError$6) {
    ctx.badRequest(title, details);
  } else if (error instanceof UnauthorizedError$1) {
    ctx.unauthorized(title, details);
  } else {
    ctx.internalServerError(title, details);
  }
  strapi.log.error(`http: ${ctx.request.method} ${ctx.request.url}`);
  if (ctx.request.body && Object.keys(ctx.request.body).length > 0) {
    strapi.log.error(`body: ${JSON.stringify(ctx.request.body)}`);
  }
  strapi.log.error(
    `error: ${JSON.stringify({
      title,
      details
    })}`
  );
};
const { ValidationError: ValidationError$5 } = utils.errors;
const oauthAccessToken$2 = factories.createCoreController(
  "plugin::oauth2.oauth-access-token",
  ({ strapi: strapi2 }) => ({
    async introspect(ctx) {
      try {
        const token = ctx.request.body.token;
        if (!token) throw new ValidationError$5("token is required");
        const res = await strapi2.service("plugin::oauth2.oauth-access-token").introspectByToken(token);
        return res;
      } catch (err) {
        handleError(ctx, err);
      }
    },
    async revoke(ctx) {
      try {
        const jti = ctx.request.body.jti;
        if (!jti) throw new ValidationError$5("jti is required");
        const ok = await strapi2.service("plugin::oauth2.oauth-access-token").revokeTokenByJti(jti, ctx.state.user?.documentId);
        return {
          revoked: ok
        };
      } catch (err) {
        handleError(ctx, err);
      }
    },
    async token(ctx) {
      try {
        const { grant_type } = ctx.request.body;
        if (grant_type === "authorization_code") {
          const { code, redirect_uri, code_verifier } = ctx.request.body;
          if (!code || !redirect_uri) {
            throw new ValidationError$5("invalid_request", {
              error: "invalid_request",
              message: "code and redirect_uri are required"
            });
          }
          return await strapi2.db.transaction(async () => {
            const { client, authorizationUser, scopes } = await strapi2.service("plugin::oauth2.oauth-authorization-code").consumeAuthorizationCode({
              rawCode: code,
              redirectUri: redirect_uri,
              codeVerifier: code_verifier
            });
            if (client.clientType === "CONFIDENTIAL") {
              let clientId;
              let clientSecret;
              const auth = ctx.request.header.authorization;
              if (auth && auth.startsWith("Basic ")) {
                const creds = Buffer.from(auth.slice("Basic ".length), "base64").toString();
                [clientId, clientSecret] = creds.split(":");
              } else {
                clientId = ctx.request.body.client_id;
                clientSecret = ctx.request.body.client_secret;
              }
              if (!clientId || !clientSecret) {
                throw new ValidationError$5("missing_client_credentials", {
                  error: "invalid_client_credentials"
                });
              }
              const validatedClient = await strapi2.service("plugin::oauth2.oauth-client").validateClientCredentials(clientId, clientSecret);
              if (!validatedClient || validatedClient.id !== client.id) {
                throw new UnauthorizedError$2("invalid_client_credentials", {
                  error: "invalid_client_credentials",
                  message: "mismatched client credentials"
                });
              }
            }
            const tokenResp = await strapi2.service("plugin::oauth2.oauth-access-token").issueAccessToken({
              grantType: grant_type,
              client,
              userDocumentId: authorizationUser.documentId,
              scope: scopes.join(" ")
            });
            return tokenResp;
          });
        } else if (grant_type === "client_credentials") {
          throw new ValidationError$5("grant_type_deprecated", {
            error: "grant_type_deprecated",
            message: "client_credentials is no longer supported"
          });
        } else if (grant_type === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
          const { assertion } = ctx.request.body;
          if (!assertion) {
            throw new ValidationError$5("invalid_request", {
              error: "invalid_request",
              message: "assertion is required"
            });
          }
          const { client, decoded } = await strapi2.service("plugin::oauth2.oauth-access-token").verifyJWTBearer(assertion);
          if (client.clientType === "CONFIDENTIAL") {
            let clientId;
            let clientSecret;
            const auth = ctx.request.header.authorization;
            if (auth && auth.startsWith("Basic ")) {
              const creds = Buffer.from(auth.slice("Basic ".length), "base64").toString();
              [clientId, clientSecret] = creds.split(":");
            } else {
              clientId = ctx.request.body.client_id;
              clientSecret = ctx.request.body.client_secret;
            }
            if (!clientId || !clientSecret) {
              throw new ValidationError$5("missing_client_credentials", {
                error: "invalid_client_credentials"
              });
            }
            const validatedClient = await strapi2.service("plugin::oauth2.oauth-client").validateClientCredentials(clientId, clientSecret);
            if (!validatedClient || validatedClient.id !== client.id) {
              throw new UnauthorizedError$2("invalid_client_credentials", {
                error: "invalid_client_credentials",
                message: "mismatched client credentials"
              });
            }
          } else {
            throw new ValidationError$5("unauthorized_client", {
              error: "unauthorized_client",
              message: "only CONFIDENTIAL client is allowed to use this grant type"
            });
          }
          if (!decoded.scope) {
            throw new ValidationError$5("invalid_scope", {
              error: "invalid_scope",
              message: "scope is required in assertion"
            });
          }
          const requestedScopes = decoded.scope.split(" ");
          const globalSettings = await strapi2.documents("plugin::oauth2.oauth-global-setting").findFirst();
          const availableScopes = globalSettings?.scopes || [];
          if (!availableScopes.length) {
            throw new ValidationError$5("invalid_scope", {
              error: "invalid_scope",
              message: "no available scopes defined"
            });
          }
          for (const s2 of requestedScopes) {
            if (!availableScopes.includes(s2)) {
              throw new ValidationError$5("invalid_scope", {
                error: "invalid_scope",
                message: `scope ${s2} is not allowed for this client`
              });
            }
          }
          const tokenResp = await strapi2.service("plugin::oauth2.oauth-access-token").issueAccessToken({
            grantType: grant_type,
            client,
            userDocumentId: client.user?.documentId,
            scope: requestedScopes.join(" ")
          });
          return tokenResp;
        } else {
          throw new ValidationError$5("unsupported_grantType", {
            error: "unsupported_grantType"
          });
        }
      } catch (err) {
        handleError(ctx, err);
      }
    }
  })
);
const { NotFoundError: NotFoundError$3, ValidationError: ValidationError$4 } = utils.errors;
const oauthClient$2 = factories.createCoreController("plugin::oauth2.oauth-client", ({ strapi: strapi2 }) => ({
  async find(ctx) {
    const filters = ctx.query?.filters || {};
    if (ctx.state.user && ctx.state.auth?.strategy?.name !== "admin") {
      _.set(filters, "user.documentId", ctx.state.user.documentId);
    }
    return await super.find({ ...ctx, query: { ...ctx.query, filters } });
  },
  async findOne(ctx) {
    const filters = ctx.query?.filters || {};
    if (ctx.state.user && ctx.state.auth?.strategy?.name !== "admin") {
      _.set(filters, "user.documentId", ctx.state.user.documentId);
    }
    return await super.findOne({ ...ctx, query: { ...ctx.query, filters } });
  },
  async rotateSecret(ctx) {
    try {
      const { documentId } = ctx.params;
      const entity = await strapi2.service("plugin::oauth2.oauth-client").rotateClientSecret(documentId, ctx.state.user?.documentId);
      const sanitizedOutput = await this.sanitizeOutput(entity, ctx);
      return this.transformResponse(sanitizedOutput);
    } catch (err) {
      handleError(ctx, err);
    }
  },
  async findOneByClientId(ctx) {
    try {
      const { clientId } = ctx.params;
      const scope = ctx.query?.scope;
      if (!scope) {
        throw new ValidationError$4("scope is required");
      }
      const scopes = scope.split(",");
      const filters = {
        clientId
      };
      if (ctx.state.user) {
        _.set(filters, "user.documentId", ctx.state.user.documentId);
      }
      const client = await strapi2.documents("plugin::oauth2.oauth-client").findFirst({
        filters
      });
      if (!client) throw new NotFoundError$3("client_not_found");
      let availableScopes = { ...client.scopes };
      if (client.createdType === "USER") {
        const globalSettings = await strapi2.documents("plugin::oauth2.oauth-global-setting").findFirst();
        availableScopes = globalSettings?.scopes || {};
        if (!availableScopes?.length) {
          throw new ValidationError$4("no_available_scopes_defined");
        }
      }
      const clientUser = await strapi2.documents("plugin::oauth2.oauth-user").findFirst({
        filters: {
          userDocumentId: ctx.state.user?.documentId,
          clientId: client.clientId
        }
      });
      for (const s2 of scopes) {
        if (!availableScopes.includes(s2)) {
          throw new ValidationError$4(`invalid_scope: ${s2}`);
        }
      }
      return {
        documentId: client.documentId,
        clientId: client.clientId,
        userId: client.user?.documentId,
        clientType: client.clientType,
        name: client.name,
        scopes,
        grantedScopes: clientUser?.scopes || [],
        redirectUris: client.redirectUris,
        meta: client.meta
      };
    } catch (err) {
      handleError(ctx, err);
    }
  },
  async generateKeyPair(ctx) {
    try {
      const { documentId } = ctx.params;
      const entity = await strapi2.service("plugin::oauth2.oauth-client").generateKeyPair(documentId);
      const sanitizedOutput = await this.sanitizeOutput(entity, ctx);
      return this.transformResponse(sanitizedOutput);
    } catch (err) {
      handleError(ctx, err);
    }
  },
  async delete(ctx) {
    try {
      return await super.delete(ctx);
    } catch (err) {
      handleError(ctx, err);
    }
  }
}));
const oauthGlobalSetting$2 = factories.createCoreController("plugin::oauth2.oauth-global-setting");
const { ValidationError: ValidationError$3, UnauthorizedError } = utils.errors;
const oauthAuthorizationCode$2 = factories.createCoreController(
  "plugin::oauth2.oauth-authorization-code",
  ({ strapi: strapi2 }) => ({
    async authorize(ctx) {
      const { approve, clientId, redirectUri, scopes, state, codeChallenge, codeChallengeMethod } = ctx.request.body;
      try {
        if (!ctx.state.user) throw new UnauthorizedError("login_required");
        if (!approve) {
          const q2 = qs.stringify({ error: "access_denied", state });
          return {
            redirectUri: `${redirectUri}?${q2}`
          };
        }
        const rawCode = await strapi2.plugin("oauth2").service("oauth-authorization-code").createAuthorizationCode({
          clientId,
          userDocumentId: ctx.state.user.documentId,
          redirectUri,
          scopes,
          codeChallenge,
          codeChallengeMethod
        });
        const q = qs.stringify({ code: rawCode, state });
        return {
          redirectUri: `${redirectUri}?${q}`
        };
      } catch (err) {
        const q = qs.stringify({ error: err.message || "access_denied", state });
        return {
          redirectUri: `${redirectUri}?${q}`
        };
      }
    },
    async introspect(ctx) {
      try {
        const token = ctx.request.body.token;
        if (!token) throw new ValidationError$3("token is required");
        const res = await strapi2.service("plugin::oauth2.oauth-access-token").introspectByToken(token);
        return res;
      } catch (err) {
        handleError(ctx, err);
      }
    },
    async revoke(ctx) {
      try {
        const jti = ctx.request.body.jti;
        if (!jti) throw new ValidationError$3("jti is required");
        const ok = await strapi2.service("plugin::oauth2.oauth-access-token").revokeTokenByJti(jti, ctx.state.user?.documentId);
        return {
          revoked: ok
        };
      } catch (err) {
        handleError(ctx, err);
      }
    }
  })
);
const controllers = {
  oauth: controller,
  "oauth-access-token": oauthAccessToken$2,
  "oauth-client": oauthClient$2,
  "oauth-global-setting": oauthGlobalSetting$2,
  "oauth-authorization-code": oauthAuthorizationCode$2
};
const oauthVerifyToken = () => {
  return async (ctx, next) => {
    const auth = ctx.request.header.authorization;
    if (!auth || !auth.startsWith("Bearer ")) {
      return await next();
    }
    const { audience } = getOAuthConfig();
    const token = auth.slice("Bearer ".length);
    const decoded = jwt.decode(token);
    if (!decoded?.aud || decoded.aud !== audience) {
      return await next();
    }
    const introspect = await strapi.service("plugin::oauth2.oauth-access-token").introspectByToken(token);
    if (!introspect || !introspect.active) {
      return ctx.throw(401, "token_user_mismatch");
    }
    const oauthUser2 = await strapi.documents("plugin::oauth2.oauth-user").findFirst({
      filters: {
        clientId: introspect.clientId,
        userDocumentId: introspect.userId
      }
    });
    if (!oauthUser2) {
      return ctx.throw(401, "token_user_mismatch");
    }
    ctx.request.headers["authorization"] = `Bearer ${oauthUser2.apiTokenAccessKey}`;
    ctx.state.oauth = {
      grantType: introspect.grantType,
      clientId: introspect.clientId,
      userId: introspect.userId,
      scope: introspect.scope,
      jti: introspect.jti,
      raw: introspect
    };
    await next();
  };
};
const middlewares = {
  "oauth-verify-token": oauthVerifyToken
};
const policies = {};
const oauthAccessToken$1 = [
  {
    method: "GET",
    path: "/oauth-access-tokens",
    handler: "oauth-access-token.find",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "GET",
    path: "/oauth-access-tokens/:documentId",
    handler: "oauth-access-token.findOne",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "POST",
    path: "/oauth-access-tokens/token",
    handler: "oauth-access-token.token",
    config: {
      policies: [],
      middlewares: ["plugin::users-permissions.rateLimit"]
    }
  },
  {
    method: "POST",
    path: "/oauth-access-tokens/revoke",
    handler: "oauth-access-token.revoke",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "POST",
    path: "/oauth-access-tokens/introspect",
    handler: "oauth-access-token.introspect",
    config: {
      policies: [],
      middlewares: []
    }
  }
];
const oauthClient$1 = [
  {
    method: "GET",
    path: "/oauth-clients",
    handler: "oauth-client.find",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "GET",
    path: "/oauth-clients/:documentId",
    handler: "oauth-client.findOne",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "GET",
    path: "/oauth-clients-authorization/:clientId",
    handler: "oauth-client.findOneByClientId",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "POST",
    path: "/oauth-clients",
    handler: "oauth-client.create",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "PUT",
    path: "/oauth-clients/:documentId",
    handler: "oauth-client.update",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "PUT",
    path: "/oauth-clients-rotate/:documentId",
    handler: "oauth-client.rotateSecret",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "DELETE",
    path: "/oauth-clients/:documentId",
    handler: "oauth-client.delete",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "PUT",
    path: "/oauth-clients-keypair/:documentId",
    handler: "oauth-client.generateKeyPair",
    config: {
      policies: [],
      middlewares: []
    }
  }
];
const oauthGlobalSetting$1 = [
  {
    method: "GET",
    path: "/oauth-global-settings",
    handler: "oauth-global-setting.find",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "PUT",
    path: "/oauth-global-settings/:documentId",
    handler: "oauth-global-setting.update",
    config: {
      policies: [],
      middlewares: []
    }
  }
];
const oauthAuthorizationCode$1 = [
  {
    method: "GET",
    path: "/oauth-authorization-codes",
    handler: "oauth-authorization-code.find",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "GET",
    path: "/oauth-authorization-codes/:documentId",
    handler: "oauth-authorization-code.findOne",
    config: {
      policies: [],
      middlewares: []
    }
  },
  {
    method: "POST",
    path: "/oauth-authorization-codes/authorize",
    handler: "oauth-authorization-code.authorize",
    config: {
      policies: [],
      middlewares: ["plugin::users-permissions.rateLimit"]
    }
  }
];
const contentAPI = {
  type: "content-api",
  routes: [...oauthAccessToken$1, ...oauthClient$1, ...oauthGlobalSetting$1, ...oauthAuthorizationCode$1]
};
const oauth = [
  {
    method: "GET",
    path: "/global-settings",
    handler: "oauth-global-setting.find",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-global-setting.read"]
          }
        }
      ]
    }
  },
  {
    method: "PUT",
    path: "/global-settings/:documentId",
    handler: "oauth-global-setting.update",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-global-setting.update"]
          }
        }
      ]
    }
  },
  {
    method: "GET",
    path: "/scopes",
    handler: "oauth.getAvailableScopes",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth.read"]
          }
        }
      ]
    }
  },
  {
    method: "POST",
    path: "/clients",
    handler: "oauth-client.create",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.create"]
          }
        }
      ]
    }
  },
  {
    method: "PUT",
    path: "/clients-rotate/:documentId",
    handler: "oauth-client.rotateSecret",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.rotate"]
          }
        }
      ]
    }
  },
  {
    method: "GET",
    path: "/clients",
    handler: "oauth-client.find",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.read"]
          }
        }
      ]
    }
  },
  {
    method: "PUT",
    path: "/clients/:documentId",
    handler: "oauth-client.update",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.update"]
          }
        }
      ]
    }
  },
  {
    method: "DELETE",
    path: "/clients/:documentId",
    handler: "oauth-client.delete",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.delete"]
          }
        }
      ]
    }
  },
  {
    method: "GET",
    path: "/access-tokens",
    handler: "oauth-access-token.find",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-access-token.read"]
          }
        }
      ]
    }
  },
  {
    method: "POST",
    path: "/access-tokens/revoke",
    handler: "oauth-access-token.revoke",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-access-token.revoke"]
          }
        }
      ]
    }
  },
  {
    method: "PUT",
    path: "/clients-keypair/:documentId",
    handler: "oauth-client.generateKeyPair",
    config: {
      policies: [
        {
          name: "admin::hasPermissions",
          config: {
            actions: ["plugin::oauth2.oauth-client.generate-keypair"]
          }
        }
      ]
    }
  }
];
const admin = {
  type: "admin",
  routes: [...oauth]
};
const routes = {
  "content-api": contentAPI,
  admin
};
const { ValidationError: ValidationError$2, NotFoundError: NotFoundError$2 } = utils.errors;
const oauthAccessToken = factories.createCoreService("plugin::oauth2.oauth-access-token", ({ strapi: strapi2 }) => ({
  // issue token (JWT) and store record
  async issueAccessToken({ grantType, client, userDocumentId, scope }) {
    const { accessTokenTTL, audience } = getOAuthConfig();
    const now = Math.floor(Date.now() / 1e3);
    const jti = generateJti();
    const payload = {
      iss: userDocumentId,
      sub: client.clientId,
      aud: audience,
      iat: now,
      jti,
      scope
    };
    const token = signJWT(payload, { expiresIn: accessTokenTTL });
    const expiresAt = new Date(Date.now() + accessTokenTTL * 1e3);
    const entity = await strapi2.documents("plugin::oauth2.oauth-access-token").create({
      data: {
        accessToken: token,
        jti,
        client: client.documentId,
        expiresAt: expiresAt.toISOString(),
        scope: payload.scope,
        user: userDocumentId,
        grantType
      },
      populate: {
        user: true
      }
    });
    return {
      accessToken: entity.accessToken,
      tokenType: "Bearer",
      expiresIn: accessTokenTTL,
      scope: payload.scope
    };
  },
  // introspect by token or jti
  async introspectByToken(token, userDocumentId) {
    const res = verifyJWT(token);
    if (!res.ok) return { active: false };
    const decoded = res.decoded;
    if (typeof decoded === "string") return { active: false };
    const rec = await strapi2.documents("plugin::oauth2.oauth-access-token").findFirst({
      filters: { jti: decoded.jti }
    });
    if (!rec) return { active: false };
    const ctx = strapi2.requestContext.get();
    if (ctx.state.auth?.strategy?.name !== "admin" && userDocumentId && rec.user.documentId !== userDocumentId) {
      return false;
    }
    if (rec.revokedAt) return { active: false };
    if (new Date(rec.expiresAt) <= /* @__PURE__ */ new Date()) return { active: false };
    return {
      active: true,
      grantType: rec.grantType,
      clientId: decoded.sub,
      userId: decoded.iss,
      audience: decoded.aud,
      scope: decoded.scope,
      exp: decoded.exp,
      iat: decoded.iat,
      jti: decoded.jti
    };
  },
  async revokeTokenByJti(jti, userDocumentId) {
    const rec = await strapi2.documents("plugin::oauth2.oauth-access-token").findFirst({
      filters: { jti },
      populate: {
        user: true
      }
    });
    if (!rec) return false;
    const ctx = strapi2.requestContext.get();
    if (ctx.state.auth?.strategy?.name !== "admin" && userDocumentId && rec.user.documentId !== userDocumentId) {
      return false;
    }
    await strapi2.documents("plugin::oauth2.oauth-access-token").update({
      documentId: rec.documentId,
      data: {
        revokedAt: (/* @__PURE__ */ new Date()).toISOString()
      }
    });
    return true;
  },
  async verifyJWTBearer(assertion) {
    let decoded;
    try {
      decoded = jwt.decode(assertion, { complete: true });
    } catch (err) {
      throw new ValidationError$2("invalid_request", {
        error: "invalid_request",
        message: "invalid JWT format"
      });
    }
    if (!decoded || typeof decoded !== "object") {
      throw new ValidationError$2("invalid_request", {
        error: "invalid_request",
        message: "invalid JWT"
      });
    }
    const payload = decoded.payload || {};
    const clientId = payload.sub;
    if (!clientId) {
      throw new ValidationError$2("invalid_client", {
        error: "invalid_client",
        message: "iss or sub is required"
      });
    }
    const client = await strapi2.documents("plugin::oauth2.oauth-client").findFirst({
      filters: {
        clientId
      },
      populate: {
        user: true
      }
    });
    if (!client) {
      throw new ValidationError$2("invalid_client", {
        error: "invalid_client"
      });
    }
    if (!client.publicKey || client.jwtAlg !== "RS256") {
      throw new ValidationError$2("invalid_client", {
        error: "invalid_client",
        message: "client does not support jwt-bearer"
      });
    }
    const res = verifyJWT(assertion, {
      jwtAlgOverride: "RS256",
      verifyKeyOverride: client.publicKey
    });
    if (!res.ok) {
      throw new ValidationError$2("invalid_grant", {
        error: "invalid_grant",
        message: res.err.message || "invalid or expired assertion"
      });
    }
    const verified = res.decoded;
    if (verified.iss !== client.user.documentId) {
      throw new ValidationError$2("invalid_grant", {
        error: "invalid_grant",
        message: "user mismatch"
      });
    }
    const { audience, maxAssertionTtl } = getOAuthConfig();
    if (verified.aud !== audience) {
      throw new ValidationError$2("invalid_grant", {
        error: "invalid_grant",
        message: "audience mismatch"
      });
    }
    if (typeof verified.iat === "number" && typeof verified.exp === "number") {
      const ttl = verified.exp - verified.iat;
      if (ttl > maxAssertionTtl) {
        throw new ValidationError$2("invalid_grant", {
          error: "invalid_grant",
          message: "assertion lifetime too long"
        });
      }
    }
    return {
      client,
      decoded: verified
    };
  }
}));
const { ValidationError: ValidationError$1, NotFoundError: NotFoundError$1 } = utils.errors;
const oauthClient = factories.createCoreService("plugin::oauth2.oauth-client", ({ strapi: strapi2 }) => ({
  async findOne(documentId, params) {
    const ctx = strapi2.requestContext.get();
    documentId = documentId || ctx?.params?.documentId;
    if (!documentId) {
      throw new ValidationError$1("documentId is required");
    }
    params = params || { ...ctx.query };
    return await super.findOne(documentId, params);
  },
  async create(params) {
    const { data } = params;
    const ctx = strapi2.requestContext.get();
    if (!ctx?.state.user) {
      throw new ValidationError$1("user is required");
    }
    const clientId = generateClientId();
    const rawSecret = generateRawSecret(32);
    const secretHash = await hashSecret(rawSecret);
    const { publicKey, privateKey } = generateRSAKeyPair();
    let userDocumentId = data.user;
    const createdType = ctx.state.auth?.strategy?.name === "admin" ? "BACK_OFFICE" : "USER";
    if (createdType === "USER") {
      userDocumentId = ctx.state.user.documentId;
    }
    const entity = await strapi2.documents("plugin::oauth2.oauth-client").create({
      data: {
        ...data,
        clientId,
        clientSecretHash: secretHash,
        user: userDocumentId,
        createdType,
        jwtAlg: "RS256",
        publicKey
      },
      populate: {
        user: true
      }
    });
    return {
      ...entity,
      clientSecret: rawSecret,
      privateKey
    };
  },
  async rotateClientSecret(documentId, userDocumentId) {
    const ctx = strapi2.requestContext.get();
    const client = await strapi2.documents("plugin::oauth2.oauth-client").findFirst({
      filters: { documentId, active: true },
      populate: {
        user: true
      }
    });
    if (!client) throw new NotFoundError$1("client_not_found");
    if (ctx.state.auth?.strategy?.name !== "admin" && client.user?.documentId !== userDocumentId) {
      throw new ValidationError$1("invalid_user");
    }
    const rawSecret = generateRawSecret(32);
    const secretHash = await hashSecret(rawSecret);
    await strapi2.documents("plugin::oauth2.oauth-client").update({
      documentId: client.documentId,
      data: {
        clientSecretHash: secretHash
      }
    });
    return {
      ...client,
      clientSecret: rawSecret
    };
  },
  async update(documentId, params) {
    const ctx = strapi2.requestContext.get();
    documentId = documentId || ctx?.params?.documentId;
    if (!documentId) {
      throw new ValidationError$1("documentId is required");
    }
    params = params || { ...ctx.query };
    return await super.update(documentId, params);
  },
  async delete(documentId, params) {
    const ctx = strapi2.requestContext.get();
    documentId = documentId || ctx?.params?.documentId;
    if (!documentId) {
      throw new ValidationError$1("documentId is required");
    }
    params = params || { ...ctx.query };
    _.set(params, "populate.user", true);
    const entity = await strapi2.documents("plugin::oauth2.oauth-client").findOne({
      documentId,
      ...params
    });
    if (!entity) throw new NotFoundError$1("client_not_found");
    if (ctx.state.auth?.strategy?.name !== "admin" && entity.user?.documentId !== ctx?.state.user?.documentId) {
      throw new ValidationError$1("invalid_client_owner");
    }
    if (ctx.state.auth?.strategy?.name !== "admin" && entity.createdType !== "USER") {
      throw new ValidationError$1("cannot_delete_system_client");
    }
    return await strapi2.db.transaction(async () => {
      await strapi2.db.query("plugin::oauth2.oauth-access-token").deleteMany({
        where: {
          client: {
            documentId
          }
        }
      });
      await strapi2.db.query("plugin::oauth2.oauth-authorization-code").deleteMany({
        where: {
          client: {
            documentId
          }
        }
      });
      await strapi2.db.query("plugin::oauth2.oauth-user").deleteMany({
        where: {
          client: {
            documentId
          }
        }
      });
      await await super.delete(documentId, params);
    });
  },
  async validateClientCredentials(clientId, clientSecret) {
    const client = await strapi2.documents("plugin::oauth2.oauth-client").findFirst({
      filters: { clientId, active: true }
    });
    if (!client) return null;
    const ok = await verifySecret(clientSecret, client.clientSecretHash);
    return ok ? client : null;
  },
  async generateKeyPair(clientDocumentId) {
    const { publicKey, privateKey } = generateRSAKeyPair();
    const client = await strapi2.documents("plugin::oauth2.oauth-client").update({
      documentId: clientDocumentId,
      data: {
        jwtAlg: "RS256",
        publicKey
      },
      populate: {
        user: true
      }
    });
    return {
      ...client,
      privateKey
    };
  }
}));
const oauthGlobalSetting = factories.createCoreService("plugin::oauth2.oauth-global-setting");
const { ValidationError, NotFoundError } = utils.errors;
const oauthAuthorizationCode = factories.createCoreService(
  "plugin::oauth2.oauth-authorization-code",
  ({ strapi: strapi2 }) => ({
    async createAuthorizationCode({
      clientId,
      userDocumentId,
      redirectUri,
      scopes,
      codeChallenge,
      codeChallengeMethod
    }) {
      const { authCodeTtlSeconds } = getOAuthConfig();
      const oauthClient2 = await strapi2.documents("plugin::oauth2.oauth-client").findFirst({
        filters: {
          clientId
        },
        populate: {
          user: true
        }
      });
      if (!oauthClient2) throw new NotFoundError("invalid_client");
      if (oauthClient2.clientType === "PUBLIC") {
        if (!codeChallenge) {
          throw new ValidationError("code_challenge_required_for_public_client");
        } else if (!codeChallengeMethod) {
          throw new ValidationError("code_challenge_method_required_for_public_client");
        }
      }
      if (!oauthClient2.redirectUris.includes(redirectUri)) {
        throw new ValidationError("redirect_uri_mismatch");
      }
      let availableScopes = { ...oauthClient2.scopes };
      if (oauthClient2.createdType === "USER") {
        const globalSettings = await strapi2.documents("plugin::oauth2.oauth-global-setting").findFirst();
        availableScopes = globalSettings?.scopes || {};
        if (!availableScopes?.length) {
          throw new ValidationError("no_available_scopes_defined");
        }
      }
      for (const s2 of scopes) {
        if (!availableScopes.includes(s2)) {
          throw new ValidationError(`invalid_scope: ${s2}`);
        }
      }
      const rawCode = generateAuthCode(32);
      const codeHash = hashValue(rawCode);
      const expiresAt = new Date(Date.now() + authCodeTtlSeconds * 1e3).toISOString();
      await strapi2.db.transaction(async () => {
        await strapi2.documents("plugin::oauth2.oauth-authorization-code").create({
          data: {
            codeHash,
            client: oauthClient2.documentId,
            user: userDocumentId,
            scopes,
            redirectUri,
            codeChallenge,
            codeChallengeMethod,
            expiresAt
          }
        });
        const tokenName = `OAuth2_${oauthClient2.clientId}_${userDocumentId}`;
        const tokenExists = await strapi2.service("admin::api-token").exists({
          name: tokenName
        });
        let apiTokenId;
        let apiTokenAccessKey;
        if (!tokenExists) {
          const result = await strapi2.service("admin::api-token").create({
            name: tokenName,
            description: `System token for Strapi OAuth2 plugin to access internal APIs. Created to client_id: ${oauthClient2.clientId} and user_id: ${userDocumentId}`,
            type: "custom",
            lifespan: null,
            permissions: scopes
          });
          apiTokenId = result.id;
          apiTokenAccessKey = result.accessKey;
        }
        const userClient = await strapi2.documents("plugin::oauth2.oauth-user").findFirst({
          filters: {
            userDocumentId,
            clientId: oauthClient2.clientId
          }
        });
        if (!userClient) {
          await strapi2.documents("plugin::oauth2.oauth-user").create({
            data: {
              userDocumentId,
              clientId: oauthClient2.clientId,
              client: oauthClient2.documentId,
              user: userDocumentId,
              scopes,
              apiTokenId,
              apiTokenAccessKey
            }
          });
        } else {
          const newData = {
            scopes
          };
          if (apiTokenId && apiTokenAccessKey) {
            newData["apiTokenId"] = apiTokenId;
            newData["apiTokenAccessKey"] = apiTokenAccessKey;
          } else {
            await strapi2.service("admin::api-token").update(userClient.apiTokenId, {
              permissions: scopes
            });
          }
          await strapi2.documents("plugin::oauth2.oauth-user").update({
            documentId: userClient.documentId,
            data: newData
          });
        }
      });
      return rawCode;
    },
    async consumeAuthorizationCode({ rawCode, redirectUri, codeVerifier = null }) {
      const codeHash = hashValue(rawCode);
      const rec = await strapi2.documents("plugin::oauth2.oauth-authorization-code").findFirst({
        filters: {
          codeHash
        },
        populate: {
          client: {
            populate: {
              user: true
            }
          },
          user: true
        },
        sort: { createdAt: "desc" }
      });
      if (!rec) throw new NotFoundError("invalid_grant");
      if (rec.usedAt) throw new ValidationError("invalid_grant_already_used");
      if (new Date(rec.expiresAt) <= /* @__PURE__ */ new Date()) throw new ValidationError("invalid_grant_expired");
      if (rec.redirectUri !== redirectUri) throw new ValidationError("redirect_uri_mismatch");
      if (rec.client.clientType === "PUBLIC") {
        if (!codeVerifier) {
          throw new ValidationError("code_verifier_required_for_public_client");
        } else if (!rec.codeChallenge) {
          throw new ValidationError("code_challenge_not_found_for_public_client");
        } else if (!rec.codeChallengeMethod) {
          throw new ValidationError("code_challenge_method_not_found_for_public_client");
        }
      }
      if (rec.codeChallenge && rec.codeChallengeMethod) {
        if (!codeVerifier) throw new ValidationError("code_verifier_required");
        const ok = verifyPkce(codeVerifier, rec.codeChallenge, rec.codeChallengeMethod);
        if (!ok) throw new ValidationError("invalid_code_verifier");
      }
      await strapi2.documents("plugin::oauth2.oauth-authorization-code").update({
        documentId: rec.documentId,
        data: {
          usedAt: (/* @__PURE__ */ new Date()).toISOString()
        }
      });
      return {
        client: rec.client,
        authorizationUser: rec.user,
        scopes: rec.scopes
      };
    }
  })
);
const services = {
  "oauth-access-token": oauthAccessToken,
  "oauth-client": oauthClient,
  "oauth-global-setting": oauthGlobalSetting,
  "oauth-authorization-code": oauthAuthorizationCode
};
const index = {
  register,
  bootstrap,
  destroy,
  config,
  controllers,
  routes,
  services,
  contentTypes,
  policies,
  middlewares
};
export {
  index as default
};
