./node_modules/socket.io/client-dist/socket.io.esm.min.js.map:{
	"version": 3,
	"file": "socket.io.esm.min.js",
	"sources": ["../node_modules/engine.io-parser/build/esm/commons.js",
	"../node_modules/engine.io-parser/build/esm/encodePacket.browser.js",
	"../node_modules/engine.io-parser/build/esm/contrib/base64-arraybuffer.js",
	"../node_modules/engine.io-parser/build/esm/decodePacket.browser.js",
	"../node_modules/engine.io-parser/build/esm/index.js",
	"../node_modules/@socket.io/component-emitter/index.mjs",
	"../node_modules/engine.io-client/build/esm/globalThis.browser.js",
	"../node_modules/engine.io-client/build/esm/util.js",
	"../node_modules/engine.io-client/build/esm/transport.js",
	"../node_modules/engine.io-client/build/esm/contrib/yeast.js",
	"../node_modules/engine.io-client/build/esm/contrib/parseqs.js",
	"../node_modules/engine.io-client/build/esm/contrib/has-cors.js",
	"../node_modules/engine.io-client/build/esm/transports/xmlhttprequest.browser.js",
	"../node_modules/engine.io-client/build/esm/transports/polling.js",
	"../node_modules/engine.io-client/build/esm/transports/websocket-constructor.browser.js",
	"../node_modules/engine.io-client/build/esm/transports/websocket.js",
	"../node_modules/engine.io-client/build/esm/transports/index.js",
	"../node_modules/engine.io-client/build/esm/contrib/parseuri.js",
	"../node_modules/engine.io-client/build/esm/socket.js",
	"../node_modules/socket.io-parser/build/esm/is-binary.js",
	"../node_modules/socket.io-parser/build/esm/binary.js",
	"../node_modules/socket.io-parser/build/esm/index.js",
	"../build/esm/on.js",
	"../build/esm/socket.js",
	"../build/esm/contrib/backo2.js",
	"../build/esm/manager.js",
	"../build/esm/index.js",
	"../build/esm/url.js"],
	"sourcesContent": ["const PACKET_TYPES = Object.create(null); // no Map = no polyfill
	PACKET_TYPES[\"open\"] = \"0\";
	PACKET_TYPES[\"close\"] = \"1\";
	PACKET_TYPES[\"ping\"] = \"2\";
	PACKET_TYPES[\"pong\"] = \"3\";
	PACKET_TYPES[\"message\"] = \"4\";
	PACKET_TYPES[\"upgrade\"] = \"5\";
	PACKET_TYPES[\"noop\"] = \"6\";
	const PACKET_TYPES_REVERSE = Object.create(null);
	Object.keys(PACKET_TYPES).forEach(key => {
    	PACKET_TYPES_REVERSE[PACKET_TYPES[key]] = key;
	});

const ERROR_PACKET = { type: \"error\", data: \"parser error\" };
export { PACKET_TYPES, PACKET_TYPES_REVERSE, ERROR_PACKET };
","import { PACKET_TYPES } from \"./commons.js\";
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        Object.prototype.toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
// ArrayBuffer.isView method is not defined in IE10
const isView = obj => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj && obj.buffer instanceof ArrayBuffer;
};
const encodePacket = ({ type, data }, supportsBinary, callback) => {
    if (withNativeBlob && data instanceof Blob) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(data, callback);
        }
    }
    else if (withNativeArrayBuffer &&
        (data instanceof ArrayBuffer || isView(data))) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(new Blob([data]), callback);
        }
    }
    // plain string
    return callback(PACKET_TYPES[type] + (data || \"\"));
};
const encodeBlobAsBase64 = (data, callback) => {
    const fileReader = new FileReader();
    fileReader.onload = function () {
        const content = fileReader.result.split(\",\")[1];
        callback(\"b\" + content);
    };
    return fileReader.readAsDataURL(data);
};
export default encodePacket;
","const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// Use a lookup table to find the index.
const lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}
export const encode = (arraybuffer) => {
    let bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = '';
    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    if (len % 3 === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    }
    else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    return base64;
};
export const decode = (base64) => {
    let bufferLength = base64.length * 0.75, len = base64.length, i, p = 0, encoded1, encoded2, encoded3, encoded4;
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    const arraybuffer = new ArrayBuffer(bufferLength), bytes = new Uint8Array(arraybuffer);
    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    return arraybuffer;
};
","import { ERROR_PACKET, PACKET_TYPES_REVERSE } from \"./commons.js\";
import { decode } from \"./contrib/base64-arraybuffer.js\";
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const decodePacket = (encodedPacket, binaryType) => {
    if (typeof encodedPacket !== \"string\") {
        return {
            type: \"message\",
            data: mapBinary(encodedPacket, binaryType)
        };
    }
    const type = encodedPacket.charAt(0);
    if (type === \"b\") {
        return {
            type: \"message\",
            data: decodeBase64Packet(encodedPacket.substring(1), binaryType)
        };
    }
    const packetType = PACKET_TYPES_REVERSE[type];
    if (!packetType) {
        return ERROR_PACKET;
    }
    return encodedPacket.length > 1
        ? {
            type: PACKET_TYPES_REVERSE[type],
            data: encodedPacket.substring(1)
        }
        : {
            type: PACKET_TYPES_REVERSE[type]
        };
};
const decodeBase64Packet = (data, binaryType) => {
    if (withNativeArrayBuffer) {
        const decoded = decode(data);
        return mapBinary(decoded, binaryType);
    }
    else {
        return { base64: true, data }; // fallback for old browsers
    }
};
const mapBinary = (data, binaryType) => {
    switch (binaryType) {
        case \"blob\":
            return data instanceof ArrayBuffer ? new Blob([data]) : data;
        case \"arraybuffer\":
        default:
            return data; // assuming the data is already an ArrayBuffer
    }
};
export default decodePacket;
","import encodePacket from \"./encodePacket.js\";
import decodePacket from \"./decodePacket.js\";
const SEPARATOR = String.fromCharCode(30); // see https://en.wikipedia.org/wiki/Delimiter#ASCII_delimited_text
const encodePayload = (packets, callback) => {
    // some packets may be added to the array while encoding, so the initial length must be saved
    const length = packets.length;
    const encodedPackets = new Array(length);
    let count = 0;
    packets.forEach((packet, i) => {
        // force base64 encoding for binary packets
        encodePacket(packet, false, encodedPacket => {
            encodedPackets[i] = encodedPacket;
            if (++count === length) {
                callback(encodedPackets.join(SEPARATOR));
            }
        });
    });
};
const decodePayload = (encodedPayload, binaryType) => {
    const encodedPackets = encodedPayload.split(SEPARATOR);
    const packets = [];
    for (let i = 0; i < encodedPackets.length; i++) {
        const decodedPacket = decodePacket(encodedPackets[i], binaryType);
        packets.push(decodedPacket);
        if (decodedPacket.type === \"error\") {
            break;
        }
    }
    return packets;
};
export const protocol = 4;
export { encodePacket, encodePayload, decodePacket, decodePayload };
","/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

export function Emitter(obj) {
  if (obj) return mixin(obj);
}

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  function on() {
    this.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks['$' + event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks['$' + event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }

  // Remove event specific arrays for event types that no
  // one is subscribed for to avoid memory leak.
  if (callbacks.length === 0) {
    delete this._callbacks['$' + event];
  }

  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};

  var args = new Array(arguments.length - 1)
    , callbacks = this._callbacks['$' + event];

  for (var i = 1; i < arguments.length; i++) {
    args[i - 1] = arguments[i];
  }

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

// alias used for reserved events (protected method)
Emitter.prototype.emitReserved = Emitter.prototype.emit;

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks['$' + event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};
","export const globalThisShim = (() => {
    if (typeof self !== \"undefined\") {
        return self;
    }
    else if (typeof window !== \"undefined\") {
        return window;
    }
    else {
        return Function(\"return this\")();
    }
})();
","import { globalThisShim as globalThis } from \"./globalThis.js\";
export function pick(obj, ...attr) {
    return attr.reduce((acc, k) => {
        if (obj.hasOwnProperty(k)) {
            acc[k] = obj[k];
        }
        return acc;
    }, {});
}
// Keep a reference to the real timeout functions so they can be used when overridden
const NATIVE_SET_TIMEOUT = globalThis.setTimeout;
const NATIVE_CLEAR_TIMEOUT = globalThis.clearTimeout;
export function installTimerFunctions(obj, opts) {
    if (opts.useNativeTimers) {
        obj.setTimeoutFn = NATIVE_SET_TIMEOUT.bind(globalThis);
        obj.clearTimeoutFn = NATIVE_CLEAR_TIMEOUT.bind(globalThis);
    }
    else {
        obj.setTimeoutFn = globalThis.setTimeout.bind(globalThis);
        obj.clearTimeoutFn = globalThis.clearTimeout.bind(globalThis);
    }
}
// base64 encoded buffers are about 33% bigger (https://en.wikipedia.org/wiki/Base64)
const BASE64_OVERHEAD = 1.33;
// we could also have used `new Blob([obj]).size`, but it isn't supported in IE9
export function byteLength(obj) {
    if (typeof obj === \"string\") {
        return utf8Length(obj);
    }
    // arraybuffer or blob
    return Math.ceil((obj.byteLength || obj.size) * BASE64_OVERHEAD);
}
function utf8Length(str) {
    let c = 0, length = 0;
    for (let i = 0, l = str.length; i < l; i++) {
        c = str.charCodeAt(i);
        if (c < 0x80) {
            length += 1;
        }
        else if (c < 0x800) {
            length += 2;
        }
        else if (c < 0xd800 || c >= 0xe000) {
            length += 3;
        }
        else {
            i++;
            length += 4;
        }
    }
    return length;
}
","import { decodePacket } from \"engine.io-parser\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions } from \"./util.js\";
class TransportError extends Error {
    constructor(reason, description, context) {
        super(reason);
        this.description = description;
        this.context = context;
        this.type = \"TransportError\";
    }
}
export class Transport extends Emitter {
    /**
     * Transport abstract constructor.
     *
     * @param {Object} opts - options
     * @protected
     */
    constructor(opts) {
        super();
        this.writable = false;
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.query = opts.query;
        this.socket = opts.socket;
    }
    /**
     * Emits an error.
     *
     * @param {String} reason
     * @param description
     * @param context - the error context
     * @return {Transport} for chaining
     * @protected
     */
    onError(reason, description, context) {
        super.emitReserved(\"error\", new TransportError(reason, description, context));
        return this;
    }
    /**
     * Opens the transport.
     */
    open() {
        this.readyState = \"opening\";
        this.doOpen();
        return this;
    }
    /**
     * Closes the transport.
     */
    close() {
        if (this.readyState === \"opening\" || this.readyState === \"open\") {
            this.doClose();
            this.onClose();
        }
        return this;
    }
    /**
     * Sends multiple packets.
     *
     * @param {Array} packets
     */
    send(packets) {
        if (this.readyState === \"open\") {
            this.write(packets);
        }
        else {
            // this might happen if the transport was silently closed in the beforeunload event handler
        }
    }
    /**
     * Called upon open
     *
     * @protected
     */
    onOpen() {
        this.readyState = \"open\";
        this.writable = true;
        super.emitReserved(\"open\");
    }
    /**
     * Called with data.
     *
     * @param {String} data
     * @protected
     */
    onData(data) {
        const packet = decodePacket(data, this.socket.binaryType);
        this.onPacket(packet);
    }
    /**
     * Called with a decoded packet.
     *
     * @protected
     */
    onPacket(packet) {
        super.emitReserved(\"packet\", packet);
    }
    /**
     * Called upon close.
     *
     * @protected
     */
    onClose(details) {
        this.readyState = \"closed\";
        super.emitReserved(\"close\", details);
    }
    /**
     * Pauses the transport, in order not to lose packets during an upgrade.
     *
     * @param onPause
     */
    pause(onPause) { }
}
","// imported from https://github.com/unshiftio/yeast
'use strict';
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'.split(''), length = 64, map = {};
let seed = 0, i = 0, prev;
/**
 * Return a string representing the specified number.
 *
 * @param {Number} num The number to convert.
 * @returns {String} The string representation of the number.
 * @api public
 */
export function encode(num) {
    let encoded = '';
    do {
        encoded = alphabet[num % length] + encoded;
        num = Math.floor(num / length);
    } while (num > 0);
    return encoded;
}
/**
 * Return the integer value specified by the given string.
 *
 * @param {String} str The string to convert.
 * @returns {Number} The integer value represented by the string.
 * @api public
 */
export function decode(str) {
    let decoded = 0;
    for (i = 0; i < str.length; i++) {
        decoded = decoded * length + map[str.charAt(i)];
    }
    return decoded;
}
/**
 * Yeast: A tiny growing id generator.
 *
 * @returns {String} A unique id.
 * @api public
 */
export function yeast() {
    const now = encode(+new Date());
    if (now !== prev)
        return seed = 0, prev = now;
    return now + '.' + encode(seed++);
}
//
// Map each character to its index.
//
for (; i < length; i++)
    map[alphabet[i]] = i;
","// imported from https://github.com/galkn/querystring
/**
 * Compiles a querystring
 * Returns string representation of the object
 *
 * @param {Object}
 * @api private
 */
export function encode(obj) {
    let str = '';
    for (let i in obj) {
        if (obj.hasOwnProperty(i)) {
            if (str.length)
                str += '&';
            str += encodeURIComponent(i) + '=' + encodeURIComponent(obj[i]);
        }
    }
    return str;
}
/**
 * Parses a simple querystring into an object
 *
 * @param {String} qs
 * @api private
 */
export function decode(qs) {
    let qry = {};
    let pairs = qs.split('&');
    for (let i = 0, l = pairs.length; i < l; i++) {
        let pair = pairs[i].split('=');
        qry[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
    }
    return qry;
}
","// imported from https://github.com/component/has-cors
let value = false;
try {
    value = typeof XMLHttpRequest !== 'undefined' &&
        'withCredentials' in new XMLHttpRequest();
}
catch (err) {
    // if XMLHttp support is disabled in IE then it will throw
    // when trying to create
}
export const hasCORS = value;
","// browser shim for xmlhttprequest module
import { hasCORS } from \"../contrib/has-cors.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
export function XHR(opts) {
    const xdomain = opts.xdomain;
    // XMLHttpRequest can be disabled on IE
    try {
        if (\"undefined\" !== typeof XMLHttpRequest && (!xdomain || hasCORS)) {
            return new XMLHttpRequest();
        }
    }
    catch (e) { }
    if (!xdomain) {
        try {
            return new globalThis[[\"Active\"].concat(\"Object\").join(\"X\")](\"Microsoft.XMLHTTP\");
        }
        catch (e) { }
    }
}
","import { Transport } from \"../transport.js\";
import { yeast } from \"../contrib/yeast.js\";
import { encode } from \"../contrib/parseqs.js\";
import { encodePayload, decodePayload } from \"engine.io-parser\";
import { XHR as XMLHttpRequest } from \"./xmlhttprequest.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions, pick } from \"../util.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
function empty() { }
const hasXHR2 = (function () {
    const xhr = new XMLHttpRequest({
        xdomain: false,
    });
    return null != xhr.responseType;
})();
export class Polling extends Transport {
    /**
     * XHR Polling constructor.
     *
     * @param {Object} opts
     * @package
     */
    constructor(opts) {
        super(opts);
        this.polling = false;
        if (typeof location !== \"undefined\") {
            const isSSL = \"https:\" === location.protocol;
            let port = location.port;
            // some user agents have empty `location.port`
            if (!port) {
                port = isSSL ? \"443\" : \"80\";
            }
            this.xd =
                (typeof location !== \"undefined\" &&
                    opts.hostname !== location.hostname) ||
                    port !== opts.port;
            this.xs = opts.secure !== isSSL;
        }
        /**
         * XHR supports binary
         */
        const forceBase64 = opts && opts.forceBase64;
        this.supportsBinary = hasXHR2 && !forceBase64;
    }
    get name() {
        return \"polling\";
    }
    /**
     * Opens the socket (triggers polling). We write a PING message to determine
     * when the transport is open.
     *
     * @protected
     */
    doOpen() {
        this.poll();
    }
    /**
     * Pauses polling.
     *
     * @param {Function} onPause - callback upon buffers are flushed and transport is paused
     * @package
     */
    pause(onPause) {
        this.readyState = \"pausing\";
        const pause = () => {
            this.readyState = \"paused\";
            onPause();
        };
        if (this.polling || !this.writable) {
            let total = 0;
            if (this.polling) {
                total++;
                this.once(\"pollComplete\", function () {
                    --total || pause();
                });
            }
            if (!this.writable) {
                total++;
                this.once(\"drain\", function () {
                    --total || pause();
                });
            }
        }
        else {
            pause();
        }
    }
    /**
     * Starts polling cycle.
     *
     * @private
     */
    poll() {
        this.polling = true;
        this.doPoll();
        this.emitReserved(\"poll\");
    }
    /**
     * Overloads onData to detect payloads.
     *
     * @protected
     */
    onData(data) {
        const callback = (packet) => {
            // if its the first message we consider the transport open
            if (\"opening\" === this.readyState && packet.type === \"open\") {
                this.onOpen();
            }
            // if its a close packet, we close the ongoing requests
            if (\"close\" === packet.type) {
                this.onClose({ description: \"transport closed by the server\" });
                return false;
            }
            // otherwise bypass onData and handle the message
            this.onPacket(packet);
        };
        // decode payload
        decodePayload(data, this.socket.binaryType).forEach(callback);
        // if an event did not trigger closing
        if (\"closed\" !== this.readyState) {
            // if we got data we're not polling
            this.polling = false;
            this.emitReserved(\"pollComplete\");
            if (\"open\" === this.readyState) {
                this.poll();
            }
            else {
            }
        }
    }
    /**
     * For polling, send a close packet.
     *
     * @protected
     */
    doClose() {
        const close = () => {
            this.write([{ type: \"close\" }]);
        };
        if (\"open\" === this.readyState) {
            close();
        }
        else {
            // in case we're trying to close while
            // handshaking is in progress (GH-164)
            this.once(\"open\", close);
        }
    }
    /**
     * Writes a packets payload.
     *
     * @param {Array} packets - data packets
     * @protected
     */
    write(packets) {
        this.writable = false;
        encodePayload(packets, (data) => {
            this.doWrite(data, () => {
                this.writable = true;
                this.emitReserved(\"drain\");
            });
        });
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"https\" : \"http\";
        let port = \"\";
        // cache busting is forced
        if (false !== this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        if (!this.supportsBinary && !query.sid) {
            query.b64 = 1;
        }
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"https\" === schema && Number(this.opts.port) !== 443) ||
                (\"http\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Creates a request.
     *
     * @param {String} method
     * @private
     */
    request(opts = {}) {
        Object.assign(opts, { xd: this.xd, xs: this.xs }, this.opts);
        return new Request(this.uri(), opts);
    }
    /**
     * Sends data.
     *
     * @param {String} data to send.
     * @param {Function} called upon flush.
     * @private
     */
    doWrite(data, fn) {
        const req = this.request({
            method: \"POST\",
            data: data,
        });
        req.on(\"success\", fn);
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr post error\", xhrStatus, context);
        });
    }
    /**
     * Starts a poll cycle.
     *
     * @private
     */
    doPoll() {
        const req = this.request();
        req.on(\"data\", this.onData.bind(this));
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr poll error\", xhrStatus, context);
        });
        this.pollXhr = req;
    }
}
export class Request extends Emitter {
    /**
     * Request constructor
     *
     * @param {Object} options
     * @package
     */
    constructor(uri, opts) {
        super();
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.method = opts.method || \"GET\";
        this.uri = uri;
        this.async = false !== opts.async;
        this.data = undefined !== opts.data ? opts.data : null;
        this.create();
    }
    /**
     * Creates the XHR object and sends the request.
     *
     * @private
     */
    create() {
        const opts = pick(this.opts, \"agent\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"autoUnref\");
        opts.xdomain = !!this.opts.xd;
        opts.xscheme = !!this.opts.xs;
        const xhr = (this.xhr = new XMLHttpRequest(opts));
        try {
            xhr.open(this.method, this.uri, this.async);
            try {
                if (this.opts.extraHeaders) {
                    xhr.setDisableHeaderCheck && xhr.setDisableHeaderCheck(true);
                    for (let i in this.opts.extraHeaders) {
                        if (this.opts.extraHeaders.hasOwnProperty(i)) {
                            xhr.setRequestHeader(i, this.opts.extraHeaders[i]);
                        }
                    }
                }
            }
            catch (e) { }
            if (\"POST\" === this.method) {
                try {
                    xhr.setRequestHeader(\"Content-type\", \"text/plain;charset=UTF-8\");
                }
                catch (e) { }
            }
            try {
                xhr.setRequestHeader(\"Accept\", \"*/*\");
            }
            catch (e) { }
            // ie6 check
            if (\"withCredentials\" in xhr) {
                xhr.withCredentials = this.opts.withCredentials;
            }
            if (this.opts.requestTimeout) {
                xhr.timeout = this.opts.requestTimeout;
            }
            xhr.onreadystatechange = () => {
                if (4 !== xhr.readyState)
                    return;
                if (200 === xhr.status || 1223 === xhr.status) {
                    this.onLoad();
                }
                else {
                    // make sure the `error` event handler that's user-set
                    // does not throw in the same tick and gets caught here
                    this.setTimeoutFn(() => {
                        this.onError(typeof xhr.status === \"number\" ? xhr.status : 0);
                    }, 0);
                }
            };
            xhr.send(this.data);
        }
        catch (e) {
            // Need to defer since .create() is called directly from the constructor
            // and thus the 'error' event can only be only bound *after* this exception
            // occurs.  Therefore, also, we cannot throw here at all.
            this.setTimeoutFn(() => {
                this.onError(e);
            }, 0);
            return;
        }
        if (typeof document !== \"undefined\") {
            this.index = Request.requestsCount++;
            Request.requests[this.index] = this;
        }
    }
    /**
     * Called upon error.
     *
     * @private
     */
    onError(err) {
        this.emitReserved(\"error\", err, this.xhr);
        this.cleanup(true);
    }
    /**
     * Cleans up house.
     *
     * @private
     */
    cleanup(fromError) {
        if (\"undefined\" === typeof this.xhr || null === this.xhr) {
            return;
        }
        this.xhr.onreadystatechange = empty;
        if (fromError) {
            try {
                this.xhr.abort();
            }
            catch (e) { }
        }
        if (typeof document !== \"undefined\") {
            delete Request.requests[this.index];
        }
        this.xhr = null;
    }
    /**
     * Called upon load.
     *
     * @private
     */
    onLoad() {
        const data = this.xhr.responseText;
        if (data !== null) {
            this.emitReserved(\"data\", data);
            this.emitReserved(\"success\");
            this.cleanup();
        }
    }
    /**
     * Aborts the request.
     *
     * @package
     */
    abort() {
        this.cleanup();
    }
}
Request.requestsCount = 0;
Request.requests = {};
/**
 * Aborts pending requests when unloading the window. This is needed to prevent
 * memory leaks (e.g. when using IE) and to ensure that no spurious error is
 * emitted.
 */
if (typeof document !== \"undefined\") {
    // @ts-ignore
    if (typeof attachEvent === \"function\") {
        // @ts-ignore
        attachEvent(\"onunload\", unloadHandler);
    }
    else if (typeof addEventListener === \"function\") {
        const terminationEvent = \"onpagehide\" in globalThis ? \"pagehide\" : \"unload\";
        addEventListener(terminationEvent, unloadHandler, false);
    }
}
function unloadHandler() {
    for (let i in Request.requests) {
        if (Request.requests.hasOwnProperty(i)) {
            Request.requests[i].abort();
        }
    }
}
","import { globalThisShim as globalThis } from \"../globalThis.js\";
export const nextTick = (() => {
    const isPromiseAvailable = typeof Promise === \"function\" && typeof Promise.resolve === \"function\";
    if (isPromiseAvailable) {
        return (cb) => Promise.resolve().then(cb);
    }
    else {
        return (cb, setTimeoutFn) => setTimeoutFn(cb, 0);
    }
})();
export const WebSocket = globalThis.WebSocket || globalThis.MozWebSocket;
export const usingBrowserWebSocket = true;
export const defaultBinaryType = \"arraybuffer\";
","import { Transport } from \"../transport.js\";
import { encode } from \"../contrib/parseqs.js\";
import { yeast } from \"../contrib/yeast.js\";
import { pick } from \"../util.js\";
import { defaultBinaryType, nextTick, usingBrowserWebSocket, WebSocket, } from \"./websocket-constructor.js\";
import { encodePacket } from \"engine.io-parser\";
// detect ReactNative environment
const isReactNative = typeof navigator !== \"undefined\" &&
    typeof navigator.product === \"string\" &&
    navigator.product.toLowerCase() === \"reactnative\";
export class WS extends Transport {
    /**
     * WebSocket transport constructor.
     *
     * @param {Object} opts - connection options
     * @protected
     */
    constructor(opts) {
        super(opts);
        this.supportsBinary = !opts.forceBase64;
    }
    get name() {
        return \"websocket\";
    }
    doOpen() {
        if (!this.check()) {
            // let probe timeout
            return;
        }
        const uri = this.uri();
        const protocols = this.opts.protocols;
        // React Native only supports the 'headers' option, and will print a warning if anything else is passed
        const opts = isReactNative
            ? {}
            : pick(this.opts, \"agent\", \"perMessageDeflate\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"localAddress\", \"protocolVersion\", \"origin\", \"maxPayload\", \"family\", \"checkServerIdentity\");
        if (this.opts.extraHeaders) {
            opts.headers = this.opts.extraHeaders;
        }
        try {
            this.ws =
                usingBrowserWebSocket && !isReactNative
                    ? protocols
                        ? new WebSocket(uri, protocols)
                        : new WebSocket(uri)
                    : new WebSocket(uri, protocols, opts);
        }
        catch (err) {
            return this.emitReserved(\"error\", err);
        }
        this.ws.binaryType = this.socket.binaryType || defaultBinaryType;
        this.addEventListeners();
    }
    /**
     * Adds event listeners to the socket
     *
     * @private
     */
    addEventListeners() {
        this.ws.onopen = () => {
            if (this.opts.autoUnref) {
                this.ws._socket.unref();
            }
            this.onOpen();
        };
        this.ws.onclose = (closeEvent) => this.onClose({
            description: \"websocket connection closed\",
            context: closeEvent,
        });
        this.ws.onmessage = (ev) => this.onData(ev.data);
        this.ws.onerror = (e) => this.onError(\"websocket error\", e);
    }
    write(packets) {
        this.writable = false;
        // encodePacket efficient as it uses WS framing
        // no need for encodePayload
        for (let i = 0; i < packets.length; i++) {
            const packet = packets[i];
            const lastPacket = i === packets.length - 1;
            encodePacket(packet, this.supportsBinary, (data) => {
                // always create a new object (GH-437)
                const opts = {};
                if (!usingBrowserWebSocket) {
                    if (packet.options) {
                        opts.compress = packet.options.compress;
                    }
                    if (this.opts.perMessageDeflate) {
                        const len = 
                        // @ts-ignore
                        \"string\" === typeof data ? Buffer.byteLength(data) : data.length;
                        if (len < this.opts.perMessageDeflate.threshold) {
                            opts.compress = false;
                        }
                    }
                }
                // Sometimes the websocket has already been closed but the browser didn't
                // have a chance of informing us about it yet, in that case send will
                // throw an error
                try {
                    if (usingBrowserWebSocket) {
                        // TypeError is thrown when passing the second argument on Safari
                        this.ws.send(data);
                    }
                    else {
                        this.ws.send(data, opts);
                    }
                }
                catch (e) {
                }
                if (lastPacket) {
                    // fake drain
                    // defer to next tick to allow Socket to clear writeBuffer
                    nextTick(() => {
                        this.writable = true;
                        this.emitReserved(\"drain\");
                    }, this.setTimeoutFn);
                }
            });
        }
    }
    doClose() {
        if (typeof this.ws !== \"undefined\") {
            this.ws.close();
            this.ws = null;
        }
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"wss\" : \"ws\";
        let port = \"\";
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"wss\" === schema && Number(this.opts.port) !== 443) ||
                (\"ws\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        // append timestamp to URI
        if (this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        // communicate binary support capabilities
        if (!this.supportsBinary) {
            query.b64 = 1;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Feature detection for WebSocket.
     *
     * @return {Boolean} whether this transport is available.
     * @private
     */
    check() {
        return !!WebSocket;
    }
}
","import { Polling } from \"./polling.js\";
import { WS } from \"./websocket.js\";
export const transports = {
    websocket: WS,
    polling: Polling,
};
","// imported from https://github.com/galkn/parseuri
/**
 * Parses a URI
 *
 * Note: we could also have used the built-in URL object, but it isn't supported on all platforms.
 *
 * See:
 * - https://developer.mozilla.org/en-US/docs/Web/API/URL
 * - https://caniuse.com/url
 * - https://www.rfc-editor.org/rfc/rfc3986#appendix-B
 *
 * History of the parse() method:
 * - first commit: https://github.com/socketio/socket.io-client/commit/4ee1d5d94b3906a9c052b459f1a818b15f38f91c
 * - export into its own module: https://github.com/socketio/engine.io-client/commit/de2c561e4564efeb78f1bdb1ba39ef81b2822cb3
 * - reimport: https://github.com/socketio/engine.io-client/commit/df32277c3f6d622eec5ed09f493cae3f3391d242
 *
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * @api private
 */
const re = /^(?:(?![^:@\\/?#]+:[^:@\\/]*@)(http|https|ws|wss):\\/\\/)?((?:(([^:@\\/?#]*)(?::([^:@\\/?#]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\\/?#]*)(?::(\\d*))?)(((\\/(?:[^?#](?![^?#\\/]*\\.[^?#\\/.]+(?:[?#]|$)))*\\/?)?([^?#\\/]*))(?:\\?([^#]*))?(?:#(.*))?)/;
const parts = [
    'source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'
];
export function parse(str) {
    const src = str, b = str.indexOf('['), e = str.indexOf(']');
    if (b != -1 && e != -1) {
        str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
    }
    let m = re.exec(str || ''), uri = {}, i = 14;
    while (i--) {
        uri[parts[i]] = m[i] || '';
    }
    if (b != -1 && e != -1) {
        uri.source = src;
        uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
        uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
        uri.ipv6uri = true;
    }
    uri.pathNames = pathNames(uri, uri['path']);
    uri.queryKey = queryKey(uri, uri['query']);
    return uri;
}
function pathNames(obj, path) {
    const regx = /\\/{2,9}/g, names = path.replace(regx, \"/\").split(\"/\");
    if (path.slice(0, 1) == '/' || path.length === 0) {
        names.splice(0, 1);
    }
    if (path.slice(-1) == '/') {
        names.splice(names.length - 1, 1);
    }
    return names;
}
function queryKey(uri, query) {
    const data = {};
    query.replace(/(?:^|&)([^&=]*)=?([^&]*)/g, function ($0, $1, $2) {
        if ($1) {
            data[$1] = $2;
        }
    });
    return data;
}
","import { transports } from \"./transports/index.js\";
import { installTimerFunctions, byteLength } from \"./util.js\";
import { decode } from \"./contrib/parseqs.js\";
import { parse } from \"./contrib/parseuri.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { protocol } from \"engine.io-parser\";
export class Socket extends Emitter {
    /**
     * Socket constructor.
     *
     * @param {String|Object} uri - uri or options
     * @param {Object} opts - options
     */
    constructor(uri, opts = {}) {
        super();
        this.writeBuffer = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = null;
        }
        if (uri) {
            uri = parse(uri);
            opts.hostname = uri.host;
            opts.secure = uri.protocol === \"https\" || uri.protocol === \"wss\";
            opts.port = uri.port;
            if (uri.query)
                opts.query = uri.query;
        }
        else if (opts.host) {
            opts.hostname = parse(opts.host).host;
        }
        installTimerFunctions(this, opts);
        this.secure =
            null != opts.secure
                ? opts.secure
                : typeof location !== \"undefined\" && \"https:\" === location.protocol;
        if (opts.hostname && !opts.port) {
            // if no port is specified manually, use the protocol default
            opts.port = this.secure ? \"443\" : \"80\";
        }
        this.hostname =
            opts.hostname ||
                (typeof location !== \"undefined\" ? location.hostname : \"localhost\");
        this.port =
            opts.port ||
                (typeof location !== \"undefined\" && location.port
                    ? location.port
                    : this.secure
                        ? \"443\"
                        : \"80\");
        this.transports = opts.transports || [\"polling\", \"websocket\"];
        this.writeBuffer = [];
        this.prevBufferLen = 0;
        this.opts = Object.assign({
            path: \"/engine.io\",
            agent: false,
            withCredentials: false,
            upgrade: true,
            timestampParam: \"t\",
            rememberUpgrade: false,
            addTrailingSlash: true,
            rejectUnauthorized: true,
            perMessageDeflate: {
                threshold: 1024,
            },
            transportOptions: {},
            closeOnBeforeunload: true,
        }, opts);
        this.opts.path =
            this.opts.path.replace(/\\/$/, \"\") +
                (this.opts.addTrailingSlash ? \"/\" : \"\");
        if (typeof this.opts.query === \"string\") {
            this.opts.query = decode(this.opts.query);
        }
        // set on handshake
        this.id = null;
        this.upgrades = null;
        this.pingInterval = null;
        this.pingTimeout = null;
        // set on heartbeat
        this.pingTimeoutTimer = null;
        if (typeof addEventListener === \"function\") {
            if (this.opts.closeOnBeforeunload) {
                // Firefox closes the connection when the \"beforeunload\" event is emitted but not Chrome. This event listener
                // ensures every browser behaves the same (no \"disconnect\" event at the Socket.IO level when the page is
                // closed/reloaded)
                this.beforeunloadEventListener = () => {
                    if (this.transport) {
                        // silently close the transport
                        this.transport.removeAllListeners();
                        this.transport.close();
                    }
                };
                addEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
            }
            if (this.hostname !== \"localhost\") {
                this.offlineEventListener = () => {
                    this.onClose(\"transport close\", {
                        description: \"network connection lost\",
                    });
                };
                addEventListener(\"offline\", this.offlineEventListener, false);
            }
        }
        this.open();
    }
    /**
     * Creates transport of the given type.
     *
     * @param {String} name - transport name
     * @return {Transport}
     * @private
     */
    createTransport(name) {
        const query = Object.assign({}, this.opts.query);
        // append engine.io protocol identifier
        query.EIO = protocol;
        // transport name
        query.transport = name;
        // session id if we already have one
        if (this.id)
            query.sid = this.id;
        const opts = Object.assign({}, this.opts.transportOptions[name], this.opts, {
            query,
            socket: this,
            hostname: this.hostname,
            secure: this.secure,
            port: this.port,
        });
        return new transports[name](opts);
    }
    /**
     * Initializes transport to use and starts probe.
     *
     * @private
     */
    open() {
        let transport;
        if (this.opts.rememberUpgrade &&
            Socket.priorWebsocketSuccess &&
            this.transports.indexOf(\"websocket\") !== -1) {
            transport = \"websocket\";
        }
        else if (0 === this.transports.length) {
            // Emit error on next tick so it can be listened to
            this.setTimeoutFn(() => {
                this.emitReserved(\"error\", \"No transports available\");
            }, 0);
            return;
        }
        else {
            transport = this.transports[0];
        }
        this.readyState = \"opening\";
        // Retry with the next transport if the transport is disabled (jsonp: false)
        try {
            transport = this.createTransport(transport);
        }
        catch (e) {
            this.transports.shift();
            this.open();
            return;
        }
        transport.open();
        this.setTransport(transport);
    }
    /**
     * Sets the current transport. Disables the existing one (if any).
     *
     * @private
     */
    setTransport(transport) {
        if (this.transport) {
            this.transport.removeAllListeners();
        }
        // set up transport
        this.transport = transport;
        // set up transport listeners
        transport
            .on(\"drain\", this.onDrain.bind(this))
            .on(\"packet\", this.onPacket.bind(this))
            .on(\"error\", this.onError.bind(this))
            .on(\"close\", (reason) => this.onClose(\"transport close\", reason));
    }
    /**
     * Probes a transport.
     *
     * @param {String} name - transport name
     * @private
     */
    probe(name) {
        let transport = this.createTransport(name);
        let failed = false;
        Socket.priorWebsocketSuccess = false;
        const onTransportOpen = () => {
            if (failed)
                return;
            transport.send([{ type: \"ping\", data: \"probe\" }]);
            transport.once(\"packet\", (msg) => {
                if (failed)
                    return;
                if (\"pong\" === msg.type && \"probe\" === msg.data) {
                    this.upgrading = true;
                    this.emitReserved(\"upgrading\", transport);
                    if (!transport)
                        return;
                    Socket.priorWebsocketSuccess = \"websocket\" === transport.name;
                    this.transport.pause(() => {
                        if (failed)
                            return;
                        if (\"closed\" === this.readyState)
                            return;
                        cleanup();
                        this.setTransport(transport);
                        transport.send([{ type: \"upgrade\" }]);
                        this.emitReserved(\"upgrade\", transport);
                        transport = null;
                        this.upgrading = false;
                        this.flush();
                    });
                }
                else {
                    const err = new Error(\"probe error\");
                    // @ts-ignore
                    err.transport = transport.name;
                    this.emitReserved(\"upgradeError\", err);
                }
            });
        };
        function freezeTransport() {
            if (failed)
                return;
            // Any callback called by transport should be ignored since now
            failed = true;
            cleanup();
            transport.close();
            transport = null;
        }
        // Handle any error that happens while probing
        const onerror = (err) => {
            const error = new Error(\"probe error: \" + err);
            // @ts-ignore
            error.transport = transport.name;
            freezeTransport();
            this.emitReserved(\"upgradeError\", error);
        };
        function onTransportClose() {
            onerror(\"transport closed\");
        }
        // When the socket is closed while we're probing
        function onclose() {
            onerror(\"socket closed\");
        }
        // When the socket is upgraded while we're probing
        function onupgrade(to) {
            if (transport && to.name !== transport.name) {
                freezeTransport();
            }
        }
        // Remove all listeners on the transport and on self
        const cleanup = () => {
            transport.removeListener(\"open\", onTransportOpen);
            transport.removeListener(\"error\", onerror);
            transport.removeListener(\"close\", onTransportClose);
            this.off(\"close\", onclose);
            this.off(\"upgrading\", onupgrade);
        };
        transport.once(\"open\", onTransportOpen);
        transport.once(\"error\", onerror);
        transport.once(\"close\", onTransportClose);
        this.once(\"close\", onclose);
        this.once(\"upgrading\", onupgrade);
        transport.open();
    }
    /**
     * Called when connection is deemed open.
     *
     * @private
     */
    onOpen() {
        this.readyState = \"open\";
        Socket.priorWebsocketSuccess = \"websocket\" === this.transport.name;
        this.emitReserved(\"open\");
        this.flush();
        // we check for `readyState` in case an `open`
        // listener already closed the socket
        if (\"open\" === this.readyState && this.opts.upgrade) {
            let i = 0;
            const l = this.upgrades.length;
            for (; i < l; i++) {
                this.probe(this.upgrades[i]);
            }
        }
    }
    /**
     * Handles a packet.
     *
     * @private
     */
    onPacket(packet) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            this.emitReserved(\"packet\", packet);
            // Socket is live - any packet counts
            this.emitReserved(\"heartbeat\");
            switch (packet.type) {
                case \"open\":
                    this.onHandshake(JSON.parse(packet.data));
                    break;
                case \"ping\":
                    this.resetPingTimeout();
                    this.sendPacket(\"pong\");
                    this.emitReserved(\"ping\");
                    this.emitReserved(\"pong\");
                    break;
                case \"error\":
                    const err = new Error(\"server error\");
                    // @ts-ignore
                    err.code = packet.data;
                    this.onError(err);
                    break;
                case \"message\":
                    this.emitReserved(\"data\", packet.data);
                    this.emitReserved(\"message\", packet.data);
                    break;
            }
        }
        else {
        }
    }
    /**
     * Called upon handshake completion.
     *
     * @param {Object} data - handshake obj
     * @private
     */
    onHandshake(data) {
        this.emitReserved(\"handshake\", data);
        this.id = data.sid;
        this.transport.query.sid = data.sid;
        this.upgrades = this.filterUpgrades(data.upgrades);
        this.pingInterval = data.pingInterval;
        this.pingTimeout = data.pingTimeout;
        this.maxPayload = data.maxPayload;
        this.onOpen();
        // In case open handler closes socket
        if (\"closed\" === this.readyState)
            return;
        this.resetPingTimeout();
    }
    /**
     * Sets and resets ping timeout timer based on server pings.
     *
     * @private
     */
    resetPingTimeout() {
        this.clearTimeoutFn(this.pingTimeoutTimer);
        this.pingTimeoutTimer = this.setTimeoutFn(() => {
            this.onClose(\"ping timeout\");
        }, this.pingInterval + this.pingTimeout);
        if (this.opts.autoUnref) {
            this.pingTimeoutTimer.unref();
        }
    }
    /**
     * Called on `drain` event
     *
     * @private
     */
    onDrain() {
        this.writeBuffer.splice(0, this.prevBufferLen);
        // setting prevBufferLen = 0 is very important
        // for example, when upgrading, upgrade packet is sent over,
        // and a nonzero prevBufferLen could cause problems on `drain`
        this.prevBufferLen = 0;
        if (0 === this.writeBuffer.length) {
            this.emitReserved(\"drain\");
        }
        else {
            this.flush();
        }
    }
    /**
     * Flush write buffers.
     *
     * @private
     */
    flush() {
        if (\"closed\" !== this.readyState &&
            this.transport.writable &&
            !this.upgrading &&
            this.writeBuffer.length) {
            const packets = this.getWritablePackets();
            this.transport.send(packets);
            // keep track of current length of writeBuffer
            // splice writeBuffer and callbackBuffer on `drain`
            this.prevBufferLen = packets.length;
            this.emitReserved(\"flush\");
        }
    }
    /**
     * Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
     * long-polling)
     *
     * @private
     */
    getWritablePackets() {
        const shouldCheckPayloadSize = this.maxPayload &&
            this.transport.name === \"polling\" &&
            this.writeBuffer.length > 1;
        if (!shouldCheckPayloadSize) {
            return this.writeBuffer;
        }
        let payloadSize = 1; // first packet type
        for (let i = 0; i < this.writeBuffer.length; i++) {
            const data = this.writeBuffer[i].data;
            if (data) {
                payloadSize += byteLength(data);
            }
            if (i > 0 && payloadSize > this.maxPayload) {
                return this.writeBuffer.slice(0, i);
            }
            payloadSize += 2; // separator + packet type
        }
        return this.writeBuffer;
    }
    /**
     * Sends a message.
     *
     * @param {String} msg - message.
     * @param {Object} options.
     * @param {Function} callback function.
     * @return {Socket} for chaining.
     */
    write(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    send(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    /**
     * Sends a packet.
     *
     * @param {String} type: packet type.
     * @param {String} data.
     * @param {Object} options.
     * @param {Function} fn - callback function.
     * @private
     */
    sendPacket(type, data, options, fn) {
        if (\"function\" === typeof data) {
            fn = data;
            data = undefined;
        }
        if (\"function\" === typeof options) {
            fn = options;
            options = null;
        }
        if (\"closing\" === this.readyState || \"closed\" === this.readyState) {
            return;
        }
        options = options || {};
        options.compress = false !== options.compress;
        const packet = {
            type: type,
            data: data,
            options: options,
        };
        this.emitReserved(\"packetCreate\", packet);
        this.writeBuffer.push(packet);
        if (fn)
            this.once(\"flush\", fn);
        this.flush();
    }
    /**
     * Closes the connection.
     */
    close() {
        const close = () => {
            this.onClose(\"forced close\");
            this.transport.close();
        };
        const cleanupAndClose = () => {
            this.off(\"upgrade\", cleanupAndClose);
            this.off(\"upgradeError\", cleanupAndClose);
            close();
        };
        const waitForUpgrade = () => {
            // wait for upgrade to finish since we can't send packets while pausing a transport
            this.once(\"upgrade\", cleanupAndClose);
            this.once(\"upgradeError\", cleanupAndClose);
        };
        if (\"opening\" === this.readyState || \"open\" === this.readyState) {
            this.readyState = \"closing\";
            if (this.writeBuffer.length) {
                this.once(\"drain\", () => {
                    if (this.upgrading) {
                        waitForUpgrade();
                    }
                    else {
                        close();
                    }
                });
            }
            else if (this.upgrading) {
                waitForUpgrade();
            }
            else {
                close();
            }
        }
        return this;
    }
    /**
     * Called upon transport error
     *
     * @private
     */
    onError(err) {
        Socket.priorWebsocketSuccess = false;
        this.emitReserved(\"error\", err);
        this.onClose(\"transport error\", err);
    }
    /**
     * Called upon transport close.
     *
     * @private
     */
    onClose(reason, description) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            // clear timers
            this.clearTimeoutFn(this.pingTimeoutTimer);
            // stop event from firing again for transport
            this.transport.removeAllListeners(\"close\");
            // ensure transport won't stay open
            this.transport.close();
            // ignore further transport communication
            this.transport.removeAllListeners();
            if (typeof removeEventListener === \"function\") {
                removeEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
                removeEventListener(\"offline\", this.offlineEventListener, false);
            }
            // set ready state
            this.readyState = \"closed\";
            // clear session id
            this.id = null;
            // emit close event
            this.emitReserved(\"close\", reason, description);
            // clean buffers after, so users can still
            // grab the buffers on `close` event
            this.writeBuffer = [];
            this.prevBufferLen = 0;
        }
    }
    /**
     * Filters upgrades, returning only those matching client transports.
     *
     * @param {Array} upgrades - server upgrades
     * @private
     */
    filterUpgrades(upgrades) {
        const filteredUpgrades = [];
        let i = 0;
        const j = upgrades.length;
        for (; i < j; i++) {
            if (~this.transports.indexOf(upgrades[i]))
                filteredUpgrades.push(upgrades[i]);
        }
        return filteredUpgrades;
    }
}
Socket.protocol = protocol;
","const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const isView = (obj) => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj.buffer instanceof ArrayBuffer;
};
const toString = Object.prototype.toString;
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeFile = typeof File === \"function\" ||
    (typeof File !== \"undefined\" &&
        toString.call(File) === \"[object FileConstructor]\");
/**
 * Returns true if obj is a Buffer, an ArrayBuffer, a Blob or a File.
 *
 * @private
 */
export function isBinary(obj) {
    return ((withNativeArrayBuffer && (obj instanceof ArrayBuffer || isView(obj))) ||
        (withNativeBlob && obj instanceof Blob) ||
        (withNativeFile && obj instanceof File));
}
export function hasBinary(obj, toJSON) {
    if (!obj || typeof obj !== \"object\") {
        return false;
    }
    if (Array.isArray(obj)) {
        for (let i = 0, l = obj.length; i < l; i++) {
            if (hasBinary(obj[i])) {
                return true;
            }
        }
        return false;
    }
    if (isBinary(obj)) {
        return true;
    }
    if (obj.toJSON &&
        typeof obj.toJSON === \"function\" &&
        arguments.length === 1) {
        return hasBinary(obj.toJSON(), true);
    }
    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key) && hasBinary(obj[key])) {
            return true;
        }
    }
    return false;
}
","import { isBinary } from \"./is-binary.js\";
/**
 * Replaces every Buffer | ArrayBuffer | Blob | File in packet with a numbered placeholder.
 *
 * @param {Object} packet - socket.io event packet
 * @return {Object} with deconstructed packet and list of buffers
 * @public
 */
export function deconstructPacket(packet) {
    const buffers = [];
    const packetData = packet.data;
    const pack = packet;
    pack.data = _deconstructPacket(packetData, buffers);
    pack.attachments = buffers.length; // number of binary 'attachments'
    return { packet: pack, buffers: buffers };
}
function _deconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (isBinary(data)) {
        const placeholder = { _placeholder: true, num: buffers.length };
        buffers.push(data);
        return placeholder;
    }
    else if (Array.isArray(data)) {
        const newData = new Array(data.length);
        for (let i = 0; i < data.length; i++) {
            newData[i] = _deconstructPacket(data[i], buffers);
        }
        return newData;
    }
    else if (typeof data === \"object\" && !(data instanceof Date)) {
        const newData = {};
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                newData[key] = _deconstructPacket(data[key], buffers);
            }
        }
        return newData;
    }
    return data;
}
/**
 * Reconstructs a binary packet from its placeholder packet and buffers
 *
 * @param {Object} packet - event packet with placeholders
 * @param {Array} buffers - binary buffers to put in placeholder positions
 * @return {Object} reconstructed packet
 * @public
 */
export function reconstructPacket(packet, buffers) {
    packet.data = _reconstructPacket(packet.data, buffers);
    delete packet.attachments; // no longer useful
    return packet;
}
function _reconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (data && data._placeholder === true) {
        const isIndexValid = typeof data.num === \"number\" &&
            data.num >= 0 &&
            data.num < buffers.length;
        if (isIndexValid) {
            return buffers[data.num]; // appropriate buffer (should be natural order anyway)
        }
        else {
            throw new Error(\"illegal attachments\");
        }
    }
    else if (Array.isArray(data)) {
        for (let i = 0; i < data.length; i++) {
            data[i] = _reconstructPacket(data[i], buffers);
        }
    }
    else if (typeof data === \"object\") {
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                data[key] = _reconstructPacket(data[key], buffers);
            }
        }
    }
    return data;
}
","import { Emitter } from \"@socket.io/component-emitter\";
import { deconstructPacket, reconstructPacket } from \"./binary.js\";
import { isBinary, hasBinary } from \"./is-binary.js\";
/**
 * These strings must not be used as event names, as they have a special meaning.
 */
const RESERVED_EVENTS = [
    \"connect\",
    \"connect_error\",
    \"disconnect\",
    \"disconnecting\",
    \"newListener\",
    \"removeListener\", // used by the Node.js EventEmitter
];
/**
 * Protocol version.
 *
 * @public
 */
export const protocol = 5;
export var PacketType;
(function (PacketType) {
    PacketType[PacketType[\"CONNECT\"] = 0] = \"CONNECT\";
    PacketType[PacketType[\"DISCONNECT\"] = 1] = \"DISCONNECT\";
    PacketType[PacketType[\"EVENT\"] = 2] = \"EVENT\";
    PacketType[PacketType[\"ACK\"] = 3] = \"ACK\";
    PacketType[PacketType[\"CONNECT_ERROR\"] = 4] = \"CONNECT_ERROR\";
    PacketType[PacketType[\"BINARY_EVENT\"] = 5] = \"BINARY_EVENT\";
    PacketType[PacketType[\"BINARY_ACK\"] = 6] = \"BINARY_ACK\";
})(PacketType || (PacketType = {}));
/**
 * A socket.io Encoder instance
 */
export class Encoder {
    /**
     * Encoder constructor
     *
     * @param {function} replacer - custom replacer to pass down to JSON.parse
     */
    constructor(replacer) {
        this.replacer = replacer;
    }
    /**
     * Encode a packet as a single string if non-binary, or as a
     * buffer sequence, depending on packet type.
     *
     * @param {Object} obj - packet object
     */
    encode(obj) {
        if (obj.type === PacketType.EVENT || obj.type === PacketType.ACK) {
            if (hasBinary(obj)) {
                return this.encodeAsBinary({
                    type: obj.type === PacketType.EVENT
                        ? PacketType.BINARY_EVENT
                        : PacketType.BINARY_ACK,
                    nsp: obj.nsp,
                    data: obj.data,
                    id: obj.id,
                });
            }
        }
        return [this.encodeAsString(obj)];
    }
    /**
     * Encode packet as string.
     */
    encodeAsString(obj) {
        // first is type
        let str = \"\" + obj.type;
        // attachments if we have them
        if (obj.type === PacketType.BINARY_EVENT ||
            obj.type === PacketType.BINARY_ACK) {
            str += obj.attachments + \"-\";
        }
        // if we have a namespace other than `/`
        // we append it followed by a comma `,`
        if (obj.nsp && \"/\" !== obj.nsp) {
            str += obj.nsp + \",\";
        }
        // immediately followed by the id
        if (null != obj.id) {
            str += obj.id;
        }
        // json data
        if (null != obj.data) {
            str += JSON.stringify(obj.data, this.replacer);
        }
        return str;
    }
    /**
     * Encode packet as 'buffer sequence' by removing blobs, and
     * deconstructing packet into object with placeholders and
     * a list of buffers.
     */
    encodeAsBinary(obj) {
        const deconstruction = deconstructPacket(obj);
        const pack = this.encodeAsString(deconstruction.packet);
        const buffers = deconstruction.buffers;
        buffers.unshift(pack); // add packet info to beginning of data list
        return buffers; // write all the buffers
    }
}
// see https://stackoverflow.com/questions/8511281/check-if-a-value-is-an-object-in-javascript
function isObject(value) {
    return Object.prototype.toString.call(value) === \"[object Object]\";
}
/**
 * A socket.io Decoder instance
 *
 * @return {Object} decoder
 */
export class Decoder extends Emitter {
    /**
     * Decoder constructor
     *
     * @param {function} reviver - custom reviver to pass down to JSON.stringify
     */
    constructor(reviver) {
        super();
        this.reviver = reviver;
    }
    /**
     * Decodes an encoded packet string into packet JSON.
     *
     * @param {String} obj - encoded packet
     */
    add(obj) {
        let packet;
        if (typeof obj === \"string\") {
            if (this.reconstructor) {
                throw new Error(\"got plaintext data when reconstructing a packet\");
            }
            packet = this.decodeString(obj);
            const isBinaryEvent = packet.type === PacketType.BINARY_EVENT;
            if (isBinaryEvent || packet.type === PacketType.BINARY_ACK) {
                packet.type = isBinaryEvent ? PacketType.EVENT : PacketType.ACK;
                // binary packet's json
                this.reconstructor = new BinaryReconstructor(packet);
                // no attachments, labeled binary but no binary data to follow
                if (packet.attachments === 0) {
                    super.emitReserved(\"decoded\", packet);
                }
            }
            else {
                // non-binary full packet
                super.emitReserved(\"decoded\", packet);
            }
        }
        else if (isBinary(obj) || obj.base64) {
            // raw binary data
            if (!this.reconstructor) {
                throw new Error(\"got binary data when not reconstructing a packet\");
            }
            else {
                packet = this.reconstructor.takeBinaryData(obj);
                if (packet) {
                    // received final buffer
                    this.reconstructor = null;
                    super.emitReserved(\"decoded\", packet);
                }
            }
        }
        else {
            throw new Error(\"Unknown type: \" + obj);
        }
    }
    /**
     * Decode a packet String (JSON data)
     *
     * @param {String} str
     * @return {Object} packet
     */
    decodeString(str) {
        let i = 0;
        // look up type
        const p = {
            type: Number(str.charAt(0)),
        };
        if (PacketType[p.type] === undefined) {
            throw new Error(\"unknown packet type \" + p.type);
        }
        // look up attachments if type binary
        if (p.type === PacketType.BINARY_EVENT ||
            p.type === PacketType.BINARY_ACK) {
            const start = i + 1;
            while (str.charAt(++i) !== \"-\" && i != str.length) { }
            const buf = str.substring(start, i);
            if (buf != Number(buf) || str.charAt(i) !== \"-\") {
                throw new Error(\"Illegal attachments\");
            }
            p.attachments = Number(buf);
        }
        // look up namespace (if any)
        if (\"/\" === str.charAt(i + 1)) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (\",\" === c)
                    break;
                if (i === str.length)
                    break;
            }
            p.nsp = str.substring(start, i);
        }
        else {
            p.nsp = \"/\";
        }
        // look up id
        const next = str.charAt(i + 1);
        if (\"\" !== next && Number(next) == next) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (null == c || Number(c) != c) {
                    --i;
                    break;
                }
                if (i === str.length)
                    break;
            }
            p.id = Number(str.substring(start, i + 1));
        }
        // look up json data
        if (str.charAt(++i)) {
            const payload = this.tryParse(str.substr(i));
            if (Decoder.isPayloadValid(p.type, payload)) {
                p.data = payload;
            }
            else {
                throw new Error(\"invalid payload\");
            }
        }
        return p;
    }
    tryParse(str) {
        try {
            return JSON.parse(str, this.reviver);
        }
        catch (e) {
            return false;
        }
    }
    static isPayloadValid(type, payload) {
        switch (type) {
            case PacketType.CONNECT:
                return isObject(payload);
            case PacketType.DISCONNECT:
                return payload === undefined;
            case PacketType.CONNECT_ERROR:
                return typeof payload === \"string\" || isObject(payload);
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                return (Array.isArray(payload) &&
                    (typeof payload[0] === \"number\" ||
                        (typeof payload[0] === \"string\" &&
                            RESERVED_EVENTS.indexOf(payload[0]) === -1)));
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                return Array.isArray(payload);
        }
    }
    /**
     * Deallocates a parser's resources
     */
    destroy() {
        if (this.reconstructor) {
            this.reconstructor.finishedReconstruction();
            this.reconstructor = null;
        }
    }
}
/**
 * A manager of a binary event's 'buffer sequence'. Should
 * be constructed whenever a packet of type BINARY_EVENT is
 * decoded.
 *
 * @param {Object} packet
 * @return {BinaryReconstructor} initialized reconstructor
 */
class BinaryReconstructor {
    constructor(packet) {
        this.packet = packet;
        this.buffers = [];
        this.reconPack = packet;
    }
    /**
     * Method to be called when binary data received from connection
     * after a BINARY_EVENT packet.
     *
     * @param {Buffer | ArrayBuffer} binData - the raw binary data received
     * @return {null | Object} returns null if more binary data is expected or
     *   a reconstructed packet object if all buffers have been received.
     */
    takeBinaryData(binData) {
        this.buffers.push(binData);
        if (this.buffers.length === this.reconPack.attachments) {
            // done with buffer list
            const packet = reconstructPacket(this.reconPack, this.buffers);
            this.finishedReconstruction();
            return packet;
        }
        return null;
    }
    /**
     * Cleans up binary packet reconstruction variables.
     */
    finishedReconstruction() {
        this.reconPack = null;
        this.buffers = [];
    }
}
","export function on(obj, ev, fn) {
    obj.on(ev, fn);
    return function subDestroy() {
        obj.off(ev, fn);
    };
}
","import { PacketType } from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
/**
 * Internal events.
 * These events can't be emitted by the user.
 */
const RESERVED_EVENTS = Object.freeze({
    connect: 1,
    connect_error: 1,
    disconnect: 1,
    disconnecting: 1,
    // EventEmitter reserved events: https://nodejs.org/api/events.html#events_event_newlistener
    newListener: 1,
    removeListener: 1,
});
/**
 * A Socket is the fundamental class for interacting with the server.
 *
 * A Socket belongs to a certain Namespace (by default /) and uses an underlying {@link Manager} to communicate.
 *
 * @example
 * const socket = io();
 *
 * socket.on(\"connect\", () => {
 *   console.log(\"connected\");
 * });
 *
 * // send an event to the server
 * socket.emit(\"foo\", \"bar\");
 *
 * socket.on(\"foobar\", () => {
 *   // an event was received from the server
 * });
 *
 * // upon disconnection
 * socket.on(\"disconnect\", (reason) => {
 *   console.log(`disconnected due to ${reason}`);
 * });
 */
export class Socket extends Emitter {
    /**
     * `Socket` constructor.
     */
    constructor(io, nsp, opts) {
        super();
        /**
         * Whether the socket is currently connected to the server.
         *
         * @example
         * const socket = io();
         *
         * socket.on(\"connect\", () => {
         *   console.log(socket.connected); // true
         * });
         *
         * socket.on(\"disconnect\", () => {
         *   console.log(socket.connected); // false
         * });
         */
        this.connected = false;
        /**
         * Whether the connection state was recovered after a temporary disconnection. In that case, any missed packets will
         * be transmitted by the server.
         */
        this.recovered = false;
        /**
         * Buffer for packets received before the CONNECT packet
         */
        this.receiveBuffer = [];
        /**
         * Buffer for packets that will be sent once the socket is connected
         */
        this.sendBuffer = [];
        /**
         * The queue of packets to be sent with retry in case of failure.
         *
         * Packets are sent one by one, each waiting for the server acknowledgement, in order to guarantee the delivery order.
         * @private
         */
        this._queue = [];
        /**
         * A sequence to generate the ID of the {@link QueuedPacket}.
         * @private
         */
        this._queueSeq = 0;
        this.ids = 0;
        this.acks = {};
        this.flags = {};
        this.io = io;
        this.nsp = nsp;
        if (opts && opts.auth) {
            this.auth = opts.auth;
        }
        this._opts = Object.assign({}, opts);
        if (this.io._autoConnect)
            this.open();
    }
    /**
     * Whether the socket is currently disconnected
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"connect\", () => {
     *   console.log(socket.disconnected); // false
     * });
     *
     * socket.on(\"disconnect\", () => {
     *   console.log(socket.disconnected); // true
     * });
     */
    get disconnected() {
        return !this.connected;
    }
    /**
     * Subscribe to open, close and packet events
     *
     * @private
     */
    subEvents() {
        if (this.subs)
            return;
        const io = this.io;
        this.subs = [
            on(io, \"open\", this.onopen.bind(this)),
            on(io, \"packet\", this.onpacket.bind(this)),
            on(io, \"error\", this.onerror.bind(this)),
            on(io, \"close\", this.onclose.bind(this)),
        ];
    }
    /**
     * Whether the Socket will try to reconnect when its Manager connects or reconnects.
     *
     * @example
     * const socket = io();
     *
     * console.log(socket.active); // true
     *
     * socket.on(\"disconnect\", (reason) => {
     *   if (reason === \"io server disconnect\") {
     *     // the disconnection was initiated by the server, you need to manually reconnect
     *     console.log(socket.active); // false
     *   }
     *   // else the socket will automatically try to reconnect
     *   console.log(socket.active); // true
     * });
     */
    get active() {
        return !!this.subs;
    }
    /**
     * \"Opens\" the socket.
     *
     * @example
     * const socket = io({
     *   autoConnect: false
     * });
     *
     * socket.connect();
     */
    connect() {
        if (this.connected)
            return this;
        this.subEvents();
        if (!this.io[\"_reconnecting\"])
            this.io.open(); // ensure open
        if (\"open\" === this.io._readyState)
            this.onopen();
        return this;
    }
    /**
     * Alias for {@link connect()}.
     */
    open() {
        return this.connect();
    }
    /**
     * Sends a `message` event.
     *
     * This method mimics the WebSocket.send() method.
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/send
     *
     * @example
     * socket.send(\"hello\");
     *
     * // this is equivalent to
     * socket.emit(\"message\", \"hello\");
     *
     * @return self
     */
    send(...args) {
        args.unshift(\"message\");
        this.emit.apply(this, args);
        return this;
    }
    /**
     * Override `emit`.
     * If the event is in `events`, it's emitted normally.
     *
     * @example
     * socket.emit(\"hello\", \"world\");
     *
     * // all serializable datastructures are supported (no need to call JSON.stringify)
     * socket.emit(\"hello\", 1, \"2\", { 3: [\"4\"], 5: Uint8Array.from([6]) });
     *
     * // with an acknowledgement from the server
     * socket.emit(\"hello\", \"world\", (val) => {
     *   // ...
     * });
     *
     * @return self
     */
    emit(ev, ...args) {
        if (RESERVED_EVENTS.hasOwnProperty(ev)) {
            throw new Error('\"' + ev.toString() + '\" is a reserved event name');
        }
        args.unshift(ev);
        if (this._opts.retries && !this.flags.fromQueue && !this.flags.volatile) {
            this._addToQueue(args);
            return this;
        }
        const packet = {
            type: PacketType.EVENT,
            data: args,
        };
        packet.options = {};
        packet.options.compress = this.flags.compress !== false;
        // event ack callback
        if (\"function\" === typeof args[args.length - 1]) {
            const id = this.ids++;
            const ack = args.pop();
            this._registerAckCallback(id, ack);
            packet.id = id;
        }
        const isTransportWritable = this.io.engine &&
            this.io.engine.transport &&
            this.io.engine.transport.writable;
        const discardPacket = this.flags.volatile && (!isTransportWritable || !this.connected);
        if (discardPacket) {
        }
        else if (this.connected) {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        }
        else {
            this.sendBuffer.push(packet);
        }
        this.flags = {};
        return this;
    }
    /**
     * @private
     */
    _registerAckCallback(id, ack) {
        var _a;
        const timeout = (_a = this.flags.timeout) !== null && _a !== void 0 ? _a : this._opts.ackTimeout;
        if (timeout === undefined) {
            this.acks[id] = ack;
            return;
        }
        // @ts-ignore
        const timer = this.io.setTimeoutFn(() => {
            delete this.acks[id];
            for (let i = 0; i < this.sendBuffer.length; i++) {
                if (this.sendBuffer[i].id === id) {
                    this.sendBuffer.splice(i, 1);
                }
            }
            ack.call(this, new Error(\"operation has timed out\"));
        }, timeout);
        this.acks[id] = (...args) => {
            // @ts-ignore
            this.io.clearTimeoutFn(timer);
            ack.apply(this, [null, ...args]);
        };
    }
    /**
     * Emits an event and waits for an acknowledgement
     *
     * @example
     * // without timeout
     * const response = await socket.emitWithAck(\"hello\", \"world\");
     *
     * // with a specific timeout
     * try {
     *   const response = await socket.timeout(1000).emitWithAck(\"hello\", \"world\");
     * } catch (err) {
     *   // the server did not acknowledge the event in the given delay
     * }
     *
     * @return a Promise that will be fulfilled when the server acknowledges the event
     */
    emitWithAck(ev, ...args) {
        // the timeout flag is optional
        const withErr = this.flags.timeout !== undefined || this._opts.ackTimeout !== undefined;
        return new Promise((resolve, reject) => {
            args.push((arg1, arg2) => {
                if (withErr) {
                    return arg1 ? reject(arg1) : resolve(arg2);
                }
                else {
                    return resolve(arg1);
                }
            });
            this.emit(ev, ...args);
        });
    }
    /**
     * Add the packet to the queue.
     * @param args
     * @private
     */
    _addToQueue(args) {
        let ack;
        if (typeof args[args.length - 1] === \"function\") {
            ack = args.pop();
        }
        const packet = {
            id: this._queueSeq++,
            tryCount: 0,
            pending: false,
            args,
            flags: Object.assign({ fromQueue: true }, this.flags),
        };
        args.push((err, ...responseArgs) => {
            if (packet !== this._queue[0]) {
                // the packet has already been acknowledged
                return;
            }
            const hasError = err !== null;
            if (hasError) {
                if (packet.tryCount > this._opts.retries) {
                    this._queue.shift();
                    if (ack) {
                        ack(err);
                    }
                }
            }
            else {
                this._queue.shift();
                if (ack) {
                    ack(null, ...responseArgs);
                }
            }
            packet.pending = false;
            return this._drainQueue();
        });
        this._queue.push(packet);
        this._drainQueue();
    }
    /**
     * Send the first packet of the queue, and wait for an acknowledgement from the server.
     * @param force - whether to resend a packet that has not been acknowledged yet
     *
     * @private
     */
    _drainQueue(force = false) {
        if (!this.connected || this._queue.length === 0) {
            return;
        }
        const packet = this._queue[0];
        if (packet.pending && !force) {
            return;
        }
        packet.pending = true;
        packet.tryCount++;
        this.flags = packet.flags;
        this.emit.apply(this, packet.args);
    }
    /**
     * Sends a packet.
     *
     * @param packet
     * @private
     */
    packet(packet) {
        packet.nsp = this.nsp;
        this.io._packet(packet);
    }
    /**
     * Called upon engine `open`.
     *
     * @private
     */
    onopen() {
        if (typeof this.auth == \"function\") {
            this.auth((data) => {
                this._sendConnectPacket(data);
            });
        }
        else {
            this._sendConnectPacket(this.auth);
        }
    }
    /**
     * Sends a CONNECT packet to initiate the Socket.IO session.
     *
     * @param data
     * @private
     */
    _sendConnectPacket(data) {
        this.packet({
            type: PacketType.CONNECT,
            data: this._pid
                ? Object.assign({ pid: this._pid, offset: this._lastOffset }, data)
                : data,
        });
    }
    /**
     * Called upon engine or manager `error`.
     *
     * @param err
     * @private
     */
    onerror(err) {
        if (!this.connected) {
            this.emitReserved(\"connect_error\", err);
        }
    }
    /**
     * Called upon engine `close`.
     *
     * @param reason
     * @param description
     * @private
     */
    onclose(reason, description) {
        this.connected = false;
        delete this.id;
        this.emitReserved(\"disconnect\", reason, description);
    }
    /**
     * Called with socket packet.
     *
     * @param packet
     * @private
     */
    onpacket(packet) {
        const sameNamespace = packet.nsp === this.nsp;
        if (!sameNamespace)
            return;
        switch (packet.type) {
            case PacketType.CONNECT:
                if (packet.data && packet.data.sid) {
                    this.onconnect(packet.data.sid, packet.data.pid);
                }
                else {
                    this.emitReserved(\"connect_error\", new Error(\"It seems you are trying to reach a Socket.IO server in v2.x with a v3.x client, but they are not compatible (more information here: https://socket.io/docs/v3/migrating-from-2-x-to-3-0/)\"));
                }
                break;
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                this.onevent(packet);
                break;
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                this.onack(packet);
                break;
            case PacketType.DISCONNECT:
                this.ondisconnect();
                break;
            case PacketType.CONNECT_ERROR:
                this.destroy();
                const err = new Error(packet.data.message);
                // @ts-ignore
                err.data = packet.data.data;
                this.emitReserved(\"connect_error\", err);
                break;
        }
    }
    /**
     * Called upon a server event.
     *
     * @param packet
     * @private
     */
    onevent(packet) {
        const args = packet.data || [];
        if (null != packet.id) {
            args.push(this.ack(packet.id));
        }
        if (this.connected) {
            this.emitEvent(args);
        }
        else {
            this.receiveBuffer.push(Object.freeze(args));
        }
    }
    emitEvent(args) {
        if (this._anyListeners && this._anyListeners.length) {
            const listeners = this._anyListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, args);
            }
        }
        super.emit.apply(this, args);
        if (this._pid && args.length && typeof args[args.length - 1] === \"string\") {
            this._lastOffset = args[args.length - 1];
        }
    }
    /**
     * Produces an ack callback to emit with an event.
     *
     * @private
     */
    ack(id) {
        const self = this;
        let sent = false;
        return function (...args) {
            // prevent double callbacks
            if (sent)
                return;
            sent = true;
            self.packet({
                type: PacketType.ACK,
                id: id,
                data: args,
            });
        };
    }
    /**
     * Called upon a server acknowlegement.
     *
     * @param packet
     * @private
     */
    onack(packet) {
        const ack = this.acks[packet.id];
        if (\"function\" === typeof ack) {
            ack.apply(this, packet.data);
            delete this.acks[packet.id];
        }
        else {
        }
    }
    /**
     * Called upon server connect.
     *
     * @private
     */
    onconnect(id, pid) {
        this.id = id;
        this.recovered = pid && this._pid === pid;
        this._pid = pid; // defined only if connection state recovery is enabled
        this.connected = true;
        this.emitBuffered();
        this.emitReserved(\"connect\");
        this._drainQueue(true);
    }
    /**
     * Emit buffered events (received and emitted).
     *
     * @private
     */
    emitBuffered() {
        this.receiveBuffer.forEach((args) => this.emitEvent(args));
        this.receiveBuffer = [];
        this.sendBuffer.forEach((packet) => {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        });
        this.sendBuffer = [];
    }
    /**
     * Called upon server disconnect.
     *
     * @private
     */
    ondisconnect() {
        this.destroy();
        this.onclose(\"io server disconnect\");
    }
    /**
     * Called upon forced client/server side disconnections,
     * this method ensures the manager stops tracking us and
     * that reconnections don't get triggered for this.
     *
     * @private
     */
    destroy() {
        if (this.subs) {
            // clean subscriptions to avoid reconnections
            this.subs.forEach((subDestroy) => subDestroy());
            this.subs = undefined;
        }
        this.io[\"_destroy\"](this);
    }
    /**
     * Disconnects the socket manually. In that case, the socket will not try to reconnect.
     *
     * If this is the last active Socket instance of the {@link Manager}, the low-level connection will be closed.
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"disconnect\", (reason) => {
     *   // console.log(reason); prints \"io client disconnect\"
     * });
     *
     * socket.disconnect();
     *
     * @return self
     */
    disconnect() {
        if (this.connected) {
            this.packet({ type: PacketType.DISCONNECT });
        }
        // remove socket from pool
        this.destroy();
        if (this.connected) {
            // fire events
            this.onclose(\"io client disconnect\");
        }
        return this;
    }
    /**
     * Alias for {@link disconnect()}.
     *
     * @return self
     */
    close() {
        return this.disconnect();
    }
    /**
     * Sets the compress flag.
     *
     * @example
     * socket.compress(false).emit(\"hello\");
     *
     * @param compress - if `true`, compresses the sending data
     * @return self
     */
    compress(compress) {
        this.flags.compress = compress;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the event message will be dropped when this socket is not
     * ready to send messages.
     *
     * @example
     * socket.volatile.emit(\"hello\"); // the server may or may not receive it
     *
     * @returns self
     */
    get volatile() {
        this.flags.volatile = true;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the callback will be called with an error when the
     * given number of milliseconds have elapsed without an acknowledgement from the server:
     *
     * @example
     * socket.timeout(5000).emit(\"my-event\", (err) => {
     *   if (err) {
     *     // the server did not acknowledge the event in the given delay
     *   }
     * });
     *
     * @returns self
     */
    timeout(timeout) {
        this.flags.timeout = timeout;
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * @example
     * socket.onAny((event, ...args) => {
     *   console.log(`got ${event}`);
     * });
     *
     * @param listener
     */
    onAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * @example
     * socket.prependAny((event, ...args) => {
     *   console.log(`got event ${event}`);
     * });
     *
     * @param listener
     */
    prependAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`got event ${event}`);
     * }
     *
     * socket.onAny(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAny(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAny();
     *
     * @param listener
     */
    offAny(listener) {
        if (!this._anyListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAny() {
        return this._anyListeners || [];
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.onAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    onAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.prependAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    prependAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`sent event ${event}`);
     * }
     *
     * socket.onAnyOutgoing(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAnyOutgoing(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAnyOutgoing();
     *
     * @param [listener] - the catch-all listener (optional)
     */
    offAnyOutgoing(listener) {
        if (!this._anyOutgoingListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyOutgoingListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyOutgoingListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAnyOutgoing() {
        return this._anyOutgoingListeners || [];
    }
    /**
     * Notify the listeners for each packet sent
     *
     * @param packet
     *
     * @private
     */
    notifyOutgoingListeners(packet) {
        if (this._anyOutgoingListeners && this._anyOutgoingListeners.length) {
            const listeners = this._anyOutgoingListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, packet.data);
            }
        }
    }
}
","/**
 * Initialize backoff timer with `opts`.
 *
 * - `min` initial timeout in milliseconds [100]
 * - `max` max timeout [10000]
 * - `jitter` [0]
 * - `factor` [2]
 *
 * @param {Object} opts
 * @api public
 */
export function Backoff(opts) {
    opts = opts || {};
    this.ms = opts.min || 100;
    this.max = opts.max || 10000;
    this.factor = opts.factor || 2;
    this.jitter = opts.jitter > 0 && opts.jitter <= 1 ? opts.jitter : 0;
    this.attempts = 0;
}
/**
 * Return the backoff duration.
 *
 * @return {Number}
 * @api public
 */
Backoff.prototype.duration = function () {
    var ms = this.ms * Math.pow(this.factor, this.attempts++);
    if (this.jitter) {
        var rand = Math.random();
        var deviation = Math.floor(rand * this.jitter * ms);
        ms = (Math.floor(rand * 10) & 1) == 0 ? ms - deviation : ms + deviation;
    }
    return Math.min(ms, this.max) | 0;
};
/**
 * Reset the number of attempts.
 *
 * @api public
 */
Backoff.prototype.reset = function () {
    this.attempts = 0;
};
/**
 * Set the minimum duration
 *
 * @api public
 */
Backoff.prototype.setMin = function (min) {
    this.ms = min;
};
/**
 * Set the maximum duration
 *
 * @api public
 */
Backoff.prototype.setMax = function (max) {
    this.max = max;
};
/**
 * Set the jitter
 *
 * @api public
 */
Backoff.prototype.setJitter = function (jitter) {
    this.jitter = jitter;
};
","import { Socket as Engine, installTimerFunctions, nextTick, } from \"engine.io-client\";
import { Socket } from \"./socket.js\";
import * as parser from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Backoff } from \"./contrib/backo2.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
export class Manager extends Emitter {
    constructor(uri, opts) {
        var _a;
        super();
        this.nsps = {};
        this.subs = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = undefined;
        }
        opts = opts || {};
        opts.path = opts.path || \"/socket.io\";
        this.opts = opts;
        installTimerFunctions(this, opts);
        this.reconnection(opts.reconnection !== false);
        this.reconnectionAttempts(opts.reconnectionAttempts || Infinity);
        this.reconnectionDelay(opts.reconnectionDelay || 1000);
        this.reconnectionDelayMax(opts.reconnectionDelayMax || 5000);
        this.randomizationFactor((_a = opts.randomizationFactor) !== null && _a !== void 0 ? _a : 0.5);
        this.backoff = new Backoff({
            min: this.reconnectionDelay(),
            max: this.reconnectionDelayMax(),
            jitter: this.randomizationFactor(),
        });
        this.timeout(null == opts.timeout ? 20000 : opts.timeout);
        this._readyState = \"closed\";
        this.uri = uri;
        const _parser = opts.parser || parser;
        this.encoder = new _parser.Encoder();
        this.decoder = new _parser.Decoder();
        this._autoConnect = opts.autoConnect !== false;
        if (this._autoConnect)
            this.open();
    }
    reconnection(v) {
        if (!arguments.length)
            return this._reconnection;
        this._reconnection = !!v;
        return this;
    }
    reconnectionAttempts(v) {
        if (v === undefined)
            return this._reconnectionAttempts;
        this._reconnectionAttempts = v;
        return this;
    }
    reconnectionDelay(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelay;
        this._reconnectionDelay = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMin(v);
        return this;
    }
    randomizationFactor(v) {
        var _a;
        if (v === undefined)
            return this._randomizationFactor;
        this._randomizationFactor = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setJitter(v);
        return this;
    }
    reconnectionDelayMax(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelayMax;
        this._reconnectionDelayMax = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMax(v);
        return this;
    }
    timeout(v) {
        if (!arguments.length)
            return this._timeout;
        this._timeout = v;
        return this;
    }
    /**
     * Starts trying to reconnect if reconnection is enabled and we have not
     * started reconnecting yet
     *
     * @private
     */
    maybeReconnectOnOpen() {
        // Only try to reconnect if it's the first time we're connecting
        if (!this._reconnecting &&
            this._reconnection &&
            this.backoff.attempts === 0) {
            // keeps reconnection from firing twice for the same reconnection loop
            this.reconnect();
        }
    }
    /**
     * Sets the current transport `socket`.
     *
     * @param {Function} fn - optional, callback
     * @return self
     * @public
     */
    open(fn) {
        if (~this._readyState.indexOf(\"open\"))
            return this;
        this.engine = new Engine(this.uri, this.opts);
        const socket = this.engine;
        const self = this;
        this._readyState = \"opening\";
        this.skipReconnect = false;
        // emit `open`
        const openSubDestroy = on(socket, \"open\", function () {
            self.onopen();
            fn && fn();
        });
        // emit `error`
        const errorSub = on(socket, \"error\", (err) => {
            self.cleanup();
            self._readyState = \"closed\";
            this.emitReserved(\"error\", err);
            if (fn) {
                fn(err);
            }
            else {
                // Only do this if there is no fn to handle the error
                self.maybeReconnectOnOpen();
            }
        });
        if (false !== this._timeout) {
            const timeout = this._timeout;
            if (timeout === 0) {
                openSubDestroy(); // prevents a race condition with the 'open' event
            }
            // set timer
            const timer = this.setTimeoutFn(() => {
                openSubDestroy();
                socket.close();
                // @ts-ignore
                socket.emit(\"error\", new Error(\"timeout\"));
            }, timeout);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
        this.subs.push(openSubDestroy);
        this.subs.push(errorSub);
        return this;
    }
    /**
     * Alias for open()
     *
     * @return self
     * @public
     */
    connect(fn) {
        return this.open(fn);
    }
    /**
     * Called upon transport open.
     *
     * @private
     */
    onopen() {
        // clear old subs
        this.cleanup();
        // mark as open
        this._readyState = \"open\";
        this.emitReserved(\"open\");
        // add new subs
        const socket = this.engine;
        this.subs.push(on(socket, \"ping\", this.onping.bind(this)), on(socket, \"data\", this.ondata.bind(this)), on(socket, \"error\", this.onerror.bind(this)), on(socket, \"close\", this.onclose.bind(this)), on(this.decoder, \"decoded\", this.ondecoded.bind(this)));
    }
    /**
     * Called upon a ping.
     *
     * @private
     */
    onping() {
        this.emitReserved(\"ping\");
    }
    /**
     * Called with data.
     *
     * @private
     */
    ondata(data) {
        try {
            this.decoder.add(data);
        }
        catch (e) {
            this.onclose(\"parse error\", e);
        }
    }
    /**
     * Called when parser fully decodes a packet.
     *
     * @private
     */
    ondecoded(packet) {
        // the nextTick call prevents an exception in a user-provided event listener from triggering a disconnection due to a \"parse error\"
        nextTick(() => {
            this.emitReserved(\"packet\", packet);
        }, this.setTimeoutFn);
    }
    /**
     * Called upon socket error.
     *
     * @private
     */
    onerror(err) {
        this.emitReserved(\"error\", err);
    }
    /**
     * Creates a new socket for the given `nsp`.
     *
     * @return {Socket}
     * @public
     */
    socket(nsp, opts) {
        let socket = this.nsps[nsp];
        if (!socket) {
            socket = new Socket(this, nsp, opts);
            this.nsps[nsp] = socket;
        }
        else if (this._autoConnect && !socket.active) {
            socket.connect();
        }
        return socket;
    }
    /**
     * Called upon a socket close.
     *
     * @param socket
     * @private
     */
    _destroy(socket) {
        const nsps = Object.keys(this.nsps);
        for (const nsp of nsps) {
            const socket = this.nsps[nsp];
            if (socket.active) {
                return;
            }
        }
        this._close();
    }
    /**
     * Writes a packet.
     *
     * @param packet
     * @private
     */
    _packet(packet) {
        const encodedPackets = this.encoder.encode(packet);
        for (let i = 0; i < encodedPackets.length; i++) {
            this.engine.write(encodedPackets[i], packet.options);
        }
    }
    /**
     * Clean up transport subscriptions and packet buffer.
     *
     * @private
     */
    cleanup() {
        this.subs.forEach((subDestroy) => subDestroy());
        this.subs.length = 0;
        this.decoder.destroy();
    }
    /**
     * Close the current socket.
     *
     * @private
     */
    _close() {
        this.skipReconnect = true;
        this._reconnecting = false;
        this.onclose(\"forced close\");
        if (this.engine)
            this.engine.close();
    }
    /**
     * Alias for close()
     *
     * @private
     */
    disconnect() {
        return this._close();
    }
    /**
     * Called upon engine close.
     *
     * @private
     */
    onclose(reason, description) {
        this.cleanup();
        this.backoff.reset();
        this._readyState = \"closed\";
        this.emitReserved(\"close\", reason, description);
        if (this._reconnection && !this.skipReconnect) {
            this.reconnect();
        }
    }
    /**
     * Attempt a reconnection.
     *
     * @private
     */
    reconnect() {
        if (this._reconnecting || this.skipReconnect)
            return this;
        const self = this;
        if (this.backoff.attempts >= this._reconnectionAttempts) {
            this.backoff.reset();
            this.emitReserved(\"reconnect_failed\");
            this._reconnecting = false;
        }
        else {
            const delay = this.backoff.duration();
            this._reconnecting = true;
            const timer = this.setTimeoutFn(() => {
                if (self.skipReconnect)
                    return;
                this.emitReserved(\"reconnect_attempt\", self.backoff.attempts);
                // check again for the case socket closed in above events
                if (self.skipReconnect)
                    return;
                self.open((err) => {
                    if (err) {
                        self._reconnecting = false;
                        self.reconnect();
                        this.emitReserved(\"reconnect_error\", err);
                    }
                    else {
                        self.onreconnect();
                    }
                });
            }, delay);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
    }
    /**
     * Called upon successful reconnect.
     *
     * @private
     */
    onreconnect() {
        const attempt = this.backoff.attempts;
        this._reconnecting = false;
        this.backoff.reset();
        this.emitReserved(\"reconnect\", attempt);
    }
}
","import { url } from \"./url.js\";
import { Manager } from \"./manager.js\";
import { Socket } from \"./socket.js\";
/**
 * Managers cache.
 */
const cache = {};
function lookup(uri, opts) {
    if (typeof uri === \"object\") {
        opts = uri;
        uri = undefined;
    }
    opts = opts || {};
    const parsed = url(uri, opts.path || \"/socket.io\");
    const source = parsed.source;
    const id = parsed.id;
    const path = parsed.path;
    const sameNamespace = cache[id] && path in cache[id][\"nsps\"];
    const newConnection = opts.forceNew ||
        opts[\"force new connection\"] ||
        false === opts.multiplex ||
        sameNamespace;
    let io;
    if (newConnection) {
        io = new Manager(source, opts);
    }
    else {
        if (!cache[id]) {
            cache[id] = new Manager(source, opts);
        }
        io = cache[id];
    }
    if (parsed.query && !opts.query) {
        opts.query = parsed.queryKey;
    }
    return io.socket(parsed.path, opts);
}
// so that \"lookup\" can be used both as a function (e.g. `io(...)`) and as a
// namespace (e.g. `io.connect(...)`), for backward compatibility
Object.assign(lookup, {
    Manager,
    Socket,
    io: lookup,
    connect: lookup,
});
/**
 * Protocol version.
 *
 * @public
 */
export { protocol } from \"socket.io-parser\";
/**
 * Expose constructors for standalone build.
 *
 * @public
 */
export { Manager, Socket, lookup as io, lookup as connect, lookup as default, };
","import { parse } from \"engine.io-client\";
/**
 * URL parser.
 *
 * @param uri - url
 * @param path - the request path of the connection
 * @param loc - An object meant to mimic window.location.
 *        Defaults to window.location.
 * @public
 */
export function url(uri, path = \"\", loc) {
    let obj = uri;
    // default to window.location
    loc = loc || (typeof location !== \"undefined\" && location);
    if (null == uri)
        uri = loc.protocol + \"//\" + loc.host;
    // relative path support
    if (typeof uri === \"string\") {
        if (\"/\" === uri.charAt(0)) {
            if (\"/\" === uri.charAt(1)) {
                uri = loc.protocol + uri;
            }
            else {
                uri = loc.host + uri;
            }
        }
        if (!/^(https?|wss?):\\/\\//.test(uri)) {
            if (\"undefined\" !== typeof loc) {
                uri = loc.protocol + \"//\" + uri;
            }
            else {
                uri = \"https://\" + uri;
            }
        }
        // parse
        obj = parse(uri);
    }
    // make sure we treat `localhost:80` and `localhost` equally
    if (!obj.port) {
        if (/^(http|ws)$/.test(obj.protocol)) {
            obj.port = \"80\";
        }
        else if (/^(http|ws)s$/.test(obj.protocol)) {
            obj.port = \"443\";
        }
    }
    obj.path = obj.path || \"/\";
    const ipv6 = obj.host.indexOf(\":\") !== -1;
    const host = ipv6 ? \"[\" + obj.host + \"]\" : obj.host;
    // define unique id
    obj.id = obj.protocol + \"://\" + host + \":\" + obj.port + path;
    // define href
    obj.href =
        obj.protocol +
            \"://\" +
            host +
            (loc && loc.port === obj.port ? \"\" : \":\" + obj.port);
    return obj;
}
"],"names":["PACKET_TYPES","Object","create","PACKET_TYPES_REVERSE","keys","forEach","key","ERROR_PACKET","type","data","withNativeBlob","Blob","prototype","toString","call","withNativeArrayBuffer","ArrayBuffer","encodePacket","supportsBinary","callback","encodeBlobAsBase64","obj","isView","buffer","fileReader","FileReader","onload","content","result","split","readAsDataURL","chars","lookup","Uint8Array","i","length","charCodeAt","decodePacket","encodedPacket","binaryType","mapBinary","charAt","decodeBase64Packet","substring","decoded","base64","encoded1","encoded2","encoded3","encoded4","bufferLength","len","p","arraybuffer","bytes","decode","SEPARATOR","String","fromCharCode","Emitter","mixin","on","addEventListener","event","fn","this","_callbacks","push","once","off","apply","arguments","removeListener","removeAllListeners","removeEventListener","cb","callbacks","splice","emit","args","Array","slice","emitReserved","listeners","hasListeners","globalThisShim","self","window","Function","pick","attr","reduce","acc","k","hasOwnProperty","NATIVE_SET_TIMEOUT","globalThis","setTimeout","NATIVE_CLEAR_TIMEOUT","clearTimeout","installTimerFunctions","opts","useNativeTimers","setTimeoutFn","bind","clearTimeoutFn","TransportError","Error","constructor","reason","description","context","super","Transport","writable","query","socket","onError","open","readyState","doOpen","close","doClose","onClose","send","packets","write","onOpen","onData","packet","onPacket","details","pause","onPause","alphabet","map","prev","seed","encode","num","encoded","Math","floor","yeast","now","Date","str","encodeURIComponent","value","XMLHttpRequest","err","hasCORS","XHR","xdomain","e","concat","join","empty","hasXHR2","responseType","Request","uri","method","async","undefined","xd","xscheme","xs","xhr","extraHeaders","setDisableHeaderCheck","setRequestHeader","withCredentials","requestTimeout","timeout","onreadystatechange","status","onLoad","document","index","requestsCount","requests","cleanup","fromError","abort","responseText","attachEvent","unloadHandler","nextTick","Promise","resolve","then","WebSocket","MozWebSocket","isReactNative","navigator","product","toLowerCase","transports","websocket","forceBase64","name","check","protocols","headers","ws","addEventListeners","onopen","autoUnref","_socket","unref","onclose","closeEvent","onmessage","ev","onerror","lastPacket","schema","secure","port","Number","timestampRequests","timestampParam","b64","encodedQuery","hostname","indexOf","path","polling","location","isSSL","protocol","poll","total","doPoll","encodedPayload","encodedPackets","decodedPacket","decodePayload","count","encodePayload","doWrite","sid","request","assign","req","xhrStatus","pollXhr","re","parts","parse","src","b","replace","m","exec","source","host","authority","ipv6uri","pathNames","regx","names","queryKey","$0","$1","$2","Socket","writeBuffer","prevBufferLen","agent","upgrade","rememberUpgrade","addTrailingSlash","rejectUnauthorized","perMessageDeflate","threshold","transportOptions","closeOnBeforeunload","qs","qry","pairs","l","pair","decodeURIComponent","id","upgrades","pingInterval","pingTimeout","pingTimeoutTimer","beforeunloadEventListener","transport","offlineEventListener","createTransport","EIO","priorWebsocketSuccess","shift","setTransport","onDrain","probe","failed","onTransportOpen","msg","upgrading","flush","freezeTransport","error","onTransportClose","onupgrade","to","onHandshake","JSON","resetPingTimeout","sendPacket","code","filterUpgrades","maxPayload","getWritablePackets","payloadSize","c","utf8Length","ceil","byteLength","size","options","compress","cleanupAndClose","waitForUpgrade","filteredUpgrades","j","withNativeFile","File","isBinary","hasBinary","toJSON","isArray","deconstructPacket","buffers","packetData","pack","_deconstructPacket","attachments","placeholder","_placeholder","newData","reconstructPacket","_reconstructPacket","RESERVED_EVENTS","PacketType","isObject","Decoder","reviver","add","reconstructor","decodeString","isBinaryEvent","BINARY_EVENT","BINARY_ACK","EVENT","ACK","BinaryReconstructor","takeBinaryData","start","buf","nsp","next","payload","tryParse","substr","isPayloadValid","static","CONNECT","DISCONNECT","CONNECT_ERROR","destroy","finishedReconstruction","reconPack","binData","replacer","encodeAsString","encodeAsBinary","stringify","deconstruction","unshift","freeze","connect","connect_error","disconnect","disconnecting","newListener","io","connected","recovered","receiveBuffer","sendBuffer","_queue","_queueSeq","ids","acks","flags","auth","_opts","_autoConnect","disconnected","subEvents","subs","onpacket","active","_readyState","retries","fromQueue","volatile","_addToQueue","ack","pop","_registerAckCallback","isTransportWritable","engine","notifyOutgoingListeners","_a","ackTimeout","timer","emitWithAck","withErr","reject","arg1","arg2","tryCount","pending","responseArgs","_drainQueue","force","_packet","_sendConnectPacket","_pid","pid","offset","_lastOffset","onconnect","onevent","onack","ondisconnect","message","emitEvent","_anyListeners","listener","sent","emitBuffered","subDestroy","onAny","prependAny","offAny","listenersAny","onAnyOutgoing","_anyOutgoingListeners","prependAnyOutgoing","offAnyOutgoing","listenersAnyOutgoing","Backoff","ms","min","max","factor","jitter","attempts","duration","pow","rand","random","deviation","reset","setMin","setMax","setJitter","Manager","nsps","reconnection","reconnectionAttempts","Infinity","reconnectionDelay","reconnectionDelayMax","randomizationFactor","backoff","_parser","parser","encoder","Encoder","decoder","autoConnect","v","_reconnection","_reconnectionAttempts","_reconnectionDelay","_randomizationFactor","_reconnectionDelayMax","_timeout","maybeReconnectOnOpen","_reconnecting","reconnect","Engine","skipReconnect","openSubDestroy","errorSub","onping","ondata","ondecoded","_destroy","_close","delay","onreconnect","attempt","cache","parsed","loc","test","href","url","sameNamespace","forceNew","multiplex"],"mappings":"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"}
./node_modules/socket.io/client-dist/socket.io.min.js.map:{"version":3,"file":"socket.io.min.js","sources":["../node_modules/engine.io-parser/build/esm/commons.js","../node_modules/engine.io-parser/build/esm/contrib/base64-arraybuffer.js","../node_modules/engine.io-parser/build/esm/encodePacket.browser.js","../node_modules/engine.io-parser/build/esm/decodePacket.browser.js","../node_modules/engine.io-parser/build/esm/index.js","../node_modules/@socket.io/component-emitter/index.mjs","../node_modules/engine.io-client/build/esm/globalThis.browser.js","../node_modules/engine.io-client/build/esm/util.js","../node_modules/engine.io-client/build/esm/contrib/yeast.js","../node_modules/engine.io-client/build/esm/transport.js","../node_modules/engine.io-client/build/esm/contrib/parseqs.js","../node_modules/engine.io-client/build/esm/contrib/has-cors.js","../node_modules/engine.io-client/build/esm/transports/xmlhttprequest.browser.js","../node_modules/engine.io-client/build/esm/transports/polling.js","../node_modules/engine.io-client/build/esm/transports/websocket-constructor.browser.js","../node_modules/engine.io-client/build/esm/transports/websocket.js","../node_modules/engine.io-client/build/esm/transports/index.js","../node_modules/engine.io-client/build/esm/contrib/parseuri.js","../node_modules/engine.io-client/build/esm/socket.js","../node_modules/engine.io-client/build/esm/index.js","../node_modules/socket.io-parser/build/esm/is-binary.js","../node_modules/socket.io-parser/build/esm/binary.js","../node_modules/socket.io-parser/build/esm/index.js","../build/esm/on.js","../build/esm/socket.js","../build/esm/contrib/backo2.js","../build/esm/manager.js","../build/esm/index.js","../build/esm/url.js"],"sourcesContent":["const PACKET_TYPES = Object.create(null); // no Map = no polyfill
PACKET_TYPES[\"open\"] = \"0\";
PACKET_TYPES[\"close\"] = \"1\";
PACKET_TYPES[\"ping\"] = \"2\";
PACKET_TYPES[\"pong\"] = \"3\";
PACKET_TYPES[\"message\"] = \"4\";
PACKET_TYPES[\"upgrade\"] = \"5\";
PACKET_TYPES[\"noop\"] = \"6\";
const PACKET_TYPES_REVERSE = Object.create(null);
Object.keys(PACKET_TYPES).forEach(key => {
    PACKET_TYPES_REVERSE[PACKET_TYPES[key]] = key;
});
const ERROR_PACKET = { type: \"error\", data: \"parser error\" };
export { PACKET_TYPES, PACKET_TYPES_REVERSE, ERROR_PACKET };
","const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// Use a lookup table to find the index.
const lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}
export const encode = (arraybuffer) => {
    let bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = '';
    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    if (len % 3 === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    }
    else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    return base64;
};
export const decode = (base64) => {
    let bufferLength = base64.length * 0.75, len = base64.length, i, p = 0, encoded1, encoded2, encoded3, encoded4;
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    const arraybuffer = new ArrayBuffer(bufferLength), bytes = new Uint8Array(arraybuffer);
    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    return arraybuffer;
};
","import { PACKET_TYPES } from \"./commons.js\";
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        Object.prototype.toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
// ArrayBuffer.isView method is not defined in IE10
const isView = obj => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj && obj.buffer instanceof ArrayBuffer;
};
const encodePacket = ({ type, data }, supportsBinary, callback) => {
    if (withNativeBlob && data instanceof Blob) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(data, callback);
        }
    }
    else if (withNativeArrayBuffer &&
        (data instanceof ArrayBuffer || isView(data))) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(new Blob([data]), callback);
        }
    }
    // plain string
    return callback(PACKET_TYPES[type] + (data || \"\"));
};
const encodeBlobAsBase64 = (data, callback) => {
    const fileReader = new FileReader();
    fileReader.onload = function () {
        const content = fileReader.result.split(\",\")[1];
        callback(\"b\" + content);
    };
    return fileReader.readAsDataURL(data);
};
export default encodePacket;
","import { ERROR_PACKET, PACKET_TYPES_REVERSE } from \"./commons.js\";
import { decode } from \"./contrib/base64-arraybuffer.js\";
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const decodePacket = (encodedPacket, binaryType) => {
    if (typeof encodedPacket !== \"string\") {
        return {
            type: \"message\",
            data: mapBinary(encodedPacket, binaryType)
        };
    }
    const type = encodedPacket.charAt(0);
    if (type === \"b\") {
        return {
            type: \"message\",
            data: decodeBase64Packet(encodedPacket.substring(1), binaryType)
        };
    }
    const packetType = PACKET_TYPES_REVERSE[type];
    if (!packetType) {
        return ERROR_PACKET;
    }
    return encodedPacket.length > 1
        ? {
            type: PACKET_TYPES_REVERSE[type],
            data: encodedPacket.substring(1)
        }
        : {
            type: PACKET_TYPES_REVERSE[type]
        };
};
const decodeBase64Packet = (data, binaryType) => {
    if (withNativeArrayBuffer) {
        const decoded = decode(data);
        return mapBinary(decoded, binaryType);
    }
    else {
        return { base64: true, data }; // fallback for old browsers
    }
};
const mapBinary = (data, binaryType) => {
    switch (binaryType) {
        case \"blob\":
            return data instanceof ArrayBuffer ? new Blob([data]) : data;
        case \"arraybuffer\":
        default:
            return data; // assuming the data is already an ArrayBuffer
    }
};
export default decodePacket;
","import encodePacket from \"./encodePacket.js\";
import decodePacket from \"./decodePacket.js\";
const SEPARATOR = String.fromCharCode(30); // see https://en.wikipedia.org/wiki/Delimiter#ASCII_delimited_text
const encodePayload = (packets, callback) => {
    // some packets may be added to the array while encoding, so the initial length must be saved
    const length = packets.length;
    const encodedPackets = new Array(length);
    let count = 0;
    packets.forEach((packet, i) => {
        // force base64 encoding for binary packets
        encodePacket(packet, false, encodedPacket => {
            encodedPackets[i] = encodedPacket;
            if (++count === length) {
                callback(encodedPackets.join(SEPARATOR));
            }
        });
    });
};
const decodePayload = (encodedPayload, binaryType) => {
    const encodedPackets = encodedPayload.split(SEPARATOR);
    const packets = [];
    for (let i = 0; i < encodedPackets.length; i++) {
        const decodedPacket = decodePacket(encodedPackets[i], binaryType);
        packets.push(decodedPacket);
        if (decodedPacket.type === \"error\") {
            break;
        }
    }
    return packets;
};
export const protocol = 4;
export { encodePacket, encodePayload, decodePacket, decodePayload };
","/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

export function Emitter(obj) {
  if (obj) return mixin(obj);
}

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  function on() {
    this.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks['$' + event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks['$' + event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }

  // Remove event specific arrays for event types that no
  // one is subscribed for to avoid memory leak.
  if (callbacks.length === 0) {
    delete this._callbacks['$' + event];
  }

  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};

  var args = new Array(arguments.length - 1)
    , callbacks = this._callbacks['$' + event];

  for (var i = 1; i < arguments.length; i++) {
    args[i - 1] = arguments[i];
  }

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

// alias used for reserved events (protected method)
Emitter.prototype.emitReserved = Emitter.prototype.emit;

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks['$' + event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};
","export const globalThisShim = (() => {
    if (typeof self !== \"undefined\") {
        return self;
    }
    else if (typeof window !== \"undefined\") {
        return window;
    }
    else {
        return Function(\"return this\")();
    }
})();
","import { globalThisShim as globalThis } from \"./globalThis.js\";
export function pick(obj, ...attr) {
    return attr.reduce((acc, k) => {
        if (obj.hasOwnProperty(k)) {
            acc[k] = obj[k];
        }
        return acc;
    }, {});
}
// Keep a reference to the real timeout functions so they can be used when overridden
const NATIVE_SET_TIMEOUT = globalThis.setTimeout;
const NATIVE_CLEAR_TIMEOUT = globalThis.clearTimeout;
export function installTimerFunctions(obj, opts) {
    if (opts.useNativeTimers) {
        obj.setTimeoutFn = NATIVE_SET_TIMEOUT.bind(globalThis);
        obj.clearTimeoutFn = NATIVE_CLEAR_TIMEOUT.bind(globalThis);
    }
    else {
        obj.setTimeoutFn = globalThis.setTimeout.bind(globalThis);
        obj.clearTimeoutFn = globalThis.clearTimeout.bind(globalThis);
    }
}
// base64 encoded buffers are about 33% bigger (https://en.wikipedia.org/wiki/Base64)
const BASE64_OVERHEAD = 1.33;
// we could also have used `new Blob([obj]).size`, but it isn't supported in IE9
export function byteLength(obj) {
    if (typeof obj === \"string\") {
        return utf8Length(obj);
    }
    // arraybuffer or blob
    return Math.ceil((obj.byteLength || obj.size) * BASE64_OVERHEAD);
}
function utf8Length(str) {
    let c = 0, length = 0;
    for (let i = 0, l = str.length; i < l; i++) {
        c = str.charCodeAt(i);
        if (c < 0x80) {
            length += 1;
        }
        else if (c < 0x800) {
            length += 2;
        }
        else if (c < 0xd800 || c >= 0xe000) {
            length += 3;
        }
        else {
            i++;
            length += 4;
        }
    }
    return length;
}
","// imported from https://github.com/unshiftio/yeast
'use strict';
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'.split(''), length = 64, map = {};
let seed = 0, i = 0, prev;
/**
 * Return a string representing the specified number.
 *
 * @param {Number} num The number to convert.
 * @returns {String} The string representation of the number.
 * @api public
 */
export function encode(num) {
    let encoded = '';
    do {
        encoded = alphabet[num % length] + encoded;
        num = Math.floor(num / length);
    } while (num > 0);
    return encoded;
}
/**
 * Return the integer value specified by the given string.
 *
 * @param {String} str The string to convert.
 * @returns {Number} The integer value represented by the string.
 * @api public
 */
export function decode(str) {
    let decoded = 0;
    for (i = 0; i < str.length; i++) {
        decoded = decoded * length + map[str.charAt(i)];
    }
    return decoded;
}
/**
 * Yeast: A tiny growing id generator.
 *
 * @returns {String} A unique id.
 * @api public
 */
export function yeast() {
    const now = encode(+new Date());
    if (now !== prev)
        return seed = 0, prev = now;
    return now + '.' + encode(seed++);
}
//
// Map each character to its index.
//
for (; i < length; i++)
    map[alphabet[i]] = i;
","import { decodePacket } from \"engine.io-parser\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions } from \"./util.js\";
class TransportError extends Error {
    constructor(reason, description, context) {
        super(reason);
        this.description = description;
        this.context = context;
        this.type = \"TransportError\";
    }
}
export class Transport extends Emitter {
    /**
     * Transport abstract constructor.
     *
     * @param {Object} opts - options
     * @protected
     */
    constructor(opts) {
        super();
        this.writable = false;
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.query = opts.query;
        this.socket = opts.socket;
    }
    /**
     * Emits an error.
     *
     * @param {String} reason
     * @param description
     * @param context - the error context
     * @return {Transport} for chaining
     * @protected
     */
    onError(reason, description, context) {
        super.emitReserved(\"error\", new TransportError(reason, description, context));
        return this;
    }
    /**
     * Opens the transport.
     */
    open() {
        this.readyState = \"opening\";
        this.doOpen();
        return this;
    }
    /**
     * Closes the transport.
     */
    close() {
        if (this.readyState === \"opening\" || this.readyState === \"open\") {
            this.doClose();
            this.onClose();
        }
        return this;
    }
    /**
     * Sends multiple packets.
     *
     * @param {Array} packets
     */
    send(packets) {
        if (this.readyState === \"open\") {
            this.write(packets);
        }
        else {
            // this might happen if the transport was silently closed in the beforeunload event handler
        }
    }
    /**
     * Called upon open
     *
     * @protected
     */
    onOpen() {
        this.readyState = \"open\";
        this.writable = true;
        super.emitReserved(\"open\");
    }
    /**
     * Called with data.
     *
     * @param {String} data
     * @protected
     */
    onData(data) {
        const packet = decodePacket(data, this.socket.binaryType);
        this.onPacket(packet);
    }
    /**
     * Called with a decoded packet.
     *
     * @protected
     */
    onPacket(packet) {
        super.emitReserved(\"packet\", packet);
    }
    /**
     * Called upon close.
     *
     * @protected
     */
    onClose(details) {
        this.readyState = \"closed\";
        super.emitReserved(\"close\", details);
    }
    /**
     * Pauses the transport, in order not to lose packets during an upgrade.
     *
     * @param onPause
     */
    pause(onPause) { }
}
","// imported from https://github.com/galkn/querystring
/**
 * Compiles a querystring
 * Returns string representation of the object
 *
 * @param {Object}
 * @api private
 */
export function encode(obj) {
    let str = '';
    for (let i in obj) {
        if (obj.hasOwnProperty(i)) {
            if (str.length)
                str += '&';
            str += encodeURIComponent(i) + '=' + encodeURIComponent(obj[i]);
        }
    }
    return str;
}
/**
 * Parses a simple querystring into an object
 *
 * @param {String} qs
 * @api private
 */
export function decode(qs) {
    let qry = {};
    let pairs = qs.split('&');
    for (let i = 0, l = pairs.length; i < l; i++) {
        let pair = pairs[i].split('=');
        qry[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
    }
    return qry;
}
","// imported from https://github.com/component/has-cors
let value = false;
try {
    value = typeof XMLHttpRequest !== 'undefined' &&
        'withCredentials' in new XMLHttpRequest();
}
catch (err) {
    // if XMLHttp support is disabled in IE then it will throw
    // when trying to create
}
export const hasCORS = value;
","// browser shim for xmlhttprequest module
import { hasCORS } from \"../contrib/has-cors.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
export function XHR(opts) {
    const xdomain = opts.xdomain;
    // XMLHttpRequest can be disabled on IE
    try {
        if (\"undefined\" !== typeof XMLHttpRequest && (!xdomain || hasCORS)) {
            return new XMLHttpRequest();
        }
    }
    catch (e) { }
    if (!xdomain) {
        try {
            return new globalThis[[\"Active\"].concat(\"Object\").join(\"X\")](\"Microsoft.XMLHTTP\");
        }
        catch (e) { }
    }
}
","import { Transport } from \"../transport.js\";
import { yeast } from \"../contrib/yeast.js\";
import { encode } from \"../contrib/parseqs.js\";
import { encodePayload, decodePayload } from \"engine.io-parser\";
import { XHR as XMLHttpRequest } from \"./xmlhttprequest.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions, pick } from \"../util.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
function empty() { }
const hasXHR2 = (function () {
    const xhr = new XMLHttpRequest({
        xdomain: false,
    });
    return null != xhr.responseType;
})();
export class Polling extends Transport {
    /**
     * XHR Polling constructor.
     *
     * @param {Object} opts
     * @package
     */
    constructor(opts) {
        super(opts);
        this.polling = false;
        if (typeof location !== \"undefined\") {
            const isSSL = \"https:\" === location.protocol;
            let port = location.port;
            // some user agents have empty `location.port`
            if (!port) {
                port = isSSL ? \"443\" : \"80\";
            }
            this.xd =
                (typeof location !== \"undefined\" &&
                    opts.hostname !== location.hostname) ||
                    port !== opts.port;
            this.xs = opts.secure !== isSSL;
        }
        /**
         * XHR supports binary
         */
        const forceBase64 = opts && opts.forceBase64;
        this.supportsBinary = hasXHR2 && !forceBase64;
    }
    get name() {
        return \"polling\";
    }
    /**
     * Opens the socket (triggers polling). We write a PING message to determine
     * when the transport is open.
     *
     * @protected
     */
    doOpen() {
        this.poll();
    }
    /**
     * Pauses polling.
     *
     * @param {Function} onPause - callback upon buffers are flushed and transport is paused
     * @package
     */
    pause(onPause) {
        this.readyState = \"pausing\";
        const pause = () => {
            this.readyState = \"paused\";
            onPause();
        };
        if (this.polling || !this.writable) {
            let total = 0;
            if (this.polling) {
                total++;
                this.once(\"pollComplete\", function () {
                    --total || pause();
                });
            }
            if (!this.writable) {
                total++;
                this.once(\"drain\", function () {
                    --total || pause();
                });
            }
        }
        else {
            pause();
        }
    }
    /**
     * Starts polling cycle.
     *
     * @private
     */
    poll() {
        this.polling = true;
        this.doPoll();
        this.emitReserved(\"poll\");
    }
    /**
     * Overloads onData to detect payloads.
     *
     * @protected
     */
    onData(data) {
        const callback = (packet) => {
            // if its the first message we consider the transport open
            if (\"opening\" === this.readyState && packet.type === \"open\") {
                this.onOpen();
            }
            // if its a close packet, we close the ongoing requests
            if (\"close\" === packet.type) {
                this.onClose({ description: \"transport closed by the server\" });
                return false;
            }
            // otherwise bypass onData and handle the message
            this.onPacket(packet);
        };
        // decode payload
        decodePayload(data, this.socket.binaryType).forEach(callback);
        // if an event did not trigger closing
        if (\"closed\" !== this.readyState) {
            // if we got data we're not polling
            this.polling = false;
            this.emitReserved(\"pollComplete\");
            if (\"open\" === this.readyState) {
                this.poll();
            }
            else {
            }
        }
    }
    /**
     * For polling, send a close packet.
     *
     * @protected
     */
    doClose() {
        const close = () => {
            this.write([{ type: \"close\" }]);
        };
        if (\"open\" === this.readyState) {
            close();
        }
        else {
            // in case we're trying to close while
            // handshaking is in progress (GH-164)
            this.once(\"open\", close);
        }
    }
    /**
     * Writes a packets payload.
     *
     * @param {Array} packets - data packets
     * @protected
     */
    write(packets) {
        this.writable = false;
        encodePayload(packets, (data) => {
            this.doWrite(data, () => {
                this.writable = true;
                this.emitReserved(\"drain\");
            });
        });
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"https\" : \"http\";
        let port = \"\";
        // cache busting is forced
        if (false !== this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        if (!this.supportsBinary && !query.sid) {
            query.b64 = 1;
        }
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"https\" === schema && Number(this.opts.port) !== 443) ||
                (\"http\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Creates a request.
     *
     * @param {String} method
     * @private
     */
    request(opts = {}) {
        Object.assign(opts, { xd: this.xd, xs: this.xs }, this.opts);
        return new Request(this.uri(), opts);
    }
    /**
     * Sends data.
     *
     * @param {String} data to send.
     * @param {Function} called upon flush.
     * @private
     */
    doWrite(data, fn) {
        const req = this.request({
            method: \"POST\",
            data: data,
        });
        req.on(\"success\", fn);
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr post error\", xhrStatus, context);
        });
    }
    /**
     * Starts a poll cycle.
     *
     * @private
     */
    doPoll() {
        const req = this.request();
        req.on(\"data\", this.onData.bind(this));
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr poll error\", xhrStatus, context);
        });
        this.pollXhr = req;
    }
}
export class Request extends Emitter {
    /**
     * Request constructor
     *
     * @param {Object} options
     * @package
     */
    constructor(uri, opts) {
        super();
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.method = opts.method || \"GET\";
        this.uri = uri;
        this.async = false !== opts.async;
        this.data = undefined !== opts.data ? opts.data : null;
        this.create();
    }
    /**
     * Creates the XHR object and sends the request.
     *
     * @private
     */
    create() {
        const opts = pick(this.opts, \"agent\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"autoUnref\");
        opts.xdomain = !!this.opts.xd;
        opts.xscheme = !!this.opts.xs;
        const xhr = (this.xhr = new XMLHttpRequest(opts));
        try {
            xhr.open(this.method, this.uri, this.async);
            try {
                if (this.opts.extraHeaders) {
                    xhr.setDisableHeaderCheck && xhr.setDisableHeaderCheck(true);
                    for (let i in this.opts.extraHeaders) {
                        if (this.opts.extraHeaders.hasOwnProperty(i)) {
                            xhr.setRequestHeader(i, this.opts.extraHeaders[i]);
                        }
                    }
                }
            }
            catch (e) { }
            if (\"POST\" === this.method) {
                try {
                    xhr.setRequestHeader(\"Content-type\", \"text/plain;charset=UTF-8\");
                }
                catch (e) { }
            }
            try {
                xhr.setRequestHeader(\"Accept\", \"*/*\");
            }
            catch (e) { }
            // ie6 check
            if (\"withCredentials\" in xhr) {
                xhr.withCredentials = this.opts.withCredentials;
            }
            if (this.opts.requestTimeout) {
                xhr.timeout = this.opts.requestTimeout;
            }
            xhr.onreadystatechange = () => {
                if (4 !== xhr.readyState)
                    return;
                if (200 === xhr.status || 1223 === xhr.status) {
                    this.onLoad();
                }
                else {
                    // make sure the `error` event handler that's user-set
                    // does not throw in the same tick and gets caught here
                    this.setTimeoutFn(() => {
                        this.onError(typeof xhr.status === \"number\" ? xhr.status : 0);
                    }, 0);
                }
            };
            xhr.send(this.data);
        }
        catch (e) {
            // Need to defer since .create() is called directly from the constructor
            // and thus the 'error' event can only be only bound *after* this exception
            // occurs.  Therefore, also, we cannot throw here at all.
            this.setTimeoutFn(() => {
                this.onError(e);
            }, 0);
            return;
        }
        if (typeof document !== \"undefined\") {
            this.index = Request.requestsCount++;
            Request.requests[this.index] = this;
        }
    }
    /**
     * Called upon error.
     *
     * @private
     */
    onError(err) {
        this.emitReserved(\"error\", err, this.xhr);
        this.cleanup(true);
    }
    /**
     * Cleans up house.
     *
     * @private
     */
    cleanup(fromError) {
        if (\"undefined\" === typeof this.xhr || null === this.xhr) {
            return;
        }
        this.xhr.onreadystatechange = empty;
        if (fromError) {
            try {
                this.xhr.abort();
            }
            catch (e) { }
        }
        if (typeof document !== \"undefined\") {
            delete Request.requests[this.index];
        }
        this.xhr = null;
    }
    /**
     * Called upon load.
     *
     * @private
     */
    onLoad() {
        const data = this.xhr.responseText;
        if (data !== null) {
            this.emitReserved(\"data\", data);
            this.emitReserved(\"success\");
            this.cleanup();
        }
    }
    /**
     * Aborts the request.
     *
     * @package
     */
    abort() {
        this.cleanup();
    }
}
Request.requestsCount = 0;
Request.requests = {};
/**
 * Aborts pending requests when unloading the window. This is needed to prevent
 * memory leaks (e.g. when using IE) and to ensure that no spurious error is
 * emitted.
 */
if (typeof document !== \"undefined\") {
    // @ts-ignore
    if (typeof attachEvent === \"function\") {
        // @ts-ignore
        attachEvent(\"onunload\", unloadHandler);
    }
    else if (typeof addEventListener === \"function\") {
        const terminationEvent = \"onpagehide\" in globalThis ? \"pagehide\" : \"unload\";
        addEventListener(terminationEvent, unloadHandler, false);
    }
}
function unloadHandler() {
    for (let i in Request.requests) {
        if (Request.requests.hasOwnProperty(i)) {
            Request.requests[i].abort();
        }
    }
}
","import { globalThisShim as globalThis } from \"../globalThis.js\";
export const nextTick = (() => {
    const isPromiseAvailable = typeof Promise === \"function\" && typeof Promise.resolve === \"function\";
    if (isPromiseAvailable) {
        return (cb) => Promise.resolve().then(cb);
    }
    else {
        return (cb, setTimeoutFn) => setTimeoutFn(cb, 0);
    }
})();
export const WebSocket = globalThis.WebSocket || globalThis.MozWebSocket;
export const usingBrowserWebSocket = true;
export const defaultBinaryType = \"arraybuffer\";
","import { Transport } from \"../transport.js\";
import { encode } from \"../contrib/parseqs.js\";
import { yeast } from \"../contrib/yeast.js\";
import { pick } from \"../util.js\";
import { defaultBinaryType, nextTick, usingBrowserWebSocket, WebSocket, } from \"./websocket-constructor.js\";
import { encodePacket } from \"engine.io-parser\";
// detect ReactNative environment
const isReactNative = typeof navigator !== \"undefined\" &&
    typeof navigator.product === \"string\" &&
    navigator.product.toLowerCase() === \"reactnative\";
export class WS extends Transport {
    /**
     * WebSocket transport constructor.
     *
     * @param {Object} opts - connection options
     * @protected
     */
    constructor(opts) {
        super(opts);
        this.supportsBinary = !opts.forceBase64;
    }
    get name() {
        return \"websocket\";
    }
    doOpen() {
        if (!this.check()) {
            // let probe timeout
            return;
        }
        const uri = this.uri();
        const protocols = this.opts.protocols;
        // React Native only supports the 'headers' option, and will print a warning if anything else is passed
        const opts = isReactNative
            ? {}
            : pick(this.opts, \"agent\", \"perMessageDeflate\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"localAddress\", \"protocolVersion\", \"origin\", \"maxPayload\", \"family\", \"checkServerIdentity\");
        if (this.opts.extraHeaders) {
            opts.headers = this.opts.extraHeaders;
        }
        try {
            this.ws =
                usingBrowserWebSocket && !isReactNative
                    ? protocols
                        ? new WebSocket(uri, protocols)
                        : new WebSocket(uri)
                    : new WebSocket(uri, protocols, opts);
        }
        catch (err) {
            return this.emitReserved(\"error\", err);
        }
        this.ws.binaryType = this.socket.binaryType || defaultBinaryType;
        this.addEventListeners();
    }
    /**
     * Adds event listeners to the socket
     *
     * @private
     */
    addEventListeners() {
        this.ws.onopen = () => {
            if (this.opts.autoUnref) {
                this.ws._socket.unref();
            }
            this.onOpen();
        };
        this.ws.onclose = (closeEvent) => this.onClose({
            description: \"websocket connection closed\",
            context: closeEvent,
        });
        this.ws.onmessage = (ev) => this.onData(ev.data);
        this.ws.onerror = (e) => this.onError(\"websocket error\", e);
    }
    write(packets) {
        this.writable = false;
        // encodePacket efficient as it uses WS framing
        // no need for encodePayload
        for (let i = 0; i < packets.length; i++) {
            const packet = packets[i];
            const lastPacket = i === packets.length - 1;
            encodePacket(packet, this.supportsBinary, (data) => {
                // always create a new object (GH-437)
                const opts = {};
                if (!usingBrowserWebSocket) {
                    if (packet.options) {
                        opts.compress = packet.options.compress;
                    }
                    if (this.opts.perMessageDeflate) {
                        const len = 
                        // @ts-ignore
                        \"string\" === typeof data ? Buffer.byteLength(data) : data.length;
                        if (len < this.opts.perMessageDeflate.threshold) {
                            opts.compress = false;
                        }
                    }
                }
                // Sometimes the websocket has already been closed but the browser didn't
                // have a chance of informing us about it yet, in that case send will
                // throw an error
                try {
                    if (usingBrowserWebSocket) {
                        // TypeError is thrown when passing the second argument on Safari
                        this.ws.send(data);
                    }
                    else {
                        this.ws.send(data, opts);
                    }
                }
                catch (e) {
                }
                if (lastPacket) {
                    // fake drain
                    // defer to next tick to allow Socket to clear writeBuffer
                    nextTick(() => {
                        this.writable = true;
                        this.emitReserved(\"drain\");
                    }, this.setTimeoutFn);
                }
            });
        }
    }
    doClose() {
        if (typeof this.ws !== \"undefined\") {
            this.ws.close();
            this.ws = null;
        }
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"wss\" : \"ws\";
        let port = \"\";
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"wss\" === schema && Number(this.opts.port) !== 443) ||
                (\"ws\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        // append timestamp to URI
        if (this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        // communicate binary support capabilities
        if (!this.supportsBinary) {
            query.b64 = 1;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Feature detection for WebSocket.
     *
     * @return {Boolean} whether this transport is available.
     * @private
     */
    check() {
        return !!WebSocket;
    }
}
","import { Polling } from \"./polling.js\";
import { WS } from \"./websocket.js\";
export const transports = {
    websocket: WS,
    polling: Polling,
};
","// imported from https://github.com/galkn/parseuri
/**
 * Parses a URI
 *
 * Note: we could also have used the built-in URL object, but it isn't supported on all platforms.
 *
 * See:
 * - https://developer.mozilla.org/en-US/docs/Web/API/URL
 * - https://caniuse.com/url
 * - https://www.rfc-editor.org/rfc/rfc3986#appendix-B
 *
 * History of the parse() method:
 * - first commit: https://github.com/socketio/socket.io-client/commit/4ee1d5d94b3906a9c052b459f1a818b15f38f91c
 * - export into its own module: https://github.com/socketio/engine.io-client/commit/de2c561e4564efeb78f1bdb1ba39ef81b2822cb3
 * - reimport: https://github.com/socketio/engine.io-client/commit/df32277c3f6d622eec5ed09f493cae3f3391d242
 *
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * @api private
 */
const re = /^(?:(?![^:@\\/?#]+:[^:@\\/]*@)(http|https|ws|wss):\\/\\/)?((?:(([^:@\\/?#]*)(?::([^:@\\/?#]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\\/?#]*)(?::(\\d*))?)(((\\/(?:[^?#](?![^?#\\/]*\\.[^?#\\/.]+(?:[?#]|$)))*\\/?)?([^?#\\/]*))(?:\\?([^#]*))?(?:#(.*))?)/;
const parts = [
    'source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'
];
export function parse(str) {
    const src = str, b = str.indexOf('['), e = str.indexOf(']');
    if (b != -1 && e != -1) {
        str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
    }
    let m = re.exec(str || ''), uri = {}, i = 14;
    while (i--) {
        uri[parts[i]] = m[i] || '';
    }
    if (b != -1 && e != -1) {
        uri.source = src;
        uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
        uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
        uri.ipv6uri = true;
    }
    uri.pathNames = pathNames(uri, uri['path']);
    uri.queryKey = queryKey(uri, uri['query']);
    return uri;
}
function pathNames(obj, path) {
    const regx = /\\/{2,9}/g, names = path.replace(regx, \"/\").split(\"/\");
    if (path.slice(0, 1) == '/' || path.length === 0) {
        names.splice(0, 1);
    }
    if (path.slice(-1) == '/') {
        names.splice(names.length - 1, 1);
    }
    return names;
}
function queryKey(uri, query) {
    const data = {};
    query.replace(/(?:^|&)([^&=]*)=?([^&]*)/g, function ($0, $1, $2) {
        if ($1) {
            data[$1] = $2;
        }
    });
    return data;
}
","import { transports } from \"./transports/index.js\";
import { installTimerFunctions, byteLength } from \"./util.js\";
import { decode } from \"./contrib/parseqs.js\";
import { parse } from \"./contrib/parseuri.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { protocol } from \"engine.io-parser\";
export class Socket extends Emitter {
    /**
     * Socket constructor.
     *
     * @param {String|Object} uri - uri or options
     * @param {Object} opts - options
     */
    constructor(uri, opts = {}) {
        super();
        this.writeBuffer = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = null;
        }
        if (uri) {
            uri = parse(uri);
            opts.hostname = uri.host;
            opts.secure = uri.protocol === \"https\" || uri.protocol === \"wss\";
            opts.port = uri.port;
            if (uri.query)
                opts.query = uri.query;
        }
        else if (opts.host) {
            opts.hostname = parse(opts.host).host;
        }
        installTimerFunctions(this, opts);
        this.secure =
            null != opts.secure
                ? opts.secure
                : typeof location !== \"undefined\" && \"https:\" === location.protocol;
        if (opts.hostname && !opts.port) {
            // if no port is specified manually, use the protocol default
            opts.port = this.secure ? \"443\" : \"80\";
        }
        this.hostname =
            opts.hostname ||
                (typeof location !== \"undefined\" ? location.hostname : \"localhost\");
        this.port =
            opts.port ||
                (typeof location !== \"undefined\" && location.port
                    ? location.port
                    : this.secure
                        ? \"443\"
                        : \"80\");
        this.transports = opts.transports || [\"polling\", \"websocket\"];
        this.writeBuffer = [];
        this.prevBufferLen = 0;
        this.opts = Object.assign({
            path: \"/engine.io\",
            agent: false,
            withCredentials: false,
            upgrade: true,
            timestampParam: \"t\",
            rememberUpgrade: false,
            addTrailingSlash: true,
            rejectUnauthorized: true,
            perMessageDeflate: {
                threshold: 1024,
            },
            transportOptions: {},
            closeOnBeforeunload: true,
        }, opts);
        this.opts.path =
            this.opts.path.replace(/\\/$/, \"\") +
                (this.opts.addTrailingSlash ? \"/\" : \"\");
        if (typeof this.opts.query === \"string\") {
            this.opts.query = decode(this.opts.query);
        }
        // set on handshake
        this.id = null;
        this.upgrades = null;
        this.pingInterval = null;
        this.pingTimeout = null;
        // set on heartbeat
        this.pingTimeoutTimer = null;
        if (typeof addEventListener === \"function\") {
            if (this.opts.closeOnBeforeunload) {
                // Firefox closes the connection when the \"beforeunload\" event is emitted but not Chrome. This event listener
                // ensures every browser behaves the same (no \"disconnect\" event at the Socket.IO level when the page is
                // closed/reloaded)
                this.beforeunloadEventListener = () => {
                    if (this.transport) {
                        // silently close the transport
                        this.transport.removeAllListeners();
                        this.transport.close();
                    }
                };
                addEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
            }
            if (this.hostname !== \"localhost\") {
                this.offlineEventListener = () => {
                    this.onClose(\"transport close\", {
                        description: \"network connection lost\",
                    });
                };
                addEventListener(\"offline\", this.offlineEventListener, false);
            }
        }
        this.open();
    }
    /**
     * Creates transport of the given type.
     *
     * @param {String} name - transport name
     * @return {Transport}
     * @private
     */
    createTransport(name) {
        const query = Object.assign({}, this.opts.query);
        // append engine.io protocol identifier
        query.EIO = protocol;
        // transport name
        query.transport = name;
        // session id if we already have one
        if (this.id)
            query.sid = this.id;
        const opts = Object.assign({}, this.opts.transportOptions[name], this.opts, {
            query,
            socket: this,
            hostname: this.hostname,
            secure: this.secure,
            port: this.port,
        });
        return new transports[name](opts);
    }
    /**
     * Initializes transport to use and starts probe.
     *
     * @private
     */
    open() {
        let transport;
        if (this.opts.rememberUpgrade &&
            Socket.priorWebsocketSuccess &&
            this.transports.indexOf(\"websocket\") !== -1) {
            transport = \"websocket\";
        }
        else if (0 === this.transports.length) {
            // Emit error on next tick so it can be listened to
            this.setTimeoutFn(() => {
                this.emitReserved(\"error\", \"No transports available\");
            }, 0);
            return;
        }
        else {
            transport = this.transports[0];
        }
        this.readyState = \"opening\";
        // Retry with the next transport if the transport is disabled (jsonp: false)
        try {
            transport = this.createTransport(transport);
        }
        catch (e) {
            this.transports.shift();
            this.open();
            return;
        }
        transport.open();
        this.setTransport(transport);
    }
    /**
     * Sets the current transport. Disables the existing one (if any).
     *
     * @private
     */
    setTransport(transport) {
        if (this.transport) {
            this.transport.removeAllListeners();
        }
        // set up transport
        this.transport = transport;
        // set up transport listeners
        transport
            .on(\"drain\", this.onDrain.bind(this))
            .on(\"packet\", this.onPacket.bind(this))
            .on(\"error\", this.onError.bind(this))
            .on(\"close\", (reason) => this.onClose(\"transport close\", reason));
    }
    /**
     * Probes a transport.
     *
     * @param {String} name - transport name
     * @private
     */
    probe(name) {
        let transport = this.createTransport(name);
        let failed = false;
        Socket.priorWebsocketSuccess = false;
        const onTransportOpen = () => {
            if (failed)
                return;
            transport.send([{ type: \"ping\", data: \"probe\" }]);
            transport.once(\"packet\", (msg) => {
                if (failed)
                    return;
                if (\"pong\" === msg.type && \"probe\" === msg.data) {
                    this.upgrading = true;
                    this.emitReserved(\"upgrading\", transport);
                    if (!transport)
                        return;
                    Socket.priorWebsocketSuccess = \"websocket\" === transport.name;
                    this.transport.pause(() => {
                        if (failed)
                            return;
                        if (\"closed\" === this.readyState)
                            return;
                        cleanup();
                        this.setTransport(transport);
                        transport.send([{ type: \"upgrade\" }]);
                        this.emitReserved(\"upgrade\", transport);
                        transport = null;
                        this.upgrading = false;
                        this.flush();
                    });
                }
                else {
                    const err = new Error(\"probe error\");
                    // @ts-ignore
                    err.transport = transport.name;
                    this.emitReserved(\"upgradeError\", err);
                }
            });
        };
        function freezeTransport() {
            if (failed)
                return;
            // Any callback called by transport should be ignored since now
            failed = true;
            cleanup();
            transport.close();
            transport = null;
        }
        // Handle any error that happens while probing
        const onerror = (err) => {
            const error = new Error(\"probe error: \" + err);
            // @ts-ignore
            error.transport = transport.name;
            freezeTransport();
            this.emitReserved(\"upgradeError\", error);
        };
        function onTransportClose() {
            onerror(\"transport closed\");
        }
        // When the socket is closed while we're probing
        function onclose() {
            onerror(\"socket closed\");
        }
        // When the socket is upgraded while we're probing
        function onupgrade(to) {
            if (transport && to.name !== transport.name) {
                freezeTransport();
            }
        }
        // Remove all listeners on the transport and on self
        const cleanup = () => {
            transport.removeListener(\"open\", onTransportOpen);
            transport.removeListener(\"error\", onerror);
            transport.removeListener(\"close\", onTransportClose);
            this.off(\"close\", onclose);
            this.off(\"upgrading\", onupgrade);
        };
        transport.once(\"open\", onTransportOpen);
        transport.once(\"error\", onerror);
        transport.once(\"close\", onTransportClose);
        this.once(\"close\", onclose);
        this.once(\"upgrading\", onupgrade);
        transport.open();
    }
    /**
     * Called when connection is deemed open.
     *
     * @private
     */
    onOpen() {
        this.readyState = \"open\";
        Socket.priorWebsocketSuccess = \"websocket\" === this.transport.name;
        this.emitReserved(\"open\");
        this.flush();
        // we check for `readyState` in case an `open`
        // listener already closed the socket
        if (\"open\" === this.readyState && this.opts.upgrade) {
            let i = 0;
            const l = this.upgrades.length;
            for (; i < l; i++) {
                this.probe(this.upgrades[i]);
            }
        }
    }
    /**
     * Handles a packet.
     *
     * @private
     */
    onPacket(packet) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            this.emitReserved(\"packet\", packet);
            // Socket is live - any packet counts
            this.emitReserved(\"heartbeat\");
            switch (packet.type) {
                case \"open\":
                    this.onHandshake(JSON.parse(packet.data));
                    break;
                case \"ping\":
                    this.resetPingTimeout();
                    this.sendPacket(\"pong\");
                    this.emitReserved(\"ping\");
                    this.emitReserved(\"pong\");
                    break;
                case \"error\":
                    const err = new Error(\"server error\");
                    // @ts-ignore
                    err.code = packet.data;
                    this.onError(err);
                    break;
                case \"message\":
                    this.emitReserved(\"data\", packet.data);
                    this.emitReserved(\"message\", packet.data);
                    break;
            }
        }
        else {
        }
    }
    /**
     * Called upon handshake completion.
     *
     * @param {Object} data - handshake obj
     * @private
     */
    onHandshake(data) {
        this.emitReserved(\"handshake\", data);
        this.id = data.sid;
        this.transport.query.sid = data.sid;
        this.upgrades = this.filterUpgrades(data.upgrades);
        this.pingInterval = data.pingInterval;
        this.pingTimeout = data.pingTimeout;
        this.maxPayload = data.maxPayload;
        this.onOpen();
        // In case open handler closes socket
        if (\"closed\" === this.readyState)
            return;
        this.resetPingTimeout();
    }
    /**
     * Sets and resets ping timeout timer based on server pings.
     *
     * @private
     */
    resetPingTimeout() {
        this.clearTimeoutFn(this.pingTimeoutTimer);
        this.pingTimeoutTimer = this.setTimeoutFn(() => {
            this.onClose(\"ping timeout\");
        }, this.pingInterval + this.pingTimeout);
        if (this.opts.autoUnref) {
            this.pingTimeoutTimer.unref();
        }
    }
    /**
     * Called on `drain` event
     *
     * @private
     */
    onDrain() {
        this.writeBuffer.splice(0, this.prevBufferLen);
        // setting prevBufferLen = 0 is very important
        // for example, when upgrading, upgrade packet is sent over,
        // and a nonzero prevBufferLen could cause problems on `drain`
        this.prevBufferLen = 0;
        if (0 === this.writeBuffer.length) {
            this.emitReserved(\"drain\");
        }
        else {
            this.flush();
        }
    }
    /**
     * Flush write buffers.
     *
     * @private
     */
    flush() {
        if (\"closed\" !== this.readyState &&
            this.transport.writable &&
            !this.upgrading &&
            this.writeBuffer.length) {
            const packets = this.getWritablePackets();
            this.transport.send(packets);
            // keep track of current length of writeBuffer
            // splice writeBuffer and callbackBuffer on `drain`
            this.prevBufferLen = packets.length;
            this.emitReserved(\"flush\");
        }
    }
    /**
     * Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
     * long-polling)
     *
     * @private
     */
    getWritablePackets() {
        const shouldCheckPayloadSize = this.maxPayload &&
            this.transport.name === \"polling\" &&
            this.writeBuffer.length > 1;
        if (!shouldCheckPayloadSize) {
            return this.writeBuffer;
        }
        let payloadSize = 1; // first packet type
        for (let i = 0; i < this.writeBuffer.length; i++) {
            const data = this.writeBuffer[i].data;
            if (data) {
                payloadSize += byteLength(data);
            }
            if (i > 0 && payloadSize > this.maxPayload) {
                return this.writeBuffer.slice(0, i);
            }
            payloadSize += 2; // separator + packet type
        }
        return this.writeBuffer;
    }
    /**
     * Sends a message.
     *
     * @param {String} msg - message.
     * @param {Object} options.
     * @param {Function} callback function.
     * @return {Socket} for chaining.
     */
    write(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    send(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    /**
     * Sends a packet.
     *
     * @param {String} type: packet type.
     * @param {String} data.
     * @param {Object} options.
     * @param {Function} fn - callback function.
     * @private
     */
    sendPacket(type, data, options, fn) {
        if (\"function\" === typeof data) {
            fn = data;
            data = undefined;
        }
        if (\"function\" === typeof options) {
            fn = options;
            options = null;
        }
        if (\"closing\" === this.readyState || \"closed\" === this.readyState) {
            return;
        }
        options = options || {};
        options.compress = false !== options.compress;
        const packet = {
            type: type,
            data: data,
            options: options,
        };
        this.emitReserved(\"packetCreate\", packet);
        this.writeBuffer.push(packet);
        if (fn)
            this.once(\"flush\", fn);
        this.flush();
    }
    /**
     * Closes the connection.
     */
    close() {
        const close = () => {
            this.onClose(\"forced close\");
            this.transport.close();
        };
        const cleanupAndClose = () => {
            this.off(\"upgrade\", cleanupAndClose);
            this.off(\"upgradeError\", cleanupAndClose);
            close();
        };
        const waitForUpgrade = () => {
            // wait for upgrade to finish since we can't send packets while pausing a transport
            this.once(\"upgrade\", cleanupAndClose);
            this.once(\"upgradeError\", cleanupAndClose);
        };
        if (\"opening\" === this.readyState || \"open\" === this.readyState) {
            this.readyState = \"closing\";
            if (this.writeBuffer.length) {
                this.once(\"drain\", () => {
                    if (this.upgrading) {
                        waitForUpgrade();
                    }
                    else {
                        close();
                    }
                });
            }
            else if (this.upgrading) {
                waitForUpgrade();
            }
            else {
                close();
            }
        }
        return this;
    }
    /**
     * Called upon transport error
     *
     * @private
     */
    onError(err) {
        Socket.priorWebsocketSuccess = false;
        this.emitReserved(\"error\", err);
        this.onClose(\"transport error\", err);
    }
    /**
     * Called upon transport close.
     *
     * @private
     */
    onClose(reason, description) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            // clear timers
            this.clearTimeoutFn(this.pingTimeoutTimer);
            // stop event from firing again for transport
            this.transport.removeAllListeners(\"close\");
            // ensure transport won't stay open
            this.transport.close();
            // ignore further transport communication
            this.transport.removeAllListeners();
            if (typeof removeEventListener === \"function\") {
                removeEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
                removeEventListener(\"offline\", this.offlineEventListener, false);
            }
            // set ready state
            this.readyState = \"closed\";
            // clear session id
            this.id = null;
            // emit close event
            this.emitReserved(\"close\", reason, description);
            // clean buffers after, so users can still
            // grab the buffers on `close` event
            this.writeBuffer = [];
            this.prevBufferLen = 0;
        }
    }
    /**
     * Filters upgrades, returning only those matching client transports.
     *
     * @param {Array} upgrades - server upgrades
     * @private
     */
    filterUpgrades(upgrades) {
        const filteredUpgrades = [];
        let i = 0;
        const j = upgrades.length;
        for (; i < j; i++) {
            if (~this.transports.indexOf(upgrades[i]))
                filteredUpgrades.push(upgrades[i]);
        }
        return filteredUpgrades;
    }
}
Socket.protocol = protocol;
","import { Socket } from \"./socket.js\";
export { Socket };
export const protocol = Socket.protocol;
export { Transport } from \"./transport.js\";
export { transports } from \"./transports/index.js\";
export { installTimerFunctions } from \"./util.js\";
export { parse } from \"./contrib/parseuri.js\";
export { nextTick } from \"./transports/websocket-constructor.js\";
","const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const isView = (obj) => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj.buffer instanceof ArrayBuffer;
};
const toString = Object.prototype.toString;
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeFile = typeof File === \"function\" ||
    (typeof File !== \"undefined\" &&
        toString.call(File) === \"[object FileConstructor]\");
/**
 * Returns true if obj is a Buffer, an ArrayBuffer, a Blob or a File.
 *
 * @private
 */
export function isBinary(obj) {
    return ((withNativeArrayBuffer && (obj instanceof ArrayBuffer || isView(obj))) ||
        (withNativeBlob && obj instanceof Blob) ||
        (withNativeFile && obj instanceof File));
}
export function hasBinary(obj, toJSON) {
    if (!obj || typeof obj !== \"object\") {
        return false;
    }
    if (Array.isArray(obj)) {
        for (let i = 0, l = obj.length; i < l; i++) {
            if (hasBinary(obj[i])) {
                return true;
            }
        }
        return false;
    }
    if (isBinary(obj)) {
        return true;
    }
    if (obj.toJSON &&
        typeof obj.toJSON === \"function\" &&
        arguments.length === 1) {
        return hasBinary(obj.toJSON(), true);
    }
    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key) && hasBinary(obj[key])) {
            return true;
        }
    }
    return false;
}
","import { isBinary } from \"./is-binary.js\";
/**
 * Replaces every Buffer | ArrayBuffer | Blob | File in packet with a numbered placeholder.
 *
 * @param {Object} packet - socket.io event packet
 * @return {Object} with deconstructed packet and list of buffers
 * @public
 */
export function deconstructPacket(packet) {
    const buffers = [];
    const packetData = packet.data;
    const pack = packet;
    pack.data = _deconstructPacket(packetData, buffers);
    pack.attachments = buffers.length; // number of binary 'attachments'
    return { packet: pack, buffers: buffers };
}
function _deconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (isBinary(data)) {
        const placeholder = { _placeholder: true, num: buffers.length };
        buffers.push(data);
        return placeholder;
    }
    else if (Array.isArray(data)) {
        const newData = new Array(data.length);
        for (let i = 0; i < data.length; i++) {
            newData[i] = _deconstructPacket(data[i], buffers);
        }
        return newData;
    }
    else if (typeof data === \"object\" && !(data instanceof Date)) {
        const newData = {};
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                newData[key] = _deconstructPacket(data[key], buffers);
            }
        }
        return newData;
    }
    return data;
}
/**
 * Reconstructs a binary packet from its placeholder packet and buffers
 *
 * @param {Object} packet - event packet with placeholders
 * @param {Array} buffers - binary buffers to put in placeholder positions
 * @return {Object} reconstructed packet
 * @public
 */
export function reconstructPacket(packet, buffers) {
    packet.data = _reconstructPacket(packet.data, buffers);
    delete packet.attachments; // no longer useful
    return packet;
}
function _reconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (data && data._placeholder === true) {
        const isIndexValid = typeof data.num === \"number\" &&
            data.num >= 0 &&
            data.num < buffers.length;
        if (isIndexValid) {
            return buffers[data.num]; // appropriate buffer (should be natural order anyway)
        }
        else {
            throw new Error(\"illegal attachments\");
        }
    }
    else if (Array.isArray(data)) {
        for (let i = 0; i < data.length; i++) {
            data[i] = _reconstructPacket(data[i], buffers);
        }
    }
    else if (typeof data === \"object\") {
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                data[key] = _reconstructPacket(data[key], buffers);
            }
        }
    }
    return data;
}
","import { Emitter } from \"@socket.io/component-emitter\";
import { deconstructPacket, reconstructPacket } from \"./binary.js\";
import { isBinary, hasBinary } from \"./is-binary.js\";
/**
 * These strings must not be used as event names, as they have a special meaning.
 */
const RESERVED_EVENTS = [
    \"connect\",
    \"connect_error\",
    \"disconnect\",
    \"disconnecting\",
    \"newListener\",
    \"removeListener\", // used by the Node.js EventEmitter
];
/**
 * Protocol version.
 *
 * @public
 */
export const protocol = 5;
export var PacketType;
(function (PacketType) {
    PacketType[PacketType[\"CONNECT\"] = 0] = \"CONNECT\";
    PacketType[PacketType[\"DISCONNECT\"] = 1] = \"DISCONNECT\";
    PacketType[PacketType[\"EVENT\"] = 2] = \"EVENT\";
    PacketType[PacketType[\"ACK\"] = 3] = \"ACK\";
    PacketType[PacketType[\"CONNECT_ERROR\"] = 4] = \"CONNECT_ERROR\";
    PacketType[PacketType[\"BINARY_EVENT\"] = 5] = \"BINARY_EVENT\";
    PacketType[PacketType[\"BINARY_ACK\"] = 6] = \"BINARY_ACK\";
})(PacketType || (PacketType = {}));
/**
 * A socket.io Encoder instance
 */
export class Encoder {
    /**
     * Encoder constructor
     *
     * @param {function} replacer - custom replacer to pass down to JSON.parse
     */
    constructor(replacer) {
        this.replacer = replacer;
    }
    /**
     * Encode a packet as a single string if non-binary, or as a
     * buffer sequence, depending on packet type.
     *
     * @param {Object} obj - packet object
     */
    encode(obj) {
        if (obj.type === PacketType.EVENT || obj.type === PacketType.ACK) {
            if (hasBinary(obj)) {
                return this.encodeAsBinary({
                    type: obj.type === PacketType.EVENT
                        ? PacketType.BINARY_EVENT
                        : PacketType.BINARY_ACK,
                    nsp: obj.nsp,
                    data: obj.data,
                    id: obj.id,
                });
            }
        }
        return [this.encodeAsString(obj)];
    }
    /**
     * Encode packet as string.
     */
    encodeAsString(obj) {
        // first is type
        let str = \"\" + obj.type;
        // attachments if we have them
        if (obj.type === PacketType.BINARY_EVENT ||
            obj.type === PacketType.BINARY_ACK) {
            str += obj.attachments + \"-\";
        }
        // if we have a namespace other than `/`
        // we append it followed by a comma `,`
        if (obj.nsp && \"/\" !== obj.nsp) {
            str += obj.nsp + \",\";
        }
        // immediately followed by the id
        if (null != obj.id) {
            str += obj.id;
        }
        // json data
        if (null != obj.data) {
            str += JSON.stringify(obj.data, this.replacer);
        }
        return str;
    }
    /**
     * Encode packet as 'buffer sequence' by removing blobs, and
     * deconstructing packet into object with placeholders and
     * a list of buffers.
     */
    encodeAsBinary(obj) {
        const deconstruction = deconstructPacket(obj);
        const pack = this.encodeAsString(deconstruction.packet);
        const buffers = deconstruction.buffers;
        buffers.unshift(pack); // add packet info to beginning of data list
        return buffers; // write all the buffers
    }
}
// see https://stackoverflow.com/questions/8511281/check-if-a-value-is-an-object-in-javascript
function isObject(value) {
    return Object.prototype.toString.call(value) === \"[object Object]\";
}
/**
 * A socket.io Decoder instance
 *
 * @return {Object} decoder
 */
export class Decoder extends Emitter {
    /**
     * Decoder constructor
     *
     * @param {function} reviver - custom reviver to pass down to JSON.stringify
     */
    constructor(reviver) {
        super();
        this.reviver = reviver;
    }
    /**
     * Decodes an encoded packet string into packet JSON.
     *
     * @param {String} obj - encoded packet
     */
    add(obj) {
        let packet;
        if (typeof obj === \"string\") {
            if (this.reconstructor) {
                throw new Error(\"got plaintext data when reconstructing a packet\");
            }
            packet = this.decodeString(obj);
            const isBinaryEvent = packet.type === PacketType.BINARY_EVENT;
            if (isBinaryEvent || packet.type === PacketType.BINARY_ACK) {
                packet.type = isBinaryEvent ? PacketType.EVENT : PacketType.ACK;
                // binary packet's json
                this.reconstructor = new BinaryReconstructor(packet);
                // no attachments, labeled binary but no binary data to follow
                if (packet.attachments === 0) {
                    super.emitReserved(\"decoded\", packet);
                }
            }
            else {
                // non-binary full packet
                super.emitReserved(\"decoded\", packet);
            }
        }
        else if (isBinary(obj) || obj.base64) {
            // raw binary data
            if (!this.reconstructor) {
                throw new Error(\"got binary data when not reconstructing a packet\");
            }
            else {
                packet = this.reconstructor.takeBinaryData(obj);
                if (packet) {
                    // received final buffer
                    this.reconstructor = null;
                    super.emitReserved(\"decoded\", packet);
                }
            }
        }
        else {
            throw new Error(\"Unknown type: \" + obj);
        }
    }
    /**
     * Decode a packet String (JSON data)
     *
     * @param {String} str
     * @return {Object} packet
     */
    decodeString(str) {
        let i = 0;
        // look up type
        const p = {
            type: Number(str.charAt(0)),
        };
        if (PacketType[p.type] === undefined) {
            throw new Error(\"unknown packet type \" + p.type);
        }
        // look up attachments if type binary
        if (p.type === PacketType.BINARY_EVENT ||
            p.type === PacketType.BINARY_ACK) {
            const start = i + 1;
            while (str.charAt(++i) !== \"-\" && i != str.length) { }
            const buf = str.substring(start, i);
            if (buf != Number(buf) || str.charAt(i) !== \"-\") {
                throw new Error(\"Illegal attachments\");
            }
            p.attachments = Number(buf);
        }
        // look up namespace (if any)
        if (\"/\" === str.charAt(i + 1)) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (\",\" === c)
                    break;
                if (i === str.length)
                    break;
            }
            p.nsp = str.substring(start, i);
        }
        else {
            p.nsp = \"/\";
        }
        // look up id
        const next = str.charAt(i + 1);
        if (\"\" !== next && Number(next) == next) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (null == c || Number(c) != c) {
                    --i;
                    break;
                }
                if (i === str.length)
                    break;
            }
            p.id = Number(str.substring(start, i + 1));
        }
        // look up json data
        if (str.charAt(++i)) {
            const payload = this.tryParse(str.substr(i));
            if (Decoder.isPayloadValid(p.type, payload)) {
                p.data = payload;
            }
            else {
                throw new Error(\"invalid payload\");
            }
        }
        return p;
    }
    tryParse(str) {
        try {
            return JSON.parse(str, this.reviver);
        }
        catch (e) {
            return false;
        }
    }
    static isPayloadValid(type, payload) {
        switch (type) {
            case PacketType.CONNECT:
                return isObject(payload);
            case PacketType.DISCONNECT:
                return payload === undefined;
            case PacketType.CONNECT_ERROR:
                return typeof payload === \"string\" || isObject(payload);
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                return (Array.isArray(payload) &&
                    (typeof payload[0] === \"number\" ||
                        (typeof payload[0] === \"string\" &&
                            RESERVED_EVENTS.indexOf(payload[0]) === -1)));
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                return Array.isArray(payload);
        }
    }
    /**
     * Deallocates a parser's resources
     */
    destroy() {
        if (this.reconstructor) {
            this.reconstructor.finishedReconstruction();
            this.reconstructor = null;
        }
    }
}
/**
 * A manager of a binary event's 'buffer sequence'. Should
 * be constructed whenever a packet of type BINARY_EVENT is
 * decoded.
 *
 * @param {Object} packet
 * @return {BinaryReconstructor} initialized reconstructor
 */
class BinaryReconstructor {
    constructor(packet) {
        this.packet = packet;
        this.buffers = [];
        this.reconPack = packet;
    }
    /**
     * Method to be called when binary data received from connection
     * after a BINARY_EVENT packet.
     *
     * @param {Buffer | ArrayBuffer} binData - the raw binary data received
     * @return {null | Object} returns null if more binary data is expected or
     *   a reconstructed packet object if all buffers have been received.
     */
    takeBinaryData(binData) {
        this.buffers.push(binData);
        if (this.buffers.length === this.reconPack.attachments) {
            // done with buffer list
            const packet = reconstructPacket(this.reconPack, this.buffers);
            this.finishedReconstruction();
            return packet;
        }
        return null;
    }
    /**
     * Cleans up binary packet reconstruction variables.
     */
    finishedReconstruction() {
        this.reconPack = null;
        this.buffers = [];
    }
}
","export function on(obj, ev, fn) {
    obj.on(ev, fn);
    return function subDestroy() {
        obj.off(ev, fn);
    };
}
","import { PacketType } from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
/**
 * Internal events.
 * These events can't be emitted by the user.
 */
const RESERVED_EVENTS = Object.freeze({
    connect: 1,
    connect_error: 1,
    disconnect: 1,
    disconnecting: 1,
    // EventEmitter reserved events: https://nodejs.org/api/events.html#events_event_newlistener
    newListener: 1,
    removeListener: 1,
});
/**
 * A Socket is the fundamental class for interacting with the server.
 *
 * A Socket belongs to a certain Namespace (by default /) and uses an underlying {@link Manager} to communicate.
 *
 * @example
 * const socket = io();
 *
 * socket.on(\"connect\", () => {
 *   console.log(\"connected\");
 * });
 *
 * // send an event to the server
 * socket.emit(\"foo\", \"bar\");
 *
 * socket.on(\"foobar\", () => {
 *   // an event was received from the server
 * });
 *
 * // upon disconnection
 * socket.on(\"disconnect\", (reason) => {
 *   console.log(`disconnected due to ${reason}`);
 * });
 */
export class Socket extends Emitter {
    /**
     * `Socket` constructor.
     */
    constructor(io, nsp, opts) {
        super();
        /**
         * Whether the socket is currently connected to the server.
         *
         * @example
         * const socket = io();
         *
         * socket.on(\"connect\", () => {
         *   console.log(socket.connected); // true
         * });
         *
         * socket.on(\"disconnect\", () => {
         *   console.log(socket.connected); // false
         * });
         */
        this.connected = false;
        /**
         * Whether the connection state was recovered after a temporary disconnection. In that case, any missed packets will
         * be transmitted by the server.
         */
        this.recovered = false;
        /**
         * Buffer for packets received before the CONNECT packet
         */
        this.receiveBuffer = [];
        /**
         * Buffer for packets that will be sent once the socket is connected
         */
        this.sendBuffer = [];
        /**
         * The queue of packets to be sent with retry in case of failure.
         *
         * Packets are sent one by one, each waiting for the server acknowledgement, in order to guarantee the delivery order.
         * @private
         */
        this._queue = [];
        /**
         * A sequence to generate the ID of the {@link QueuedPacket}.
         * @private
         */
        this._queueSeq = 0;
        this.ids = 0;
        this.acks = {};
        this.flags = {};
        this.io = io;
        this.nsp = nsp;
        if (opts && opts.auth) {
            this.auth = opts.auth;
        }
        this._opts = Object.assign({}, opts);
        if (this.io._autoConnect)
            this.open();
    }
    /**
     * Whether the socket is currently disconnected
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"connect\", () => {
     *   console.log(socket.disconnected); // false
     * });
     *
     * socket.on(\"disconnect\", () => {
     *   console.log(socket.disconnected); // true
     * });
     */
    get disconnected() {
        return !this.connected;
    }
    /**
     * Subscribe to open, close and packet events
     *
     * @private
     */
    subEvents() {
        if (this.subs)
            return;
        const io = this.io;
        this.subs = [
            on(io, \"open\", this.onopen.bind(this)),
            on(io, \"packet\", this.onpacket.bind(this)),
            on(io, \"error\", this.onerror.bind(this)),
            on(io, \"close\", this.onclose.bind(this)),
        ];
    }
    /**
     * Whether the Socket will try to reconnect when its Manager connects or reconnects.
     *
     * @example
     * const socket = io();
     *
     * console.log(socket.active); // true
     *
     * socket.on(\"disconnect\", (reason) => {
     *   if (reason === \"io server disconnect\") {
     *     // the disconnection was initiated by the server, you need to manually reconnect
     *     console.log(socket.active); // false
     *   }
     *   // else the socket will automatically try to reconnect
     *   console.log(socket.active); // true
     * });
     */
    get active() {
        return !!this.subs;
    }
    /**
     * \"Opens\" the socket.
     *
     * @example
     * const socket = io({
     *   autoConnect: false
     * });
     *
     * socket.connect();
     */
    connect() {
        if (this.connected)
            return this;
        this.subEvents();
        if (!this.io[\"_reconnecting\"])
            this.io.open(); // ensure open
        if (\"open\" === this.io._readyState)
            this.onopen();
        return this;
    }
    /**
     * Alias for {@link connect()}.
     */
    open() {
        return this.connect();
    }
    /**
     * Sends a `message` event.
     *
     * This method mimics the WebSocket.send() method.
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/send
     *
     * @example
     * socket.send(\"hello\");
     *
     * // this is equivalent to
     * socket.emit(\"message\", \"hello\");
     *
     * @return self
     */
    send(...args) {
        args.unshift(\"message\");
        this.emit.apply(this, args);
        return this;
    }
    /**
     * Override `emit`.
     * If the event is in `events`, it's emitted normally.
     *
     * @example
     * socket.emit(\"hello\", \"world\");
     *
     * // all serializable datastructures are supported (no need to call JSON.stringify)
     * socket.emit(\"hello\", 1, \"2\", { 3: [\"4\"], 5: Uint8Array.from([6]) });
     *
     * // with an acknowledgement from the server
     * socket.emit(\"hello\", \"world\", (val) => {
     *   // ...
     * });
     *
     * @return self
     */
    emit(ev, ...args) {
        if (RESERVED_EVENTS.hasOwnProperty(ev)) {
            throw new Error('\"' + ev.toString() + '\" is a reserved event name');
        }
        args.unshift(ev);
        if (this._opts.retries && !this.flags.fromQueue && !this.flags.volatile) {
            this._addToQueue(args);
            return this;
        }
        const packet = {
            type: PacketType.EVENT,
            data: args,
        };
        packet.options = {};
        packet.options.compress = this.flags.compress !== false;
        // event ack callback
        if (\"function\" === typeof args[args.length - 1]) {
            const id = this.ids++;
            const ack = args.pop();
            this._registerAckCallback(id, ack);
            packet.id = id;
        }
        const isTransportWritable = this.io.engine &&
            this.io.engine.transport &&
            this.io.engine.transport.writable;
        const discardPacket = this.flags.volatile && (!isTransportWritable || !this.connected);
        if (discardPacket) {
        }
        else if (this.connected) {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        }
        else {
            this.sendBuffer.push(packet);
        }
        this.flags = {};
        return this;
    }
    /**
     * @private
     */
    _registerAckCallback(id, ack) {
        var _a;
        const timeout = (_a = this.flags.timeout) !== null && _a !== void 0 ? _a : this._opts.ackTimeout;
        if (timeout === undefined) {
            this.acks[id] = ack;
            return;
        }
        // @ts-ignore
        const timer = this.io.setTimeoutFn(() => {
            delete this.acks[id];
            for (let i = 0; i < this.sendBuffer.length; i++) {
                if (this.sendBuffer[i].id === id) {
                    this.sendBuffer.splice(i, 1);
                }
            }
            ack.call(this, new Error(\"operation has timed out\"));
        }, timeout);
        this.acks[id] = (...args) => {
            // @ts-ignore
            this.io.clearTimeoutFn(timer);
            ack.apply(this, [null, ...args]);
        };
    }
    /**
     * Emits an event and waits for an acknowledgement
     *
     * @example
     * // without timeout
     * const response = await socket.emitWithAck(\"hello\", \"world\");
     *
     * // with a specific timeout
     * try {
     *   const response = await socket.timeout(1000).emitWithAck(\"hello\", \"world\");
     * } catch (err) {
     *   // the server did not acknowledge the event in the given delay
     * }
     *
     * @return a Promise that will be fulfilled when the server acknowledges the event
     */
    emitWithAck(ev, ...args) {
        // the timeout flag is optional
        const withErr = this.flags.timeout !== undefined || this._opts.ackTimeout !== undefined;
        return new Promise((resolve, reject) => {
            args.push((arg1, arg2) => {
                if (withErr) {
                    return arg1 ? reject(arg1) : resolve(arg2);
                }
                else {
                    return resolve(arg1);
                }
            });
            this.emit(ev, ...args);
        });
    }
    /**
     * Add the packet to the queue.
     * @param args
     * @private
     */
    _addToQueue(args) {
        let ack;
        if (typeof args[args.length - 1] === \"function\") {
            ack = args.pop();
        }
        const packet = {
            id: this._queueSeq++,
            tryCount: 0,
            pending: false,
            args,
            flags: Object.assign({ fromQueue: true }, this.flags),
        };
        args.push((err, ...responseArgs) => {
            if (packet !== this._queue[0]) {
                // the packet has already been acknowledged
                return;
            }
            const hasError = err !== null;
            if (hasError) {
                if (packet.tryCount > this._opts.retries) {
                    this._queue.shift();
                    if (ack) {
                        ack(err);
                    }
                }
            }
            else {
                this._queue.shift();
                if (ack) {
                    ack(null, ...responseArgs);
                }
            }
            packet.pending = false;
            return this._drainQueue();
        });
        this._queue.push(packet);
        this._drainQueue();
    }
    /**
     * Send the first packet of the queue, and wait for an acknowledgement from the server.
     * @param force - whether to resend a packet that has not been acknowledged yet
     *
     * @private
     */
    _drainQueue(force = false) {
        if (!this.connected || this._queue.length === 0) {
            return;
        }
        const packet = this._queue[0];
        if (packet.pending && !force) {
            return;
        }
        packet.pending = true;
        packet.tryCount++;
        this.flags = packet.flags;
        this.emit.apply(this, packet.args);
    }
    /**
     * Sends a packet.
     *
     * @param packet
     * @private
     */
    packet(packet) {
        packet.nsp = this.nsp;
        this.io._packet(packet);
    }
    /**
     * Called upon engine `open`.
     *
     * @private
     */
    onopen() {
        if (typeof this.auth == \"function\") {
            this.auth((data) => {
                this._sendConnectPacket(data);
            });
        }
        else {
            this._sendConnectPacket(this.auth);
        }
    }
    /**
     * Sends a CONNECT packet to initiate the Socket.IO session.
     *
     * @param data
     * @private
     */
    _sendConnectPacket(data) {
        this.packet({
            type: PacketType.CONNECT,
            data: this._pid
                ? Object.assign({ pid: this._pid, offset: this._lastOffset }, data)
                : data,
        });
    }
    /**
     * Called upon engine or manager `error`.
     *
     * @param err
     * @private
     */
    onerror(err) {
        if (!this.connected) {
            this.emitReserved(\"connect_error\", err);
        }
    }
    /**
     * Called upon engine `close`.
     *
     * @param reason
     * @param description
     * @private
     */
    onclose(reason, description) {
        this.connected = false;
        delete this.id;
        this.emitReserved(\"disconnect\", reason, description);
    }
    /**
     * Called with socket packet.
     *
     * @param packet
     * @private
     */
    onpacket(packet) {
        const sameNamespace = packet.nsp === this.nsp;
        if (!sameNamespace)
            return;
        switch (packet.type) {
            case PacketType.CONNECT:
                if (packet.data && packet.data.sid) {
                    this.onconnect(packet.data.sid, packet.data.pid);
                }
                else {
                    this.emitReserved(\"connect_error\", new Error(\"It seems you are trying to reach a Socket.IO server in v2.x with a v3.x client, but they are not compatible (more information here: https://socket.io/docs/v3/migrating-from-2-x-to-3-0/)\"));
                }
                break;
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                this.onevent(packet);
                break;
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                this.onack(packet);
                break;
            case PacketType.DISCONNECT:
                this.ondisconnect();
                break;
            case PacketType.CONNECT_ERROR:
                this.destroy();
                const err = new Error(packet.data.message);
                // @ts-ignore
                err.data = packet.data.data;
                this.emitReserved(\"connect_error\", err);
                break;
        }
    }
    /**
     * Called upon a server event.
     *
     * @param packet
     * @private
     */
    onevent(packet) {
        const args = packet.data || [];
        if (null != packet.id) {
            args.push(this.ack(packet.id));
        }
        if (this.connected) {
            this.emitEvent(args);
        }
        else {
            this.receiveBuffer.push(Object.freeze(args));
        }
    }
    emitEvent(args) {
        if (this._anyListeners && this._anyListeners.length) {
            const listeners = this._anyListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, args);
            }
        }
        super.emit.apply(this, args);
        if (this._pid && args.length && typeof args[args.length - 1] === \"string\") {
            this._lastOffset = args[args.length - 1];
        }
    }
    /**
     * Produces an ack callback to emit with an event.
     *
     * @private
     */
    ack(id) {
        const self = this;
        let sent = false;
        return function (...args) {
            // prevent double callbacks
            if (sent)
                return;
            sent = true;
            self.packet({
                type: PacketType.ACK,
                id: id,
                data: args,
            });
        };
    }
    /**
     * Called upon a server acknowlegement.
     *
     * @param packet
     * @private
     */
    onack(packet) {
        const ack = this.acks[packet.id];
        if (\"function\" === typeof ack) {
            ack.apply(this, packet.data);
            delete this.acks[packet.id];
        }
        else {
        }
    }
    /**
     * Called upon server connect.
     *
     * @private
     */
    onconnect(id, pid) {
        this.id = id;
        this.recovered = pid && this._pid === pid;
        this._pid = pid; // defined only if connection state recovery is enabled
        this.connected = true;
        this.emitBuffered();
        this.emitReserved(\"connect\");
        this._drainQueue(true);
    }
    /**
     * Emit buffered events (received and emitted).
     *
     * @private
     */
    emitBuffered() {
        this.receiveBuffer.forEach((args) => this.emitEvent(args));
        this.receiveBuffer = [];
        this.sendBuffer.forEach((packet) => {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        });
        this.sendBuffer = [];
    }
    /**
     * Called upon server disconnect.
     *
     * @private
     */
    ondisconnect() {
        this.destroy();
        this.onclose(\"io server disconnect\");
    }
    /**
     * Called upon forced client/server side disconnections,
     * this method ensures the manager stops tracking us and
     * that reconnections don't get triggered for this.
     *
     * @private
     */
    destroy() {
        if (this.subs) {
            // clean subscriptions to avoid reconnections
            this.subs.forEach((subDestroy) => subDestroy());
            this.subs = undefined;
        }
        this.io[\"_destroy\"](this);
    }
    /**
     * Disconnects the socket manually. In that case, the socket will not try to reconnect.
     *
     * If this is the last active Socket instance of the {@link Manager}, the low-level connection will be closed.
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"disconnect\", (reason) => {
     *   // console.log(reason); prints \"io client disconnect\"
     * });
     *
     * socket.disconnect();
     *
     * @return self
     */
    disconnect() {
        if (this.connected) {
            this.packet({ type: PacketType.DISCONNECT });
        }
        // remove socket from pool
        this.destroy();
        if (this.connected) {
            // fire events
            this.onclose(\"io client disconnect\");
        }
        return this;
    }
    /**
     * Alias for {@link disconnect()}.
     *
     * @return self
     */
    close() {
        return this.disconnect();
    }
    /**
     * Sets the compress flag.
     *
     * @example
     * socket.compress(false).emit(\"hello\");
     *
     * @param compress - if `true`, compresses the sending data
     * @return self
     */
    compress(compress) {
        this.flags.compress = compress;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the event message will be dropped when this socket is not
     * ready to send messages.
     *
     * @example
     * socket.volatile.emit(\"hello\"); // the server may or may not receive it
     *
     * @returns self
     */
    get volatile() {
        this.flags.volatile = true;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the callback will be called with an error when the
     * given number of milliseconds have elapsed without an acknowledgement from the server:
     *
     * @example
     * socket.timeout(5000).emit(\"my-event\", (err) => {
     *   if (err) {
     *     // the server did not acknowledge the event in the given delay
     *   }
     * });
     *
     * @returns self
     */
    timeout(timeout) {
        this.flags.timeout = timeout;
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * @example
     * socket.onAny((event, ...args) => {
     *   console.log(`got ${event}`);
     * });
     *
     * @param listener
     */
    onAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * @example
     * socket.prependAny((event, ...args) => {
     *   console.log(`got event ${event}`);
     * });
     *
     * @param listener
     */
    prependAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`got event ${event}`);
     * }
     *
     * socket.onAny(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAny(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAny();
     *
     * @param listener
     */
    offAny(listener) {
        if (!this._anyListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAny() {
        return this._anyListeners || [];
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.onAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    onAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.prependAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    prependAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`sent event ${event}`);
     * }
     *
     * socket.onAnyOutgoing(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAnyOutgoing(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAnyOutgoing();
     *
     * @param [listener] - the catch-all listener (optional)
     */
    offAnyOutgoing(listener) {
        if (!this._anyOutgoingListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyOutgoingListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyOutgoingListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAnyOutgoing() {
        return this._anyOutgoingListeners || [];
    }
    /**
     * Notify the listeners for each packet sent
     *
     * @param packet
     *
     * @private
     */
    notifyOutgoingListeners(packet) {
        if (this._anyOutgoingListeners && this._anyOutgoingListeners.length) {
            const listeners = this._anyOutgoingListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, packet.data);
            }
        }
    }
}
","/**
 * Initialize backoff timer with `opts`.
 *
 * - `min` initial timeout in milliseconds [100]
 * - `max` max timeout [10000]
 * - `jitter` [0]
 * - `factor` [2]
 *
 * @param {Object} opts
 * @api public
 */
export function Backoff(opts) {
    opts = opts || {};
    this.ms = opts.min || 100;
    this.max = opts.max || 10000;
    this.factor = opts.factor || 2;
    this.jitter = opts.jitter > 0 && opts.jitter <= 1 ? opts.jitter : 0;
    this.attempts = 0;
}
/**
 * Return the backoff duration.
 *
 * @return {Number}
 * @api public
 */
Backoff.prototype.duration = function () {
    var ms = this.ms * Math.pow(this.factor, this.attempts++);
    if (this.jitter) {
        var rand = Math.random();
        var deviation = Math.floor(rand * this.jitter * ms);
        ms = (Math.floor(rand * 10) & 1) == 0 ? ms - deviation : ms + deviation;
    }
    return Math.min(ms, this.max) | 0;
};
/**
 * Reset the number of attempts.
 *
 * @api public
 */
Backoff.prototype.reset = function () {
    this.attempts = 0;
};
/**
 * Set the minimum duration
 *
 * @api public
 */
Backoff.prototype.setMin = function (min) {
    this.ms = min;
};
/**
 * Set the maximum duration
 *
 * @api public
 */
Backoff.prototype.setMax = function (max) {
    this.max = max;
};
/**
 * Set the jitter
 *
 * @api public
 */
Backoff.prototype.setJitter = function (jitter) {
    this.jitter = jitter;
};
","import { Socket as Engine, installTimerFunctions, nextTick, } from \"engine.io-client\";
import { Socket } from \"./socket.js\";
import * as parser from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Backoff } from \"./contrib/backo2.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
export class Manager extends Emitter {
    constructor(uri, opts) {
        var _a;
        super();
        this.nsps = {};
        this.subs = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = undefined;
        }
        opts = opts || {};
        opts.path = opts.path || \"/socket.io\";
        this.opts = opts;
        installTimerFunctions(this, opts);
        this.reconnection(opts.reconnection !== false);
        this.reconnectionAttempts(opts.reconnectionAttempts || Infinity);
        this.reconnectionDelay(opts.reconnectionDelay || 1000);
        this.reconnectionDelayMax(opts.reconnectionDelayMax || 5000);
        this.randomizationFactor((_a = opts.randomizationFactor) !== null && _a !== void 0 ? _a : 0.5);
        this.backoff = new Backoff({
            min: this.reconnectionDelay(),
            max: this.reconnectionDelayMax(),
            jitter: this.randomizationFactor(),
        });
        this.timeout(null == opts.timeout ? 20000 : opts.timeout);
        this._readyState = \"closed\";
        this.uri = uri;
        const _parser = opts.parser || parser;
        this.encoder = new _parser.Encoder();
        this.decoder = new _parser.Decoder();
        this._autoConnect = opts.autoConnect !== false;
        if (this._autoConnect)
            this.open();
    }
    reconnection(v) {
        if (!arguments.length)
            return this._reconnection;
        this._reconnection = !!v;
        return this;
    }
    reconnectionAttempts(v) {
        if (v === undefined)
            return this._reconnectionAttempts;
        this._reconnectionAttempts = v;
        return this;
    }
    reconnectionDelay(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelay;
        this._reconnectionDelay = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMin(v);
        return this;
    }
    randomizationFactor(v) {
        var _a;
        if (v === undefined)
            return this._randomizationFactor;
        this._randomizationFactor = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setJitter(v);
        return this;
    }
    reconnectionDelayMax(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelayMax;
        this._reconnectionDelayMax = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMax(v);
        return this;
    }
    timeout(v) {
        if (!arguments.length)
            return this._timeout;
        this._timeout = v;
        return this;
    }
    /**
     * Starts trying to reconnect if reconnection is enabled and we have not
     * started reconnecting yet
     *
     * @private
     */
    maybeReconnectOnOpen() {
        // Only try to reconnect if it's the first time we're connecting
        if (!this._reconnecting &&
            this._reconnection &&
            this.backoff.attempts === 0) {
            // keeps reconnection from firing twice for the same reconnection loop
            this.reconnect();
        }
    }
    /**
     * Sets the current transport `socket`.
     *
     * @param {Function} fn - optional, callback
     * @return self
     * @public
     */
    open(fn) {
        if (~this._readyState.indexOf(\"open\"))
            return this;
        this.engine = new Engine(this.uri, this.opts);
        const socket = this.engine;
        const self = this;
        this._readyState = \"opening\";
        this.skipReconnect = false;
        // emit `open`
        const openSubDestroy = on(socket, \"open\", function () {
            self.onopen();
            fn && fn();
        });
        // emit `error`
        const errorSub = on(socket, \"error\", (err) => {
            self.cleanup();
            self._readyState = \"closed\";
            this.emitReserved(\"error\", err);
            if (fn) {
                fn(err);
            }
            else {
                // Only do this if there is no fn to handle the error
                self.maybeReconnectOnOpen();
            }
        });
        if (false !== this._timeout) {
            const timeout = this._timeout;
            if (timeout === 0) {
                openSubDestroy(); // prevents a race condition with the 'open' event
            }
            // set timer
            const timer = this.setTimeoutFn(() => {
                openSubDestroy();
                socket.close();
                // @ts-ignore
                socket.emit(\"error\", new Error(\"timeout\"));
            }, timeout);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
        this.subs.push(openSubDestroy);
        this.subs.push(errorSub);
        return this;
    }
    /**
     * Alias for open()
     *
     * @return self
     * @public
     */
    connect(fn) {
        return this.open(fn);
    }
    /**
     * Called upon transport open.
     *
     * @private
     */
    onopen() {
        // clear old subs
        this.cleanup();
        // mark as open
        this._readyState = \"open\";
        this.emitReserved(\"open\");
        // add new subs
        const socket = this.engine;
        this.subs.push(on(socket, \"ping\", this.onping.bind(this)), on(socket, \"data\", this.ondata.bind(this)), on(socket, \"error\", this.onerror.bind(this)), on(socket, \"close\", this.onclose.bind(this)), on(this.decoder, \"decoded\", this.ondecoded.bind(this)));
    }
    /**
     * Called upon a ping.
     *
     * @private
     */
    onping() {
        this.emitReserved(\"ping\");
    }
    /**
     * Called with data.
     *
     * @private
     */
    ondata(data) {
        try {
            this.decoder.add(data);
        }
        catch (e) {
            this.onclose(\"parse error\", e);
        }
    }
    /**
     * Called when parser fully decodes a packet.
     *
     * @private
     */
    ondecoded(packet) {
        // the nextTick call prevents an exception in a user-provided event listener from triggering a disconnection due to a \"parse error\"
        nextTick(() => {
            this.emitReserved(\"packet\", packet);
        }, this.setTimeoutFn);
    }
    /**
     * Called upon socket error.
     *
     * @private
     */
    onerror(err) {
        this.emitReserved(\"error\", err);
    }
    /**
     * Creates a new socket for the given `nsp`.
     *
     * @return {Socket}
     * @public
     */
    socket(nsp, opts) {
        let socket = this.nsps[nsp];
        if (!socket) {
            socket = new Socket(this, nsp, opts);
            this.nsps[nsp] = socket;
        }
        else if (this._autoConnect && !socket.active) {
            socket.connect();
        }
        return socket;
    }
    /**
     * Called upon a socket close.
     *
     * @param socket
     * @private
     */
    _destroy(socket) {
        const nsps = Object.keys(this.nsps);
        for (const nsp of nsps) {
            const socket = this.nsps[nsp];
            if (socket.active) {
                return;
            }
        }
        this._close();
    }
    /**
     * Writes a packet.
     *
     * @param packet
     * @private
     */
    _packet(packet) {
        const encodedPackets = this.encoder.encode(packet);
        for (let i = 0; i < encodedPackets.length; i++) {
            this.engine.write(encodedPackets[i], packet.options);
        }
    }
    /**
     * Clean up transport subscriptions and packet buffer.
     *
     * @private
     */
    cleanup() {
        this.subs.forEach((subDestroy) => subDestroy());
        this.subs.length = 0;
        this.decoder.destroy();
    }
    /**
     * Close the current socket.
     *
     * @private
     */
    _close() {
        this.skipReconnect = true;
        this._reconnecting = false;
        this.onclose(\"forced close\");
        if (this.engine)
            this.engine.close();
    }
    /**
     * Alias for close()
     *
     * @private
     */
    disconnect() {
        return this._close();
    }
    /**
     * Called upon engine close.
     *
     * @private
     */
    onclose(reason, description) {
        this.cleanup();
        this.backoff.reset();
        this._readyState = \"closed\";
        this.emitReserved(\"close\", reason, description);
        if (this._reconnection && !this.skipReconnect) {
            this.reconnect();
        }
    }
    /**
     * Attempt a reconnection.
     *
     * @private
     */
    reconnect() {
        if (this._reconnecting || this.skipReconnect)
            return this;
        const self = this;
        if (this.backoff.attempts >= this._reconnectionAttempts) {
            this.backoff.reset();
            this.emitReserved(\"reconnect_failed\");
            this._reconnecting = false;
        }
        else {
            const delay = this.backoff.duration();
            this._reconnecting = true;
            const timer = this.setTimeoutFn(() => {
                if (self.skipReconnect)
                    return;
                this.emitReserved(\"reconnect_attempt\", self.backoff.attempts);
                // check again for the case socket closed in above events
                if (self.skipReconnect)
                    return;
                self.open((err) => {
                    if (err) {
                        self._reconnecting = false;
                        self.reconnect();
                        this.emitReserved(\"reconnect_error\", err);
                    }
                    else {
                        self.onreconnect();
                    }
                });
            }, delay);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
    }
    /**
     * Called upon successful reconnect.
     *
     * @private
     */
    onreconnect() {
        const attempt = this.backoff.attempts;
        this._reconnecting = false;
        this.backoff.reset();
        this.emitReserved(\"reconnect\", attempt);
    }
}
","import { url } from \"./url.js\";
import { Manager } from \"./manager.js\";
import { Socket } from \"./socket.js\";
/**
 * Managers cache.
 */
const cache = {};
function lookup(uri, opts) {
    if (typeof uri === \"object\") {
        opts = uri;
        uri = undefined;
    }
    opts = opts || {};
    const parsed = url(uri, opts.path || \"/socket.io\");
    const source = parsed.source;
    const id = parsed.id;
    const path = parsed.path;
    const sameNamespace = cache[id] && path in cache[id][\"nsps\"];
    const newConnection = opts.forceNew ||
        opts[\"force new connection\"] ||
        false === opts.multiplex ||
        sameNamespace;
    let io;
    if (newConnection) {
        io = new Manager(source, opts);
    }
    else {
        if (!cache[id]) {
            cache[id] = new Manager(source, opts);
        }
        io = cache[id];
    }
    if (parsed.query && !opts.query) {
        opts.query = parsed.queryKey;
    }
    return io.socket(parsed.path, opts);
}
// so that \"lookup\" can be used both as a function (e.g. `io(...)`) and as a
// namespace (e.g. `io.connect(...)`), for backward compatibility
Object.assign(lookup, {
    Manager,
    Socket,
    io: lookup,
    connect: lookup,
});
/**
 * Protocol version.
 *
 * @public
 */
export { protocol } from \"socket.io-parser\";
/**
 * Expose constructors for standalone build.
 *
 * @public
 */
export { Manager, Socket, lookup as io, lookup as connect, lookup as default, };
","import { parse } from \"engine.io-client\";
/**
 * URL parser.
 *
 * @param uri - url
 * @param path - the request path of the connection
 * @param loc - An object meant to mimic window.location.
 *        Defaults to window.location.
 * @public
 */
export function url(uri, path = \"\", loc) {
    let obj = uri;
    // default to window.location
    loc = loc || (typeof location !== \"undefined\" && location);
    if (null == uri)
        uri = loc.protocol + \"//\" + loc.host;
    // relative path support
    if (typeof uri === \"string\") {
        if (\"/\" === uri.charAt(0)) {
            if (\"/\" === uri.charAt(1)) {
                uri = loc.protocol + uri;
            }
            else {
                uri = loc.host + uri;
            }
        }
        if (!/^(https?|wss?):\\/\\//.test(uri)) {
            if (\"undefined\" !== typeof loc) {
                uri = loc.protocol + \"//\" + uri;
            }
            else {
                uri = \"https://\" + uri;
            }
        }
        // parse
        obj = parse(uri);
    }
    // make sure we treat `localhost:80` and `localhost` equally
    if (!obj.port) {
        if (/^(http|ws)$/.test(obj.protocol)) {
            obj.port = \"80\";
        }
        else if (/^(http|ws)s$/.test(obj.protocol)) {
            obj.port = \"443\";
        }
    }
    obj.path = obj.path || \"/\";
    const ipv6 = obj.host.indexOf(\":\") !== -1;
    const host = ipv6 ? \"[\" + obj.host + \"]\" : obj.host;
    // define unique id
    obj.id = obj.protocol + \"://\" + host + \":\" + obj.port + path;
    // define href
    obj.href =
        obj.protocol +
            \"://\" +
            host +
            (loc && loc.port === obj.port ? \"\" : \":\" + obj.port);
    return obj;
}
"],"names":["PACKET_TYPES","Object","create","PACKET_TYPES_REVERSE","keys","forEach","key","ERROR_PACKET","type","data","withNativeBlob","Blob","prototype","toString","call","withNativeArrayBuffer","ArrayBuffer","encodePacket","supportsBinary","callback","obj","encodeBlobAsBase64","isView","buffer","fileReader","FileReader","onload","content","result","split","readAsDataURL","chars","lookup","Uint8Array","i","length","charCodeAt","decodePacket","encodedPacket","binaryType","mapBinary","charAt","decodeBase64Packet","substring","decoded","base64","encoded1","encoded2","encoded3","encoded4","bufferLength","len","p","arraybuffer","bytes","decode","SEPARATOR","String","fromCharCode","Emitter","mixin","on","addEventListener","event","fn","this","_callbacks","push","once","off","apply","arguments","removeListener","removeAllListeners","removeEventListener","cb","callbacks","splice","emit","args","Array","slice","emitReserved","listeners","hasListeners","globalThisShim","self","window","Function","pick","_len","attr","_key","reduce","acc","k","hasOwnProperty","NATIVE_SET_TIMEOUT","globalThis","setTimeout","NATIVE_CLEAR_TIMEOUT","clearTimeout","installTimerFunctions","opts","useNativeTimers","setTimeoutFn","bind","clearTimeoutFn","prev","TransportError","reason","description","context","_this","_classCallCheck","_super","Error","Transport","_Emitter","_inherits","_super2","_createSuper","_this2","writable","_assertThisInitialized","query","socket","_createClass","value","_get","_getPrototypeOf","readyState","doOpen","doClose","onClose","packets","write","packet","onPacket","details","onPause","alphabet","map","seed","encode","num","encoded","Math","floor","yeast","now","Date","str","encodeURIComponent","qs","qry","pairs","l","pair","decodeURIComponent","XMLHttpRequest","err","hasCORS","XHR","xdomain","e","concat","join","empty","hasXHR2","responseType","Polling","_Transport","polling","location","isSSL","protocol","port","xd","hostname","xs","secure","forceBase64","get","poll","pause","total","doPoll","_this3","encodedPayload","encodedPackets","decodedPacket","decodePayload","onOpen","_this4","close","_this5","count","encodePayload","doWrite","schema","timestampRequests","timestampParam","sid","b64","Number","encodedQuery","indexOf","path","_extends","Request","uri","_this6","req","request","method","xhrStatus","onError","_this7","onData","pollXhr","_this8","async","undefined","_this9","xscheme","xhr","open","extraHeaders","setDisableHeaderCheck","setRequestHeader","withCredentials","requestTimeout","timeout","onreadystatechange","status","onLoad","send","document","index","requestsCount","requests","cleanup","fromError","abort","responseText","attachEvent","unloadHandler","nextTick","Promise","resolve","then","WebSocket","MozWebSocket","isReactNative","navigator","product","toLowerCase","WS","check","protocols","headers","ws","addEventListeners","onopen","autoUnref","_socket","unref","onclose","closeEvent","onmessage","ev","onerror","_loop","lastPacket","transports","websocket","re","parts","parse","src","b","replace","m","exec","source","host","authority","ipv6uri","pathNames","regx","names","queryKey","$0","$1","$2","Socket","writeBuffer","prevBufferLen","agent","upgrade","rememberUpgrade","addTrailingSlash","rejectUnauthorized","perMessageDeflate","threshold","transportOptions","closeOnBeforeunload","id","upgrades","pingInterval","pingTimeout","pingTimeoutTimer","beforeunloadEventListener","transport","offlineEventListener","name","EIO","priorWebsocketSuccess","createTransport","shift","setTransport","onDrain","failed","onTransportOpen","msg","upgrading","flush","freezeTransport","error","onTransportClose","onupgrade","to","probe","onHandshake","JSON","resetPingTimeout","sendPacket","code","filterUpgrades","maxPayload","getWritablePackets","payloadSize","c","utf8Length","ceil","byteLength","size","options","compress","cleanupAndClose","waitForUpgrade","filteredUpgrades","j","Socket$1","withNativeFile","File","isBinary","hasBinary","toJSON","_typeof","isArray","deconstructPacket","buffers","packetData","pack","_deconstructPacket","attachments","placeholder","_placeholder","newData","reconstructPacket","_reconstructPacket","PacketType","RESERVED_EVENTS","Encoder","replacer","EVENT","ACK","encodeAsString","encodeAsBinary","BINARY_EVENT","BINARY_ACK","nsp","stringify","deconstruction","unshift","isObject","Decoder","reviver","reconstructor","isBinaryEvent","decodeString","BinaryReconstructor","takeBinaryData","start","buf","next","payload","tryParse","substr","isPayloadValid","finishedReconstruction","CONNECT","DISCONNECT","CONNECT_ERROR","reconPack","binData","freeze","connect","connect_error","disconnect","disconnecting","newListener","io","connected","recovered","receiveBuffer","sendBuffer","_queue","_queueSeq","ids","acks","flags","auth","_opts","_autoConnect","subs","onpacket","subEvents","_readyState","_len2","_key2","retries","fromQueue","_addToQueue","ack","pop","_registerAckCallback","isTransportWritable","engine","discardPacket","notifyOutgoingListeners","_a","ackTimeout","timer","_len3","_key3","_len4","_key4","withErr","reject","arg1","arg2","tryCount","pending","hasError","_len5","responseArgs","_key5","_drainQueue","force","_packet","_sendConnectPacket","_pid","pid","offset","_lastOffset","onconnect","onevent","onack","ondisconnect","destroy","message","emitEvent","_anyListeners","_step","_iterator","_createForOfIteratorHelper","s","n","done","f","sent","_len6","_key6","emitBuffered","subDestroy","listener","_anyOutgoingListeners","_step2","_iterator2","Backoff","ms","min","max","factor","jitter","attempts","duration","pow","rand","random","deviation","reset","setMin","setMax","setJitter","Manager","nsps","reconnection","reconnectionAttempts","Infinity","reconnectionDelay","reconnectionDelayMax","randomizationFactor","backoff","_parser","parser","encoder","decoder","autoConnect","v","_reconnection","_reconnectionAttempts","_reconnectionDelay","_randomizationFactor","_reconnectionDelayMax","_timeout","_reconnecting","reconnect","Engine","skipReconnect","openSubDestroy","errorSub","maybeReconnectOnOpen","onping","ondata","ondecoded","add","active","_i","_nsps","_close","delay","onreconnect","attempt","cache","parsed","loc","test","href","url","sameNamespace","forceNew","multiplex"],"mappings":"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"}
./node_modules/socket.io/client-dist/socket.io.msgpack.min.js.map:{"version":3,"file":"socket.io.msgpack.min.js","sources":["../node_modules/engine.io-parser/build/esm/commons.js","../node_modules/engine.io-parser/build/esm/contrib/base64-arraybuffer.js","../node_modules/engine.io-parser/build/esm/encodePacket.browser.js","../node_modules/engine.io-parser/build/esm/decodePacket.browser.js","../node_modules/engine.io-parser/build/esm/index.js","../node_modules/@socket.io/component-emitter/index.mjs","../node_modules/engine.io-client/build/esm/globalThis.browser.js","../node_modules/engine.io-client/build/esm/util.js","../node_modules/engine.io-client/build/esm/contrib/yeast.js","../node_modules/engine.io-client/build/esm/transport.js","../node_modules/engine.io-client/build/esm/contrib/parseqs.js","../node_modules/engine.io-client/build/esm/contrib/has-cors.js","../node_modules/engine.io-client/build/esm/transports/xmlhttprequest.browser.js","../node_modules/engine.io-client/build/esm/transports/polling.js","../node_modules/engine.io-client/build/esm/transports/websocket-constructor.browser.js","../node_modules/engine.io-client/build/esm/transports/websocket.js","../node_modules/engine.io-client/build/esm/transports/index.js","../node_modules/engine.io-client/build/esm/contrib/parseuri.js","../node_modules/engine.io-client/build/esm/socket.js","../node_modules/engine.io-client/build/esm/index.js","../node_modules/notepack.io/browser/encode.js","../node_modules/notepack.io/browser/decode.js","../node_modules/notepack.io/lib/index.js","../node_modules/component-emitter/index.js","../node_modules/socket.io-msgpack-parser/index.js","../build/esm/on.js","../build/esm/socket.js","../build/esm/contrib/backo2.js","../build/esm/manager.js","../build/esm/index.js","../build/esm/url.js"],"sourcesContent":["const PACKET_TYPES = Object.create(null); // no Map = no polyfill
PACKET_TYPES[\"open\"] = \"0\";
PACKET_TYPES[\"close\"] = \"1\";
PACKET_TYPES[\"ping\"] = \"2\";
PACKET_TYPES[\"pong\"] = \"3\";
PACKET_TYPES[\"message\"] = \"4\";
PACKET_TYPES[\"upgrade\"] = \"5\";
PACKET_TYPES[\"noop\"] = \"6\";
const PACKET_TYPES_REVERSE = Object.create(null);
Object.keys(PACKET_TYPES).forEach(key => {
    PACKET_TYPES_REVERSE[PACKET_TYPES[key]] = key;
});
const ERROR_PACKET = { type: \"error\", data: \"parser error\" };
export { PACKET_TYPES, PACKET_TYPES_REVERSE, ERROR_PACKET };
","const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// Use a lookup table to find the index.
const lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}
export const encode = (arraybuffer) => {
    let bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = '';
    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    if (len % 3 === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    }
    else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    return base64;
};
export const decode = (base64) => {
    let bufferLength = base64.length * 0.75, len = base64.length, i, p = 0, encoded1, encoded2, encoded3, encoded4;
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    const arraybuffer = new ArrayBuffer(bufferLength), bytes = new Uint8Array(arraybuffer);
    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    return arraybuffer;
};
","import { PACKET_TYPES } from \"./commons.js\";
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        Object.prototype.toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
// ArrayBuffer.isView method is not defined in IE10
const isView = obj => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj && obj.buffer instanceof ArrayBuffer;
};
const encodePacket = ({ type, data }, supportsBinary, callback) => {
    if (withNativeBlob && data instanceof Blob) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(data, callback);
        }
    }
    else if (withNativeArrayBuffer &&
        (data instanceof ArrayBuffer || isView(data))) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(new Blob([data]), callback);
        }
    }
    // plain string
    return callback(PACKET_TYPES[type] + (data || \"\"));
};
const encodeBlobAsBase64 = (data, callback) => {
    const fileReader = new FileReader();
    fileReader.onload = function () {
        const content = fileReader.result.split(\",\")[1];
        callback(\"b\" + content);
    };
    return fileReader.readAsDataURL(data);
};
export default encodePacket;
","import { ERROR_PACKET, PACKET_TYPES_REVERSE } from \"./commons.js\";
import { decode } from \"./contrib/base64-arraybuffer.js\";
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const decodePacket = (encodedPacket, binaryType) => {
    if (typeof encodedPacket !== \"string\") {
        return {
            type: \"message\",
            data: mapBinary(encodedPacket, binaryType)
        };
    }
    const type = encodedPacket.charAt(0);
    if (type === \"b\") {
        return {
            type: \"message\",
            data: decodeBase64Packet(encodedPacket.substring(1), binaryType)
        };
    }
    const packetType = PACKET_TYPES_REVERSE[type];
    if (!packetType) {
        return ERROR_PACKET;
    }
    return encodedPacket.length > 1
        ? {
            type: PACKET_TYPES_REVERSE[type],
            data: encodedPacket.substring(1)
        }
        : {
            type: PACKET_TYPES_REVERSE[type]
        };
};
const decodeBase64Packet = (data, binaryType) => {
    if (withNativeArrayBuffer) {
        const decoded = decode(data);
        return mapBinary(decoded, binaryType);
    }
    else {
        return { base64: true, data }; // fallback for old browsers
    }
};
const mapBinary = (data, binaryType) => {
    switch (binaryType) {
        case \"blob\":
            return data instanceof ArrayBuffer ? new Blob([data]) : data;
        case \"arraybuffer\":
        default:
            return data; // assuming the data is already an ArrayBuffer
    }
};
export default decodePacket;
","import encodePacket from \"./encodePacket.js\";
import decodePacket from \"./decodePacket.js\";
const SEPARATOR = String.fromCharCode(30); // see https://en.wikipedia.org/wiki/Delimiter#ASCII_delimited_text
const encodePayload = (packets, callback) => {
    // some packets may be added to the array while encoding, so the initial length must be saved
    const length = packets.length;
    const encodedPackets = new Array(length);
    let count = 0;
    packets.forEach((packet, i) => {
        // force base64 encoding for binary packets
        encodePacket(packet, false, encodedPacket => {
            encodedPackets[i] = encodedPacket;
            if (++count === length) {
                callback(encodedPackets.join(SEPARATOR));
            }
        });
    });
};
const decodePayload = (encodedPayload, binaryType) => {
    const encodedPackets = encodedPayload.split(SEPARATOR);
    const packets = [];
    for (let i = 0; i < encodedPackets.length; i++) {
        const decodedPacket = decodePacket(encodedPackets[i], binaryType);
        packets.push(decodedPacket);
        if (decodedPacket.type === \"error\") {
            break;
        }
    }
    return packets;
};
export const protocol = 4;
export { encodePacket, encodePayload, decodePacket, decodePayload };
","/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

export function Emitter(obj) {
  if (obj) return mixin(obj);
}

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  function on() {
    this.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks['$' + event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks['$' + event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }

  // Remove event specific arrays for event types that no
  // one is subscribed for to avoid memory leak.
  if (callbacks.length === 0) {
    delete this._callbacks['$' + event];
  }

  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};

  var args = new Array(arguments.length - 1)
    , callbacks = this._callbacks['$' + event];

  for (var i = 1; i < arguments.length; i++) {
    args[i - 1] = arguments[i];
  }

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

// alias used for reserved events (protected method)
Emitter.prototype.emitReserved = Emitter.prototype.emit;

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks['$' + event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};
","export const globalThisShim = (() => {
    if (typeof self !== \"undefined\") {
        return self;
    }
    else if (typeof window !== \"undefined\") {
        return window;
    }
    else {
        return Function(\"return this\")();
    }
})();
","import { globalThisShim as globalThis } from \"./globalThis.js\";
export function pick(obj, ...attr) {
    return attr.reduce((acc, k) => {
        if (obj.hasOwnProperty(k)) {
            acc[k] = obj[k];
        }
        return acc;
    }, {});
}
// Keep a reference to the real timeout functions so they can be used when overridden
const NATIVE_SET_TIMEOUT = globalThis.setTimeout;
const NATIVE_CLEAR_TIMEOUT = globalThis.clearTimeout;
export function installTimerFunctions(obj, opts) {
    if (opts.useNativeTimers) {
        obj.setTimeoutFn = NATIVE_SET_TIMEOUT.bind(globalThis);
        obj.clearTimeoutFn = NATIVE_CLEAR_TIMEOUT.bind(globalThis);
    }
    else {
        obj.setTimeoutFn = globalThis.setTimeout.bind(globalThis);
        obj.clearTimeoutFn = globalThis.clearTimeout.bind(globalThis);
    }
}
// base64 encoded buffers are about 33% bigger (https://en.wikipedia.org/wiki/Base64)
const BASE64_OVERHEAD = 1.33;
// we could also have used `new Blob([obj]).size`, but it isn't supported in IE9
export function byteLength(obj) {
    if (typeof obj === \"string\") {
        return utf8Length(obj);
    }
    // arraybuffer or blob
    return Math.ceil((obj.byteLength || obj.size) * BASE64_OVERHEAD);
}
function utf8Length(str) {
    let c = 0, length = 0;
    for (let i = 0, l = str.length; i < l; i++) {
        c = str.charCodeAt(i);
        if (c < 0x80) {
            length += 1;
        }
        else if (c < 0x800) {
            length += 2;
        }
        else if (c < 0xd800 || c >= 0xe000) {
            length += 3;
        }
        else {
            i++;
            length += 4;
        }
    }
    return length;
}
","// imported from https://github.com/unshiftio/yeast
'use strict';
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'.split(''), length = 64, map = {};
let seed = 0, i = 0, prev;
/**
 * Return a string representing the specified number.
 *
 * @param {Number} num The number to convert.
 * @returns {String} The string representation of the number.
 * @api public
 */
export function encode(num) {
    let encoded = '';
    do {
        encoded = alphabet[num % length] + encoded;
        num = Math.floor(num / length);
    } while (num > 0);
    return encoded;
}
/**
 * Return the integer value specified by the given string.
 *
 * @param {String} str The string to convert.
 * @returns {Number} The integer value represented by the string.
 * @api public
 */
export function decode(str) {
    let decoded = 0;
    for (i = 0; i < str.length; i++) {
        decoded = decoded * length + map[str.charAt(i)];
    }
    return decoded;
}
/**
 * Yeast: A tiny growing id generator.
 *
 * @returns {String} A unique id.
 * @api public
 */
export function yeast() {
    const now = encode(+new Date());
    if (now !== prev)
        return seed = 0, prev = now;
    return now + '.' + encode(seed++);
}
//
// Map each character to its index.
//
for (; i < length; i++)
    map[alphabet[i]] = i;
","import { decodePacket } from \"engine.io-parser\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions } from \"./util.js\";
class TransportError extends Error {
    constructor(reason, description, context) {
        super(reason);
        this.description = description;
        this.context = context;
        this.type = \"TransportError\";
    }
}
export class Transport extends Emitter {
    /**
     * Transport abstract constructor.
     *
     * @param {Object} opts - options
     * @protected
     */
    constructor(opts) {
        super();
        this.writable = false;
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.query = opts.query;
        this.socket = opts.socket;
    }
    /**
     * Emits an error.
     *
     * @param {String} reason
     * @param description
     * @param context - the error context
     * @return {Transport} for chaining
     * @protected
     */
    onError(reason, description, context) {
        super.emitReserved(\"error\", new TransportError(reason, description, context));
        return this;
    }
    /**
     * Opens the transport.
     */
    open() {
        this.readyState = \"opening\";
        this.doOpen();
        return this;
    }
    /**
     * Closes the transport.
     */
    close() {
        if (this.readyState === \"opening\" || this.readyState === \"open\") {
            this.doClose();
            this.onClose();
        }
        return this;
    }
    /**
     * Sends multiple packets.
     *
     * @param {Array} packets
     */
    send(packets) {
        if (this.readyState === \"open\") {
            this.write(packets);
        }
        else {
            // this might happen if the transport was silently closed in the beforeunload event handler
        }
    }
    /**
     * Called upon open
     *
     * @protected
     */
    onOpen() {
        this.readyState = \"open\";
        this.writable = true;
        super.emitReserved(\"open\");
    }
    /**
     * Called with data.
     *
     * @param {String} data
     * @protected
     */
    onData(data) {
        const packet = decodePacket(data, this.socket.binaryType);
        this.onPacket(packet);
    }
    /**
     * Called with a decoded packet.
     *
     * @protected
     */
    onPacket(packet) {
        super.emitReserved(\"packet\", packet);
    }
    /**
     * Called upon close.
     *
     * @protected
     */
    onClose(details) {
        this.readyState = \"closed\";
        super.emitReserved(\"close\", details);
    }
    /**
     * Pauses the transport, in order not to lose packets during an upgrade.
     *
     * @param onPause
     */
    pause(onPause) { }
}
","// imported from https://github.com/galkn/querystring
/**
 * Compiles a querystring
 * Returns string representation of the object
 *
 * @param {Object}
 * @api private
 */
export function encode(obj) {
    let str = '';
    for (let i in obj) {
        if (obj.hasOwnProperty(i)) {
            if (str.length)
                str += '&';
            str += encodeURIComponent(i) + '=' + encodeURIComponent(obj[i]);
        }
    }
    return str;
}
/**
 * Parses a simple querystring into an object
 *
 * @param {String} qs
 * @api private
 */
export function decode(qs) {
    let qry = {};
    let pairs = qs.split('&');
    for (let i = 0, l = pairs.length; i < l; i++) {
        let pair = pairs[i].split('=');
        qry[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
    }
    return qry;
}
","// imported from https://github.com/component/has-cors
let value = false;
try {
    value = typeof XMLHttpRequest !== 'undefined' &&
        'withCredentials' in new XMLHttpRequest();
}
catch (err) {
    // if XMLHttp support is disabled in IE then it will throw
    // when trying to create
}
export const hasCORS = value;
","// browser shim for xmlhttprequest module
import { hasCORS } from \"../contrib/has-cors.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
export function XHR(opts) {
    const xdomain = opts.xdomain;
    // XMLHttpRequest can be disabled on IE
    try {
        if (\"undefined\" !== typeof XMLHttpRequest && (!xdomain || hasCORS)) {
            return new XMLHttpRequest();
        }
    }
    catch (e) { }
    if (!xdomain) {
        try {
            return new globalThis[[\"Active\"].concat(\"Object\").join(\"X\")](\"Microsoft.XMLHTTP\");
        }
        catch (e) { }
    }
}
","import { Transport } from \"../transport.js\";
import { yeast } from \"../contrib/yeast.js\";
import { encode } from \"../contrib/parseqs.js\";
import { encodePayload, decodePayload } from \"engine.io-parser\";
import { XHR as XMLHttpRequest } from \"./xmlhttprequest.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions, pick } from \"../util.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
function empty() { }
const hasXHR2 = (function () {
    const xhr = new XMLHttpRequest({
        xdomain: false,
    });
    return null != xhr.responseType;
})();
export class Polling extends Transport {
    /**
     * XHR Polling constructor.
     *
     * @param {Object} opts
     * @package
     */
    constructor(opts) {
        super(opts);
        this.polling = false;
        if (typeof location !== \"undefined\") {
            const isSSL = \"https:\" === location.protocol;
            let port = location.port;
            // some user agents have empty `location.port`
            if (!port) {
                port = isSSL ? \"443\" : \"80\";
            }
            this.xd =
                (typeof location !== \"undefined\" &&
                    opts.hostname !== location.hostname) ||
                    port !== opts.port;
            this.xs = opts.secure !== isSSL;
        }
        /**
         * XHR supports binary
         */
        const forceBase64 = opts && opts.forceBase64;
        this.supportsBinary = hasXHR2 && !forceBase64;
    }
    get name() {
        return \"polling\";
    }
    /**
     * Opens the socket (triggers polling). We write a PING message to determine
     * when the transport is open.
     *
     * @protected
     */
    doOpen() {
        this.poll();
    }
    /**
     * Pauses polling.
     *
     * @param {Function} onPause - callback upon buffers are flushed and transport is paused
     * @package
     */
    pause(onPause) {
        this.readyState = \"pausing\";
        const pause = () => {
            this.readyState = \"paused\";
            onPause();
        };
        if (this.polling || !this.writable) {
            let total = 0;
            if (this.polling) {
                total++;
                this.once(\"pollComplete\", function () {
                    --total || pause();
                });
            }
            if (!this.writable) {
                total++;
                this.once(\"drain\", function () {
                    --total || pause();
                });
            }
        }
        else {
            pause();
        }
    }
    /**
     * Starts polling cycle.
     *
     * @private
     */
    poll() {
        this.polling = true;
        this.doPoll();
        this.emitReserved(\"poll\");
    }
    /**
     * Overloads onData to detect payloads.
     *
     * @protected
     */
    onData(data) {
        const callback = (packet) => {
            // if its the first message we consider the transport open
            if (\"opening\" === this.readyState && packet.type === \"open\") {
                this.onOpen();
            }
            // if its a close packet, we close the ongoing requests
            if (\"close\" === packet.type) {
                this.onClose({ description: \"transport closed by the server\" });
                return false;
            }
            // otherwise bypass onData and handle the message
            this.onPacket(packet);
        };
        // decode payload
        decodePayload(data, this.socket.binaryType).forEach(callback);
        // if an event did not trigger closing
        if (\"closed\" !== this.readyState) {
            // if we got data we're not polling
            this.polling = false;
            this.emitReserved(\"pollComplete\");
            if (\"open\" === this.readyState) {
                this.poll();
            }
            else {
            }
        }
    }
    /**
     * For polling, send a close packet.
     *
     * @protected
     */
    doClose() {
        const close = () => {
            this.write([{ type: \"close\" }]);
        };
        if (\"open\" === this.readyState) {
            close();
        }
        else {
            // in case we're trying to close while
            // handshaking is in progress (GH-164)
            this.once(\"open\", close);
        }
    }
    /**
     * Writes a packets payload.
     *
     * @param {Array} packets - data packets
     * @protected
     */
    write(packets) {
        this.writable = false;
        encodePayload(packets, (data) => {
            this.doWrite(data, () => {
                this.writable = true;
                this.emitReserved(\"drain\");
            });
        });
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"https\" : \"http\";
        let port = \"\";
        // cache busting is forced
        if (false !== this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        if (!this.supportsBinary && !query.sid) {
            query.b64 = 1;
        }
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"https\" === schema && Number(this.opts.port) !== 443) ||
                (\"http\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Creates a request.
     *
     * @param {String} method
     * @private
     */
    request(opts = {}) {
        Object.assign(opts, { xd: this.xd, xs: this.xs }, this.opts);
        return new Request(this.uri(), opts);
    }
    /**
     * Sends data.
     *
     * @param {String} data to send.
     * @param {Function} called upon flush.
     * @private
     */
    doWrite(data, fn) {
        const req = this.request({
            method: \"POST\",
            data: data,
        });
        req.on(\"success\", fn);
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr post error\", xhrStatus, context);
        });
    }
    /**
     * Starts a poll cycle.
     *
     * @private
     */
    doPoll() {
        const req = this.request();
        req.on(\"data\", this.onData.bind(this));
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr poll error\", xhrStatus, context);
        });
        this.pollXhr = req;
    }
}
export class Request extends Emitter {
    /**
     * Request constructor
     *
     * @param {Object} options
     * @package
     */
    constructor(uri, opts) {
        super();
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.method = opts.method || \"GET\";
        this.uri = uri;
        this.async = false !== opts.async;
        this.data = undefined !== opts.data ? opts.data : null;
        this.create();
    }
    /**
     * Creates the XHR object and sends the request.
     *
     * @private
     */
    create() {
        const opts = pick(this.opts, \"agent\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"autoUnref\");
        opts.xdomain = !!this.opts.xd;
        opts.xscheme = !!this.opts.xs;
        const xhr = (this.xhr = new XMLHttpRequest(opts));
        try {
            xhr.open(this.method, this.uri, this.async);
            try {
                if (this.opts.extraHeaders) {
                    xhr.setDisableHeaderCheck && xhr.setDisableHeaderCheck(true);
                    for (let i in this.opts.extraHeaders) {
                        if (this.opts.extraHeaders.hasOwnProperty(i)) {
                            xhr.setRequestHeader(i, this.opts.extraHeaders[i]);
                        }
                    }
                }
            }
            catch (e) { }
            if (\"POST\" === this.method) {
                try {
                    xhr.setRequestHeader(\"Content-type\", \"text/plain;charset=UTF-8\");
                }
                catch (e) { }
            }
            try {
                xhr.setRequestHeader(\"Accept\", \"*/*\");
            }
            catch (e) { }
            // ie6 check
            if (\"withCredentials\" in xhr) {
                xhr.withCredentials = this.opts.withCredentials;
            }
            if (this.opts.requestTimeout) {
                xhr.timeout = this.opts.requestTimeout;
            }
            xhr.onreadystatechange = () => {
                if (4 !== xhr.readyState)
                    return;
                if (200 === xhr.status || 1223 === xhr.status) {
                    this.onLoad();
                }
                else {
                    // make sure the `error` event handler that's user-set
                    // does not throw in the same tick and gets caught here
                    this.setTimeoutFn(() => {
                        this.onError(typeof xhr.status === \"number\" ? xhr.status : 0);
                    }, 0);
                }
            };
            xhr.send(this.data);
        }
        catch (e) {
            // Need to defer since .create() is called directly from the constructor
            // and thus the 'error' event can only be only bound *after* this exception
            // occurs.  Therefore, also, we cannot throw here at all.
            this.setTimeoutFn(() => {
                this.onError(e);
            }, 0);
            return;
        }
        if (typeof document !== \"undefined\") {
            this.index = Request.requestsCount++;
            Request.requests[this.index] = this;
        }
    }
    /**
     * Called upon error.
     *
     * @private
     */
    onError(err) {
        this.emitReserved(\"error\", err, this.xhr);
        this.cleanup(true);
    }
    /**
     * Cleans up house.
     *
     * @private
     */
    cleanup(fromError) {
        if (\"undefined\" === typeof this.xhr || null === this.xhr) {
            return;
        }
        this.xhr.onreadystatechange = empty;
        if (fromError) {
            try {
                this.xhr.abort();
            }
            catch (e) { }
        }
        if (typeof document !== \"undefined\") {
            delete Request.requests[this.index];
        }
        this.xhr = null;
    }
    /**
     * Called upon load.
     *
     * @private
     */
    onLoad() {
        const data = this.xhr.responseText;
        if (data !== null) {
            this.emitReserved(\"data\", data);
            this.emitReserved(\"success\");
            this.cleanup();
        }
    }
    /**
     * Aborts the request.
     *
     * @package
     */
    abort() {
        this.cleanup();
    }
}
Request.requestsCount = 0;
Request.requests = {};
/**
 * Aborts pending requests when unloading the window. This is needed to prevent
 * memory leaks (e.g. when using IE) and to ensure that no spurious error is
 * emitted.
 */
if (typeof document !== \"undefined\") {
    // @ts-ignore
    if (typeof attachEvent === \"function\") {
        // @ts-ignore
        attachEvent(\"onunload\", unloadHandler);
    }
    else if (typeof addEventListener === \"function\") {
        const terminationEvent = \"onpagehide\" in globalThis ? \"pagehide\" : \"unload\";
        addEventListener(terminationEvent, unloadHandler, false);
    }
}
function unloadHandler() {
    for (let i in Request.requests) {
        if (Request.requests.hasOwnProperty(i)) {
            Request.requests[i].abort();
        }
    }
}
","import { globalThisShim as globalThis } from \"../globalThis.js\";
export const nextTick = (() => {
    const isPromiseAvailable = typeof Promise === \"function\" && typeof Promise.resolve === \"function\";
    if (isPromiseAvailable) {
        return (cb) => Promise.resolve().then(cb);
    }
    else {
        return (cb, setTimeoutFn) => setTimeoutFn(cb, 0);
    }
})();
export const WebSocket = globalThis.WebSocket || globalThis.MozWebSocket;
export const usingBrowserWebSocket = true;
export const defaultBinaryType = \"arraybuffer\";
","import { Transport } from \"../transport.js\";
import { encode } from \"../contrib/parseqs.js\";
import { yeast } from \"../contrib/yeast.js\";
import { pick } from \"../util.js\";
import { defaultBinaryType, nextTick, usingBrowserWebSocket, WebSocket, } from \"./websocket-constructor.js\";
import { encodePacket } from \"engine.io-parser\";
// detect ReactNative environment
const isReactNative = typeof navigator !== \"undefined\" &&
    typeof navigator.product === \"string\" &&
    navigator.product.toLowerCase() === \"reactnative\";
export class WS extends Transport {
    /**
     * WebSocket transport constructor.
     *
     * @param {Object} opts - connection options
     * @protected
     */
    constructor(opts) {
        super(opts);
        this.supportsBinary = !opts.forceBase64;
    }
    get name() {
        return \"websocket\";
    }
    doOpen() {
        if (!this.check()) {
            // let probe timeout
            return;
        }
        const uri = this.uri();
        const protocols = this.opts.protocols;
        // React Native only supports the 'headers' option, and will print a warning if anything else is passed
        const opts = isReactNative
            ? {}
            : pick(this.opts, \"agent\", \"perMessageDeflate\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"localAddress\", \"protocolVersion\", \"origin\", \"maxPayload\", \"family\", \"checkServerIdentity\");
        if (this.opts.extraHeaders) {
            opts.headers = this.opts.extraHeaders;
        }
        try {
            this.ws =
                usingBrowserWebSocket && !isReactNative
                    ? protocols
                        ? new WebSocket(uri, protocols)
                        : new WebSocket(uri)
                    : new WebSocket(uri, protocols, opts);
        }
        catch (err) {
            return this.emitReserved(\"error\", err);
        }
        this.ws.binaryType = this.socket.binaryType || defaultBinaryType;
        this.addEventListeners();
    }
    /**
     * Adds event listeners to the socket
     *
     * @private
     */
    addEventListeners() {
        this.ws.onopen = () => {
            if (this.opts.autoUnref) {
                this.ws._socket.unref();
            }
            this.onOpen();
        };
        this.ws.onclose = (closeEvent) => this.onClose({
            description: \"websocket connection closed\",
            context: closeEvent,
        });
        this.ws.onmessage = (ev) => this.onData(ev.data);
        this.ws.onerror = (e) => this.onError(\"websocket error\", e);
    }
    write(packets) {
        this.writable = false;
        // encodePacket efficient as it uses WS framing
        // no need for encodePayload
        for (let i = 0; i < packets.length; i++) {
            const packet = packets[i];
            const lastPacket = i === packets.length - 1;
            encodePacket(packet, this.supportsBinary, (data) => {
                // always create a new object (GH-437)
                const opts = {};
                if (!usingBrowserWebSocket) {
                    if (packet.options) {
                        opts.compress = packet.options.compress;
                    }
                    if (this.opts.perMessageDeflate) {
                        const len = 
                        // @ts-ignore
                        \"string\" === typeof data ? Buffer.byteLength(data) : data.length;
                        if (len < this.opts.perMessageDeflate.threshold) {
                            opts.compress = false;
                        }
                    }
                }
                // Sometimes the websocket has already been closed but the browser didn't
                // have a chance of informing us about it yet, in that case send will
                // throw an error
                try {
                    if (usingBrowserWebSocket) {
                        // TypeError is thrown when passing the second argument on Safari
                        this.ws.send(data);
                    }
                    else {
                        this.ws.send(data, opts);
                    }
                }
                catch (e) {
                }
                if (lastPacket) {
                    // fake drain
                    // defer to next tick to allow Socket to clear writeBuffer
                    nextTick(() => {
                        this.writable = true;
                        this.emitReserved(\"drain\");
                    }, this.setTimeoutFn);
                }
            });
        }
    }
    doClose() {
        if (typeof this.ws !== \"undefined\") {
            this.ws.close();
            this.ws = null;
        }
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"wss\" : \"ws\";
        let port = \"\";
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"wss\" === schema && Number(this.opts.port) !== 443) ||
                (\"ws\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        // append timestamp to URI
        if (this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        // communicate binary support capabilities
        if (!this.supportsBinary) {
            query.b64 = 1;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Feature detection for WebSocket.
     *
     * @return {Boolean} whether this transport is available.
     * @private
     */
    check() {
        return !!WebSocket;
    }
}
","import { Polling } from \"./polling.js\";
import { WS } from \"./websocket.js\";
export const transports = {
    websocket: WS,
    polling: Polling,
};
","// imported from https://github.com/galkn/parseuri
/**
 * Parses a URI
 *
 * Note: we could also have used the built-in URL object, but it isn't supported on all platforms.
 *
 * See:
 * - https://developer.mozilla.org/en-US/docs/Web/API/URL
 * - https://caniuse.com/url
 * - https://www.rfc-editor.org/rfc/rfc3986#appendix-B
 *
 * History of the parse() method:
 * - first commit: https://github.com/socketio/socket.io-client/commit/4ee1d5d94b3906a9c052b459f1a818b15f38f91c
 * - export into its own module: https://github.com/socketio/engine.io-client/commit/de2c561e4564efeb78f1bdb1ba39ef81b2822cb3
 * - reimport: https://github.com/socketio/engine.io-client/commit/df32277c3f6d622eec5ed09f493cae3f3391d242
 *
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * @api private
 */
const re = /^(?:(?![^:@\\/?#]+:[^:@\\/]*@)(http|https|ws|wss):\\/\\/)?((?:(([^:@\\/?#]*)(?::([^:@\\/?#]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\\/?#]*)(?::(\\d*))?)(((\\/(?:[^?#](?![^?#\\/]*\\.[^?#\\/.]+(?:[?#]|$)))*\\/?)?([^?#\\/]*))(?:\\?([^#]*))?(?:#(.*))?)/;
const parts = [
    'source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'
];
export function parse(str) {
    const src = str, b = str.indexOf('['), e = str.indexOf(']');
    if (b != -1 && e != -1) {
        str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
    }
    let m = re.exec(str || ''), uri = {}, i = 14;
    while (i--) {
        uri[parts[i]] = m[i] || '';
    }
    if (b != -1 && e != -1) {
        uri.source = src;
        uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
        uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
        uri.ipv6uri = true;
    }
    uri.pathNames = pathNames(uri, uri['path']);
    uri.queryKey = queryKey(uri, uri['query']);
    return uri;
}
function pathNames(obj, path) {
    const regx = /\\/{2,9}/g, names = path.replace(regx, \"/\").split(\"/\");
    if (path.slice(0, 1) == '/' || path.length === 0) {
        names.splice(0, 1);
    }
    if (path.slice(-1) == '/') {
        names.splice(names.length - 1, 1);
    }
    return names;
}
function queryKey(uri, query) {
    const data = {};
    query.replace(/(?:^|&)([^&=]*)=?([^&]*)/g, function ($0, $1, $2) {
        if ($1) {
            data[$1] = $2;
        }
    });
    return data;
}
","import { transports } from \"./transports/index.js\";
import { installTimerFunctions, byteLength } from \"./util.js\";
import { decode } from \"./contrib/parseqs.js\";
import { parse } from \"./contrib/parseuri.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { protocol } from \"engine.io-parser\";
export class Socket extends Emitter {
    /**
     * Socket constructor.
     *
     * @param {String|Object} uri - uri or options
     * @param {Object} opts - options
     */
    constructor(uri, opts = {}) {
        super();
        this.writeBuffer = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = null;
        }
        if (uri) {
            uri = parse(uri);
            opts.hostname = uri.host;
            opts.secure = uri.protocol === \"https\" || uri.protocol === \"wss\";
            opts.port = uri.port;
            if (uri.query)
                opts.query = uri.query;
        }
        else if (opts.host) {
            opts.hostname = parse(opts.host).host;
        }
        installTimerFunctions(this, opts);
        this.secure =
            null != opts.secure
                ? opts.secure
                : typeof location !== \"undefined\" && \"https:\" === location.protocol;
        if (opts.hostname && !opts.port) {
            // if no port is specified manually, use the protocol default
            opts.port = this.secure ? \"443\" : \"80\";
        }
        this.hostname =
            opts.hostname ||
                (typeof location !== \"undefined\" ? location.hostname : \"localhost\");
        this.port =
            opts.port ||
                (typeof location !== \"undefined\" && location.port
                    ? location.port
                    : this.secure
                        ? \"443\"
                        : \"80\");
        this.transports = opts.transports || [\"polling\", \"websocket\"];
        this.writeBuffer = [];
        this.prevBufferLen = 0;
        this.opts = Object.assign({
            path: \"/engine.io\",
            agent: false,
            withCredentials: false,
            upgrade: true,
            timestampParam: \"t\",
            rememberUpgrade: false,
            addTrailingSlash: true,
            rejectUnauthorized: true,
            perMessageDeflate: {
                threshold: 1024,
            },
            transportOptions: {},
            closeOnBeforeunload: true,
        }, opts);
        this.opts.path =
            this.opts.path.replace(/\\/$/, \"\") +
                (this.opts.addTrailingSlash ? \"/\" : \"\");
        if (typeof this.opts.query === \"string\") {
            this.opts.query = decode(this.opts.query);
        }
        // set on handshake
        this.id = null;
        this.upgrades = null;
        this.pingInterval = null;
        this.pingTimeout = null;
        // set on heartbeat
        this.pingTimeoutTimer = null;
        if (typeof addEventListener === \"function\") {
            if (this.opts.closeOnBeforeunload) {
                // Firefox closes the connection when the \"beforeunload\" event is emitted but not Chrome. This event listener
                // ensures every browser behaves the same (no \"disconnect\" event at the Socket.IO level when the page is
                // closed/reloaded)
                this.beforeunloadEventListener = () => {
                    if (this.transport) {
                        // silently close the transport
                        this.transport.removeAllListeners();
                        this.transport.close();
                    }
                };
                addEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
            }
            if (this.hostname !== \"localhost\") {
                this.offlineEventListener = () => {
                    this.onClose(\"transport close\", {
                        description: \"network connection lost\",
                    });
                };
                addEventListener(\"offline\", this.offlineEventListener, false);
            }
        }
        this.open();
    }
    /**
     * Creates transport of the given type.
     *
     * @param {String} name - transport name
     * @return {Transport}
     * @private
     */
    createTransport(name) {
        const query = Object.assign({}, this.opts.query);
        // append engine.io protocol identifier
        query.EIO = protocol;
        // transport name
        query.transport = name;
        // session id if we already have one
        if (this.id)
            query.sid = this.id;
        const opts = Object.assign({}, this.opts.transportOptions[name], this.opts, {
            query,
            socket: this,
            hostname: this.hostname,
            secure: this.secure,
            port: this.port,
        });
        return new transports[name](opts);
    }
    /**
     * Initializes transport to use and starts probe.
     *
     * @private
     */
    open() {
        let transport;
        if (this.opts.rememberUpgrade &&
            Socket.priorWebsocketSuccess &&
            this.transports.indexOf(\"websocket\") !== -1) {
            transport = \"websocket\";
        }
        else if (0 === this.transports.length) {
            // Emit error on next tick so it can be listened to
            this.setTimeoutFn(() => {
                this.emitReserved(\"error\", \"No transports available\");
            }, 0);
            return;
        }
        else {
            transport = this.transports[0];
        }
        this.readyState = \"opening\";
        // Retry with the next transport if the transport is disabled (jsonp: false)
        try {
            transport = this.createTransport(transport);
        }
        catch (e) {
            this.transports.shift();
            this.open();
            return;
        }
        transport.open();
        this.setTransport(transport);
    }
    /**
     * Sets the current transport. Disables the existing one (if any).
     *
     * @private
     */
    setTransport(transport) {
        if (this.transport) {
            this.transport.removeAllListeners();
        }
        // set up transport
        this.transport = transport;
        // set up transport listeners
        transport
            .on(\"drain\", this.onDrain.bind(this))
            .on(\"packet\", this.onPacket.bind(this))
            .on(\"error\", this.onError.bind(this))
            .on(\"close\", (reason) => this.onClose(\"transport close\", reason));
    }
    /**
     * Probes a transport.
     *
     * @param {String} name - transport name
     * @private
     */
    probe(name) {
        let transport = this.createTransport(name);
        let failed = false;
        Socket.priorWebsocketSuccess = false;
        const onTransportOpen = () => {
            if (failed)
                return;
            transport.send([{ type: \"ping\", data: \"probe\" }]);
            transport.once(\"packet\", (msg) => {
                if (failed)
                    return;
                if (\"pong\" === msg.type && \"probe\" === msg.data) {
                    this.upgrading = true;
                    this.emitReserved(\"upgrading\", transport);
                    if (!transport)
                        return;
                    Socket.priorWebsocketSuccess = \"websocket\" === transport.name;
                    this.transport.pause(() => {
                        if (failed)
                            return;
                        if (\"closed\" === this.readyState)
                            return;
                        cleanup();
                        this.setTransport(transport);
                        transport.send([{ type: \"upgrade\" }]);
                        this.emitReserved(\"upgrade\", transport);
                        transport = null;
                        this.upgrading = false;
                        this.flush();
                    });
                }
                else {
                    const err = new Error(\"probe error\");
                    // @ts-ignore
                    err.transport = transport.name;
                    this.emitReserved(\"upgradeError\", err);
                }
            });
        };
        function freezeTransport() {
            if (failed)
                return;
            // Any callback called by transport should be ignored since now
            failed = true;
            cleanup();
            transport.close();
            transport = null;
        }
        // Handle any error that happens while probing
        const onerror = (err) => {
            const error = new Error(\"probe error: \" + err);
            // @ts-ignore
            error.transport = transport.name;
            freezeTransport();
            this.emitReserved(\"upgradeError\", error);
        };
        function onTransportClose() {
            onerror(\"transport closed\");
        }
        // When the socket is closed while we're probing
        function onclose() {
            onerror(\"socket closed\");
        }
        // When the socket is upgraded while we're probing
        function onupgrade(to) {
            if (transport && to.name !== transport.name) {
                freezeTransport();
            }
        }
        // Remove all listeners on the transport and on self
        const cleanup = () => {
            transport.removeListener(\"open\", onTransportOpen);
            transport.removeListener(\"error\", onerror);
            transport.removeListener(\"close\", onTransportClose);
            this.off(\"close\", onclose);
            this.off(\"upgrading\", onupgrade);
        };
        transport.once(\"open\", onTransportOpen);
        transport.once(\"error\", onerror);
        transport.once(\"close\", onTransportClose);
        this.once(\"close\", onclose);
        this.once(\"upgrading\", onupgrade);
        transport.open();
    }
    /**
     * Called when connection is deemed open.
     *
     * @private
     */
    onOpen() {
        this.readyState = \"open\";
        Socket.priorWebsocketSuccess = \"websocket\" === this.transport.name;
        this.emitReserved(\"open\");
        this.flush();
        // we check for `readyState` in case an `open`
        // listener already closed the socket
        if (\"open\" === this.readyState && this.opts.upgrade) {
            let i = 0;
            const l = this.upgrades.length;
            for (; i < l; i++) {
                this.probe(this.upgrades[i]);
            }
        }
    }
    /**
     * Handles a packet.
     *
     * @private
     */
    onPacket(packet) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            this.emitReserved(\"packet\", packet);
            // Socket is live - any packet counts
            this.emitReserved(\"heartbeat\");
            switch (packet.type) {
                case \"open\":
                    this.onHandshake(JSON.parse(packet.data));
                    break;
                case \"ping\":
                    this.resetPingTimeout();
                    this.sendPacket(\"pong\");
                    this.emitReserved(\"ping\");
                    this.emitReserved(\"pong\");
                    break;
                case \"error\":
                    const err = new Error(\"server error\");
                    // @ts-ignore
                    err.code = packet.data;
                    this.onError(err);
                    break;
                case \"message\":
                    this.emitReserved(\"data\", packet.data);
                    this.emitReserved(\"message\", packet.data);
                    break;
            }
        }
        else {
        }
    }
    /**
     * Called upon handshake completion.
     *
     * @param {Object} data - handshake obj
     * @private
     */
    onHandshake(data) {
        this.emitReserved(\"handshake\", data);
        this.id = data.sid;
        this.transport.query.sid = data.sid;
        this.upgrades = this.filterUpgrades(data.upgrades);
        this.pingInterval = data.pingInterval;
        this.pingTimeout = data.pingTimeout;
        this.maxPayload = data.maxPayload;
        this.onOpen();
        // In case open handler closes socket
        if (\"closed\" === this.readyState)
            return;
        this.resetPingTimeout();
    }
    /**
     * Sets and resets ping timeout timer based on server pings.
     *
     * @private
     */
    resetPingTimeout() {
        this.clearTimeoutFn(this.pingTimeoutTimer);
        this.pingTimeoutTimer = this.setTimeoutFn(() => {
            this.onClose(\"ping timeout\");
        }, this.pingInterval + this.pingTimeout);
        if (this.opts.autoUnref) {
            this.pingTimeoutTimer.unref();
        }
    }
    /**
     * Called on `drain` event
     *
     * @private
     */
    onDrain() {
        this.writeBuffer.splice(0, this.prevBufferLen);
        // setting prevBufferLen = 0 is very important
        // for example, when upgrading, upgrade packet is sent over,
        // and a nonzero prevBufferLen could cause problems on `drain`
        this.prevBufferLen = 0;
        if (0 === this.writeBuffer.length) {
            this.emitReserved(\"drain\");
        }
        else {
            this.flush();
        }
    }
    /**
     * Flush write buffers.
     *
     * @private
     */
    flush() {
        if (\"closed\" !== this.readyState &&
            this.transport.writable &&
            !this.upgrading &&
            this.writeBuffer.length) {
            const packets = this.getWritablePackets();
            this.transport.send(packets);
            // keep track of current length of writeBuffer
            // splice writeBuffer and callbackBuffer on `drain`
            this.prevBufferLen = packets.length;
            this.emitReserved(\"flush\");
        }
    }
    /**
     * Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
     * long-polling)
     *
     * @private
     */
    getWritablePackets() {
        const shouldCheckPayloadSize = this.maxPayload &&
            this.transport.name === \"polling\" &&
            this.writeBuffer.length > 1;
        if (!shouldCheckPayloadSize) {
            return this.writeBuffer;
        }
        let payloadSize = 1; // first packet type
        for (let i = 0; i < this.writeBuffer.length; i++) {
            const data = this.writeBuffer[i].data;
            if (data) {
                payloadSize += byteLength(data);
            }
            if (i > 0 && payloadSize > this.maxPayload) {
                return this.writeBuffer.slice(0, i);
            }
            payloadSize += 2; // separator + packet type
        }
        return this.writeBuffer;
    }
    /**
     * Sends a message.
     *
     * @param {String} msg - message.
     * @param {Object} options.
     * @param {Function} callback function.
     * @return {Socket} for chaining.
     */
    write(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    send(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    /**
     * Sends a packet.
     *
     * @param {String} type: packet type.
     * @param {String} data.
     * @param {Object} options.
     * @param {Function} fn - callback function.
     * @private
     */
    sendPacket(type, data, options, fn) {
        if (\"function\" === typeof data) {
            fn = data;
            data = undefined;
        }
        if (\"function\" === typeof options) {
            fn = options;
            options = null;
        }
        if (\"closing\" === this.readyState || \"closed\" === this.readyState) {
            return;
        }
        options = options || {};
        options.compress = false !== options.compress;
        const packet = {
            type: type,
            data: data,
            options: options,
        };
        this.emitReserved(\"packetCreate\", packet);
        this.writeBuffer.push(packet);
        if (fn)
            this.once(\"flush\", fn);
        this.flush();
    }
    /**
     * Closes the connection.
     */
    close() {
        const close = () => {
            this.onClose(\"forced close\");
            this.transport.close();
        };
        const cleanupAndClose = () => {
            this.off(\"upgrade\", cleanupAndClose);
            this.off(\"upgradeError\", cleanupAndClose);
            close();
        };
        const waitForUpgrade = () => {
            // wait for upgrade to finish since we can't send packets while pausing a transport
            this.once(\"upgrade\", cleanupAndClose);
            this.once(\"upgradeError\", cleanupAndClose);
        };
        if (\"opening\" === this.readyState || \"open\" === this.readyState) {
            this.readyState = \"closing\";
            if (this.writeBuffer.length) {
                this.once(\"drain\", () => {
                    if (this.upgrading) {
                        waitForUpgrade();
                    }
                    else {
                        close();
                    }
                });
            }
            else if (this.upgrading) {
                waitForUpgrade();
            }
            else {
                close();
            }
        }
        return this;
    }
    /**
     * Called upon transport error
     *
     * @private
     */
    onError(err) {
        Socket.priorWebsocketSuccess = false;
        this.emitReserved(\"error\", err);
        this.onClose(\"transport error\", err);
    }
    /**
     * Called upon transport close.
     *
     * @private
     */
    onClose(reason, description) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            // clear timers
            this.clearTimeoutFn(this.pingTimeoutTimer);
            // stop event from firing again for transport
            this.transport.removeAllListeners(\"close\");
            // ensure transport won't stay open
            this.transport.close();
            // ignore further transport communication
            this.transport.removeAllListeners();
            if (typeof removeEventListener === \"function\") {
                removeEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
                removeEventListener(\"offline\", this.offlineEventListener, false);
            }
            // set ready state
            this.readyState = \"closed\";
            // clear session id
            this.id = null;
            // emit close event
            this.emitReserved(\"close\", reason, description);
            // clean buffers after, so users can still
            // grab the buffers on `close` event
            this.writeBuffer = [];
            this.prevBufferLen = 0;
        }
    }
    /**
     * Filters upgrades, returning only those matching client transports.
     *
     * @param {Array} upgrades - server upgrades
     * @private
     */
    filterUpgrades(upgrades) {
        const filteredUpgrades = [];
        let i = 0;
        const j = upgrades.length;
        for (; i < j; i++) {
            if (~this.transports.indexOf(upgrades[i]))
                filteredUpgrades.push(upgrades[i]);
        }
        return filteredUpgrades;
    }
}
Socket.protocol = protocol;
","import { Socket } from \"./socket.js\";
export { Socket };
export const protocol = Socket.protocol;
export { Transport } from \"./transport.js\";
export { transports } from \"./transports/index.js\";
export { installTimerFunctions } from \"./util.js\";
export { parse } from \"./contrib/parseuri.js\";
export { nextTick } from \"./transports/websocket-constructor.js\";
","'use strict';

function utf8Write(view, offset, str) {
  var c = 0;
  for (var i = 0, l = str.length; i < l; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) {
      view.setUint8(offset++, c);
    }
    else if (c < 0x800) {
      view.setUint8(offset++, 0xc0 | (c >> 6));
      view.setUint8(offset++, 0x80 | (c & 0x3f));
    }
    else if (c < 0xd800 || c >= 0xe000) {
      view.setUint8(offset++, 0xe0 | (c >> 12));
      view.setUint8(offset++, 0x80 | (c >> 6) & 0x3f);
      view.setUint8(offset++, 0x80 | (c & 0x3f));
    }
    else {
      i++;
      c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      view.setUint8(offset++, 0xf0 | (c >> 18));
      view.setUint8(offset++, 0x80 | (c >> 12) & 0x3f);
      view.setUint8(offset++, 0x80 | (c >> 6) & 0x3f);
      view.setUint8(offset++, 0x80 | (c & 0x3f));
    }
  }
}

function utf8Length(str) {
  var c = 0, length = 0;
  for (var i = 0, l = str.length; i < l; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) {
      length += 1;
    }
    else if (c < 0x800) {
      length += 2;
    }
    else if (c < 0xd800 || c >= 0xe000) {
      length += 3;
    }
    else {
      i++;
      length += 4;
    }
  }
  return length;
}

function _encode(bytes, defers, value) {
  var type = typeof value, i = 0, l = 0, hi = 0, lo = 0, length = 0, size = 0;

  if (type === 'string') {
    length = utf8Length(value);

    // fixstr
    if (length < 0x20) {
      bytes.push(length | 0xa0);
      size = 1;
    }
    // str 8
    else if (length < 0x100) {
      bytes.push(0xd9, length);
      size = 2;
    }
    // str 16
    else if (length < 0x10000) {
      bytes.push(0xda, length >> 8, length);
      size = 3;
    }
    // str 32
    else if (length < 0x100000000) {
      bytes.push(0xdb, length >> 24, length >> 16, length >> 8, length);
      size = 5;
    } else {
      throw new Error('String too long');
    }
    defers.push({ _str: value, _length: length, _offset: bytes.length });
    return size + length;
  }
  if (type === 'number') {
    // TODO: encode to float 32?

    // float 64
    if (Math.floor(value) !== value || !isFinite(value)) {
      bytes.push(0xcb);
      defers.push({ _float: value, _length: 8, _offset: bytes.length });
      return 9;
    }

    if (value >= 0) {
      // positive fixnum
      if (value < 0x80) {
        bytes.push(value);
        return 1;
      }
      // uint 8
      if (value < 0x100) {
        bytes.push(0xcc, value);
        return 2;
      }
      // uint 16
      if (value < 0x10000) {
        bytes.push(0xcd, value >> 8, value);
        return 3;
      }
      // uint 32
      if (value < 0x100000000) {
        bytes.push(0xce, value >> 24, value >> 16, value >> 8, value);
        return 5;
      }
      // uint 64
      hi = (value / Math.pow(2, 32)) >> 0;
      lo = value >>> 0;
      bytes.push(0xcf, hi >> 24, hi >> 16, hi >> 8, hi, lo >> 24, lo >> 16, lo >> 8, lo);
      return 9;
    } else {
      // negative fixnum
      if (value >= -0x20) {
        bytes.push(value);
        return 1;
      }
      // int 8
      if (value >= -0x80) {
        bytes.push(0xd0, value);
        return 2;
      }
      // int 16
      if (value >= -0x8000) {
        bytes.push(0xd1, value >> 8, value);
        return 3;
      }
      // int 32
      if (value >= -0x80000000) {
        bytes.push(0xd2, value >> 24, value >> 16, value >> 8, value);
        return 5;
      }
      // int 64
      hi = Math.floor(value / Math.pow(2, 32));
      lo = value >>> 0;
      bytes.push(0xd3, hi >> 24, hi >> 16, hi >> 8, hi, lo >> 24, lo >> 16, lo >> 8, lo);
      return 9;
    }
  }
  if (type === 'object') {
    // nil
    if (value === null) {
      bytes.push(0xc0);
      return 1;
    }

    if (Array.isArray(value)) {
      length = value.length;

      // fixarray
      if (length < 0x10) {
        bytes.push(length | 0x90);
        size = 1;
      }
      // array 16
      else if (length < 0x10000) {
        bytes.push(0xdc, length >> 8, length);
        size = 3;
      }
      // array 32
      else if (length < 0x100000000) {
        bytes.push(0xdd, length >> 24, length >> 16, length >> 8, length);
        size = 5;
      } else {
        throw new Error('Array too large');
      }
      for (i = 0; i < length; i++) {
        size += _encode(bytes, defers, value[i]);
      }
      return size;
    }

    // fixext 8 / Date
    if (value instanceof Date) {
      var time = value.getTime();
      hi = Math.floor(time / Math.pow(2, 32));
      lo = time >>> 0;
      bytes.push(0xd7, 0, hi >> 24, hi >> 16, hi >> 8, hi, lo >> 24, lo >> 16, lo >> 8, lo);
      return 10;
    }

    if (value instanceof ArrayBuffer) {
      length = value.byteLength;

      // bin 8
      if (length < 0x100) {
        bytes.push(0xc4, length);
        size = 2;
      } else
      // bin 16
      if (length < 0x10000) {
        bytes.push(0xc5, length >> 8, length);
        size = 3;
      } else
      // bin 32
      if (length < 0x100000000) {
        bytes.push(0xc6, length >> 24, length >> 16, length >> 8, length);
        size = 5;
      } else {
        throw new Error('Buffer too large');
      }
      defers.push({ _bin: value, _length: length, _offset: bytes.length });
      return size + length;
    }

    if (typeof value.toJSON === 'function') {
      return _encode(bytes, defers, value.toJSON());
    }

    var keys = [], key = '';

    var allKeys = Object.keys(value);
    for (i = 0, l = allKeys.length; i < l; i++) {
      key = allKeys[i];
      if (typeof value[key] !== 'function') {
        keys.push(key);
      }
    }
    length = keys.length;

    // fixmap
    if (length < 0x10) {
      bytes.push(length | 0x80);
      size = 1;
    }
    // map 16
    else if (length < 0x10000) {
      bytes.push(0xde, length >> 8, length);
      size = 3;
    }
    // map 32
    else if (length < 0x100000000) {
      bytes.push(0xdf, length >> 24, length >> 16, length >> 8, length);
      size = 5;
    } else {
      throw new Error('Object too large');
    }

    for (i = 0; i < length; i++) {
      key = keys[i];
      size += _encode(bytes, defers, key);
      size += _encode(bytes, defers, value[key]);
    }
    return size;
  }
  // false/true
  if (type === 'boolean') {
    bytes.push(value ? 0xc3 : 0xc2);
    return 1;
  }
  // fixext 1 / undefined
  if (type === 'undefined') {
    bytes.push(0xd4, 0, 0);
    return 3;
  }
  throw new Error('Could not encode');
}

function encode(value) {
  var bytes = [];
  var defers = [];
  var size = _encode(bytes, defers, value);
  var buf = new ArrayBuffer(size);
  var view = new DataView(buf);

  var deferIndex = 0;
  var deferWritten = 0;
  var nextOffset = -1;
  if (defers.length > 0) {
    nextOffset = defers[0]._offset;
  }

  var defer, deferLength = 0, offset = 0;
  for (var i = 0, l = bytes.length; i < l; i++) {
    view.setUint8(deferWritten + i, bytes[i]);
    if (i + 1 !== nextOffset) { continue; }
    defer = defers[deferIndex];
    deferLength = defer._length;
    offset = deferWritten + nextOffset;
    if (defer._bin) {
      var bin = new Uint8Array(defer._bin);
      for (var j = 0; j < deferLength; j++) {
        view.setUint8(offset + j, bin[j]);
      }
    } else if (defer._str) {
      utf8Write(view, offset, defer._str);
    } else if (defer._float !== undefined) {
      view.setFloat64(offset, defer._float);
    }
    deferIndex++;
    deferWritten += deferLength;
    if (defers[deferIndex]) {
      nextOffset = defers[deferIndex]._offset;
    }
  }
  return buf;
}

module.exports = encode;
","'use strict';

function Decoder(buffer) {
  this._offset = 0;
  if (buffer instanceof ArrayBuffer) {
    this._buffer = buffer;
    this._view = new DataView(this._buffer);
  } else if (ArrayBuffer.isView(buffer)) {
    this._buffer = buffer.buffer;
    this._view = new DataView(this._buffer, buffer.byteOffset, buffer.byteLength);
  } else {
    throw new Error('Invalid argument');
  }
}

function utf8Read(view, offset, length) {
  var string = '', chr = 0;
  for (var i = offset, end = offset + length; i < end; i++) {
    var byte = view.getUint8(i);
    if ((byte & 0x80) === 0x00) {
      string += String.fromCharCode(byte);
      continue;
    }
    if ((byte & 0xe0) === 0xc0) {
      string += String.fromCharCode(
        ((byte & 0x1f) << 6) |
        (view.getUint8(++i) & 0x3f)
      );
      continue;
    }
    if ((byte & 0xf0) === 0xe0) {
      string += String.fromCharCode(
        ((byte & 0x0f) << 12) |
        ((view.getUint8(++i) & 0x3f) << 6) |
        ((view.getUint8(++i) & 0x3f) << 0)
      );
      continue;
    }
    if ((byte & 0xf8) === 0xf0) {
      chr = ((byte & 0x07) << 18) |
        ((view.getUint8(++i) & 0x3f) << 12) |
        ((view.getUint8(++i) & 0x3f) << 6) |
        ((view.getUint8(++i) & 0x3f) << 0);
      if (chr >= 0x010000) { // surrogate pair
        chr -= 0x010000;
        string += String.fromCharCode((chr >>> 10) + 0xD800, (chr & 0x3FF) + 0xDC00);
      } else {
        string += String.fromCharCode(chr);
      }
      continue;
    }
    throw new Error('Invalid byte ' + byte.toString(16));
  }
  return string;
}

Decoder.prototype._array = function (length) {
  var value = new Array(length);
  for (var i = 0; i < length; i++) {
    value[i] = this._parse();
  }
  return value;
};

Decoder.prototype._map = function (length) {
  var key = '', value = {};
  for (var i = 0; i < length; i++) {
    key = this._parse();
    value[key] = this._parse();
  }
  return value;
};

Decoder.prototype._str = function (length) {
  var value = utf8Read(this._view, this._offset, length);
  this._offset += length;
  return value;
};

Decoder.prototype._bin = function (length) {
  var value = this._buffer.slice(this._offset, this._offset + length);
  this._offset += length;
  return value;
};

Decoder.prototype._parse = function () {
  var prefix = this._view.getUint8(this._offset++);
  var value, length = 0, type = 0, hi = 0, lo = 0;

  if (prefix < 0xc0) {
    // positive fixint
    if (prefix < 0x80) {
      return prefix;
    }
    // fixmap
    if (prefix < 0x90) {
      return this._map(prefix & 0x0f);
    }
    // fixarray
    if (prefix < 0xa0) {
      return this._array(prefix & 0x0f);
    }
    // fixstr
    return this._str(prefix & 0x1f);
  }

  // negative fixint
  if (prefix > 0xdf) {
    return (0xff - prefix + 1) * -1;
  }

  switch (prefix) {
    // nil
    case 0xc0:
      return null;
    // false
    case 0xc2:
      return false;
    // true
    case 0xc3:
      return true;

    // bin
    case 0xc4:
      length = this._view.getUint8(this._offset);
      this._offset += 1;
      return this._bin(length);
    case 0xc5:
      length = this._view.getUint16(this._offset);
      this._offset += 2;
      return this._bin(length);
    case 0xc6:
      length = this._view.getUint32(this._offset);
      this._offset += 4;
      return this._bin(length);

    // ext
    case 0xc7:
      length = this._view.getUint8(this._offset);
      type = this._view.getInt8(this._offset + 1);
      this._offset += 2;
      return [type, this._bin(length)];
    case 0xc8:
      length = this._view.getUint16(this._offset);
      type = this._view.getInt8(this._offset + 2);
      this._offset += 3;
      return [type, this._bin(length)];
    case 0xc9:
      length = this._view.getUint32(this._offset);
      type = this._view.getInt8(this._offset + 4);
      this._offset += 5;
      return [type, this._bin(length)];

    // float
    case 0xca:
      value = this._view.getFloat32(this._offset);
      this._offset += 4;
      return value;
    case 0xcb:
      value = this._view.getFloat64(this._offset);
      this._offset += 8;
      return value;

    // uint
    case 0xcc:
      value = this._view.getUint8(this._offset);
      this._offset += 1;
      return value;
    case 0xcd:
      value = this._view.getUint16(this._offset);
      this._offset += 2;
      return value;
    case 0xce:
      value = this._view.getUint32(this._offset);
      this._offset += 4;
      return value;
    case 0xcf:
      hi = this._view.getUint32(this._offset) * Math.pow(2, 32);
      lo = this._view.getUint32(this._offset + 4);
      this._offset += 8;
      return hi + lo;

    // int
    case 0xd0:
      value = this._view.getInt8(this._offset);
      this._offset += 1;
      return value;
    case 0xd1:
      value = this._view.getInt16(this._offset);
      this._offset += 2;
      return value;
    case 0xd2:
      value = this._view.getInt32(this._offset);
      this._offset += 4;
      return value;
    case 0xd3:
      hi = this._view.getInt32(this._offset) * Math.pow(2, 32);
      lo = this._view.getUint32(this._offset + 4);
      this._offset += 8;
      return hi + lo;

    // fixext
    case 0xd4:
      type = this._view.getInt8(this._offset);
      this._offset += 1;
      if (type === 0x00) {
        this._offset += 1;
        return void 0;
      }
      return [type, this._bin(1)];
    case 0xd5:
      type = this._view.getInt8(this._offset);
      this._offset += 1;
      return [type, this._bin(2)];
    case 0xd6:
      type = this._view.getInt8(this._offset);
      this._offset += 1;
      return [type, this._bin(4)];
    case 0xd7:
      type = this._view.getInt8(this._offset);
      this._offset += 1;
      if (type === 0x00) {
        hi = this._view.getInt32(this._offset) * Math.pow(2, 32);
        lo = this._view.getUint32(this._offset + 4);
        this._offset += 8;
        return new Date(hi + lo);
      }
      return [type, this._bin(8)];
    case 0xd8:
      type = this._view.getInt8(this._offset);
      this._offset += 1;
      return [type, this._bin(16)];

    // str
    case 0xd9:
      length = this._view.getUint8(this._offset);
      this._offset += 1;
      return this._str(length);
    case 0xda:
      length = this._view.getUint16(this._offset);
      this._offset += 2;
      return this._str(length);
    case 0xdb:
      length = this._view.getUint32(this._offset);
      this._offset += 4;
      return this._str(length);

    // array
    case 0xdc:
      length = this._view.getUint16(this._offset);
      this._offset += 2;
      return this._array(length);
    case 0xdd:
      length = this._view.getUint32(this._offset);
      this._offset += 4;
      return this._array(length);

    // map
    case 0xde:
      length = this._view.getUint16(this._offset);
      this._offset += 2;
      return this._map(length);
    case 0xdf:
      length = this._view.getUint32(this._offset);
      this._offset += 4;
      return this._map(length);
  }

  throw new Error('Could not parse');
};

function decode(buffer) {
  var decoder = new Decoder(buffer);
  var value = decoder._parse();
  if (decoder._offset !== buffer.byteLength) {
    throw new Error((buffer.byteLength - decoder._offset) + ' trailing bytes');
  }
  return value;
}

module.exports = decode;
","exports.encode = require('./encode');
exports.decode = require('./decode');
","\r
/**\r
 * Expose `Emitter`.\r
 */\r
\r
if (typeof module !== 'undefined') {\r
  module.exports = Emitter;\r
}\r
\r
/**\r
 * Initialize a new `Emitter`.\r
 *\r
 * @api public\r
 */\r
\r
function Emitter(obj) {\r
  if (obj) return mixin(obj);\r
};\r
\r
/**\r
 * Mixin the emitter properties.\r
 *\r
 * @param {Object} obj\r
 * @return {Object}\r
 * @api private\r
 */\r
\r
function mixin(obj) {\r
  for (var key in Emitter.prototype) {\r
    obj[key] = Emitter.prototype[key];\r
  }\r
  return obj;\r
}\r
\r
/**\r
 * Listen on the given `event` with `fn`.\r
 *\r
 * @param {String} event\r
 * @param {Function} fn\r
 * @return {Emitter}\r
 * @api public\r
 */\r
\r
Emitter.prototype.on =\r
Emitter.prototype.addEventListener = function(event, fn){\r
  this._callbacks = this._callbacks || {};\r
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])\r
    .push(fn);\r
  return this;\r
};\r
\r
/**\r
 * Adds an `event` listener that will be invoked a single\r
 * time then automatically removed.\r
 *\r
 * @param {String} event\r
 * @param {Function} fn\r
 * @return {Emitter}\r
 * @api public\r
 */\r
\r
Emitter.prototype.once = function(event, fn){\r
  function on() {\r
    this.off(event, on);\r
    fn.apply(this, arguments);\r
  }\r
\r
  on.fn = fn;\r
  this.on(event, on);\r
  return this;\r
};\r
\r
/**\r
 * Remove the given callback for `event` or all\r
 * registered callbacks.\r
 *\r
 * @param {String} event\r
 * @param {Function} fn\r
 * @return {Emitter}\r
 * @api public\r
 */\r
\r
Emitter.prototype.off =\r
Emitter.prototype.removeListener =\r
Emitter.prototype.removeAllListeners =\r
Emitter.prototype.removeEventListener = function(event, fn){\r
  this._callbacks = this._callbacks || {};\r
\r
  // all\r
  if (0 == arguments.length) {\r
    this._callbacks = {};\r
    return this;\r
  }\r
\r
  // specific event\r
  var callbacks = this._callbacks['$' + event];\r
  if (!callbacks) return this;\r
\r
  // remove all handlers\r
  if (1 == arguments.length) {\r
    delete this._callbacks['$' + event];\r
    return this;\r
  }\r
\r
  // remove specific handler\r
  var cb;\r
  for (var i = 0; i < callbacks.length; i++) {\r
    cb = callbacks[i];\r
    if (cb === fn || cb.fn === fn) {\r
      callbacks.splice(i, 1);\r
      break;\r
    }\r
  }\r
\r
  // Remove event specific arrays for event types that no\r
  // one is subscribed for to avoid memory leak.\r
  if (callbacks.length === 0) {\r
    delete this._callbacks['$' + event];\r
  }\r
\r
  return this;\r
};\r
\r
/**\r
 * Emit `event` with the given args.\r
 *\r
 * @param {String} event\r
 * @param {Mixed} ...\r
 * @return {Emitter}\r
 */\r
\r
Emitter.prototype.emit = function(event){\r
  this._callbacks = this._callbacks || {};\r
\r
  var args = new Array(arguments.length - 1)\r
    , callbacks = this._callbacks['$' + event];\r
\r
  for (var i = 1; i < arguments.length; i++) {\r
    args[i - 1] = arguments[i];\r
  }\r
\r
  if (callbacks) {\r
    callbacks = callbacks.slice(0);\r
    for (var i = 0, len = callbacks.length; i < len; ++i) {\r
      callbacks[i].apply(this, args);\r
    }\r
  }\r
\r
  return this;\r
};\r
\r
/**\r
 * Return array of callbacks for `event`.\r
 *\r
 * @param {String} event\r
 * @return {Array}\r
 * @api public\r
 */\r
\r
Emitter.prototype.listeners = function(event){\r
  this._callbacks = this._callbacks || {};\r
  return this._callbacks['$' + event] || [];\r
};\r
\r
/**\r
 * Check if this emitter has `event` handlers.\r
 *\r
 * @param {String} event\r
 * @return {Boolean}\r
 * @api public\r
 */\r
\r
Emitter.prototype.hasListeners = function(event){\r
  return !! this.listeners(event).length;\r
};\r
","var msgpack = require(\"notepack.io\");
var Emitter = require(\"component-emitter\");

exports.protocol = 5;

/**
 * Packet types (see https://github.com/socketio/socket.io-protocol)
 */

var PacketType = (exports.PacketType = {
  CONNECT: 0,
  DISCONNECT: 1,
  EVENT: 2,
  ACK: 3,
  CONNECT_ERROR: 4,
});

var isInteger =
  Number.isInteger ||
  function (value) {
    return (
      typeof value === \"number\" &&
      isFinite(value) &&
      Math.floor(value) === value
    );
  };

var isString = function (value) {
  return typeof value === \"string\";
};

var isObject = function (value) {
  return Object.prototype.toString.call(value) === \"[object Object]\";
};

function Encoder() {}

Encoder.prototype.encode = function (packet) {
  return [msgpack.encode(packet)];
};

function Decoder() {}

Emitter(Decoder.prototype);

Decoder.prototype.add = function (obj) {
  var decoded = msgpack.decode(obj);
  this.checkPacket(decoded);
  this.emit(\"decoded\", decoded);
};

function isDataValid(decoded) {
  switch (decoded.type) {
    case PacketType.CONNECT:
      return decoded.data === undefined || isObject(decoded.data);
    case PacketType.DISCONNECT:
      return decoded.data === undefined;
    case PacketType.CONNECT_ERROR:
      return isString(decoded.data) || isObject(decoded.data);
    default:
      return Array.isArray(decoded.data);
  }
}

Decoder.prototype.checkPacket = function (decoded) {
  var isTypeValid =
    isInteger(decoded.type) &&
    decoded.type >= PacketType.CONNECT &&
    decoded.type <= PacketType.CONNECT_ERROR;
  if (!isTypeValid) {
    throw new Error(\"invalid packet type\");
  }

  if (!isString(decoded.nsp)) {
    throw new Error(\"invalid namespace\");
  }

  if (!isDataValid(decoded)) {
    throw new Error(\"invalid payload\");
  }

  var isAckValid = decoded.id === undefined || isInteger(decoded.id);
  if (!isAckValid) {
    throw new Error(\"invalid packet id\");
  }
};

Decoder.prototype.destroy = function () {};

exports.Encoder = Encoder;
exports.Decoder = Decoder;
","export function on(obj, ev, fn) {
    obj.on(ev, fn);
    return function subDestroy() {
        obj.off(ev, fn);
    };
}
","import { PacketType } from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
/**
 * Internal events.
 * These events can't be emitted by the user.
 */
const RESERVED_EVENTS = Object.freeze({
    connect: 1,
    connect_error: 1,
    disconnect: 1,
    disconnecting: 1,
    // EventEmitter reserved events: https://nodejs.org/api/events.html#events_event_newlistener
    newListener: 1,
    removeListener: 1,
});
/**
 * A Socket is the fundamental class for interacting with the server.
 *
 * A Socket belongs to a certain Namespace (by default /) and uses an underlying {@link Manager} to communicate.
 *
 * @example
 * const socket = io();
 *
 * socket.on(\"connect\", () => {
 *   console.log(\"connected\");
 * });
 *
 * // send an event to the server
 * socket.emit(\"foo\", \"bar\");
 *
 * socket.on(\"foobar\", () => {
 *   // an event was received from the server
 * });
 *
 * // upon disconnection
 * socket.on(\"disconnect\", (reason) => {
 *   console.log(`disconnected due to ${reason}`);
 * });
 */
export class Socket extends Emitter {
    /**
     * `Socket` constructor.
     */
    constructor(io, nsp, opts) {
        super();
        /**
         * Whether the socket is currently connected to the server.
         *
         * @example
         * const socket = io();
         *
         * socket.on(\"connect\", () => {
         *   console.log(socket.connected); // true
         * });
         *
         * socket.on(\"disconnect\", () => {
         *   console.log(socket.connected); // false
         * });
         */
        this.connected = false;
        /**
         * Whether the connection state was recovered after a temporary disconnection. In that case, any missed packets will
         * be transmitted by the server.
         */
        this.recovered = false;
        /**
         * Buffer for packets received before the CONNECT packet
         */
        this.receiveBuffer = [];
        /**
         * Buffer for packets that will be sent once the socket is connected
         */
        this.sendBuffer = [];
        /**
         * The queue of packets to be sent with retry in case of failure.
         *
         * Packets are sent one by one, each waiting for the server acknowledgement, in order to guarantee the delivery order.
         * @private
         */
        this._queue = [];
        /**
         * A sequence to generate the ID of the {@link QueuedPacket}.
         * @private
         */
        this._queueSeq = 0;
        this.ids = 0;
        this.acks = {};
        this.flags = {};
        this.io = io;
        this.nsp = nsp;
        if (opts && opts.auth) {
            this.auth = opts.auth;
        }
        this._opts = Object.assign({}, opts);
        if (this.io._autoConnect)
            this.open();
    }
    /**
     * Whether the socket is currently disconnected
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"connect\", () => {
     *   console.log(socket.disconnected); // false
     * });
     *
     * socket.on(\"disconnect\", () => {
     *   console.log(socket.disconnected); // true
     * });
     */
    get disconnected() {
        return !this.connected;
    }
    /**
     * Subscribe to open, close and packet events
     *
     * @private
     */
    subEvents() {
        if (this.subs)
            return;
        const io = this.io;
        this.subs = [
            on(io, \"open\", this.onopen.bind(this)),
            on(io, \"packet\", this.onpacket.bind(this)),
            on(io, \"error\", this.onerror.bind(this)),
            on(io, \"close\", this.onclose.bind(this)),
        ];
    }
    /**
     * Whether the Socket will try to reconnect when its Manager connects or reconnects.
     *
     * @example
     * const socket = io();
     *
     * console.log(socket.active); // true
     *
     * socket.on(\"disconnect\", (reason) => {
     *   if (reason === \"io server disconnect\") {
     *     // the disconnection was initiated by the server, you need to manually reconnect
     *     console.log(socket.active); // false
     *   }
     *   // else the socket will automatically try to reconnect
     *   console.log(socket.active); // true
     * });
     */
    get active() {
        return !!this.subs;
    }
    /**
     * \"Opens\" the socket.
     *
     * @example
     * const socket = io({
     *   autoConnect: false
     * });
     *
     * socket.connect();
     */
    connect() {
        if (this.connected)
            return this;
        this.subEvents();
        if (!this.io[\"_reconnecting\"])
            this.io.open(); // ensure open
        if (\"open\" === this.io._readyState)
            this.onopen();
        return this;
    }
    /**
     * Alias for {@link connect()}.
     */
    open() {
        return this.connect();
    }
    /**
     * Sends a `message` event.
     *
     * This method mimics the WebSocket.send() method.
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/send
     *
     * @example
     * socket.send(\"hello\");
     *
     * // this is equivalent to
     * socket.emit(\"message\", \"hello\");
     *
     * @return self
     */
    send(...args) {
        args.unshift(\"message\");
        this.emit.apply(this, args);
        return this;
    }
    /**
     * Override `emit`.
     * If the event is in `events`, it's emitted normally.
     *
     * @example
     * socket.emit(\"hello\", \"world\");
     *
     * // all serializable datastructures are supported (no need to call JSON.stringify)
     * socket.emit(\"hello\", 1, \"2\", { 3: [\"4\"], 5: Uint8Array.from([6]) });
     *
     * // with an acknowledgement from the server
     * socket.emit(\"hello\", \"world\", (val) => {
     *   // ...
     * });
     *
     * @return self
     */
    emit(ev, ...args) {
        if (RESERVED_EVENTS.hasOwnProperty(ev)) {
            throw new Error('\"' + ev.toString() + '\" is a reserved event name');
        }
        args.unshift(ev);
        if (this._opts.retries && !this.flags.fromQueue && !this.flags.volatile) {
            this._addToQueue(args);
            return this;
        }
        const packet = {
            type: PacketType.EVENT,
            data: args,
        };
        packet.options = {};
        packet.options.compress = this.flags.compress !== false;
        // event ack callback
        if (\"function\" === typeof args[args.length - 1]) {
            const id = this.ids++;
            const ack = args.pop();
            this._registerAckCallback(id, ack);
            packet.id = id;
        }
        const isTransportWritable = this.io.engine &&
            this.io.engine.transport &&
            this.io.engine.transport.writable;
        const discardPacket = this.flags.volatile && (!isTransportWritable || !this.connected);
        if (discardPacket) {
        }
        else if (this.connected) {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        }
        else {
            this.sendBuffer.push(packet);
        }
        this.flags = {};
        return this;
    }
    /**
     * @private
     */
    _registerAckCallback(id, ack) {
        var _a;
        const timeout = (_a = this.flags.timeout) !== null && _a !== void 0 ? _a : this._opts.ackTimeout;
        if (timeout === undefined) {
            this.acks[id] = ack;
            return;
        }
        // @ts-ignore
        const timer = this.io.setTimeoutFn(() => {
            delete this.acks[id];
            for (let i = 0; i < this.sendBuffer.length; i++) {
                if (this.sendBuffer[i].id === id) {
                    this.sendBuffer.splice(i, 1);
                }
            }
            ack.call(this, new Error(\"operation has timed out\"));
        }, timeout);
        this.acks[id] = (...args) => {
            // @ts-ignore
            this.io.clearTimeoutFn(timer);
            ack.apply(this, [null, ...args]);
        };
    }
    /**
     * Emits an event and waits for an acknowledgement
     *
     * @example
     * // without timeout
     * const response = await socket.emitWithAck(\"hello\", \"world\");
     *
     * // with a specific timeout
     * try {
     *   const response = await socket.timeout(1000).emitWithAck(\"hello\", \"world\");
     * } catch (err) {
     *   // the server did not acknowledge the event in the given delay
     * }
     *
     * @return a Promise that will be fulfilled when the server acknowledges the event
     */
    emitWithAck(ev, ...args) {
        // the timeout flag is optional
        const withErr = this.flags.timeout !== undefined || this._opts.ackTimeout !== undefined;
        return new Promise((resolve, reject) => {
            args.push((arg1, arg2) => {
                if (withErr) {
                    return arg1 ? reject(arg1) : resolve(arg2);
                }
                else {
                    return resolve(arg1);
                }
            });
            this.emit(ev, ...args);
        });
    }
    /**
     * Add the packet to the queue.
     * @param args
     * @private
     */
    _addToQueue(args) {
        let ack;
        if (typeof args[args.length - 1] === \"function\") {
            ack = args.pop();
        }
        const packet = {
            id: this._queueSeq++,
            tryCount: 0,
            pending: false,
            args,
            flags: Object.assign({ fromQueue: true }, this.flags),
        };
        args.push((err, ...responseArgs) => {
            if (packet !== this._queue[0]) {
                // the packet has already been acknowledged
                return;
            }
            const hasError = err !== null;
            if (hasError) {
                if (packet.tryCount > this._opts.retries) {
                    this._queue.shift();
                    if (ack) {
                        ack(err);
                    }
                }
            }
            else {
                this._queue.shift();
                if (ack) {
                    ack(null, ...responseArgs);
                }
            }
            packet.pending = false;
            return this._drainQueue();
        });
        this._queue.push(packet);
        this._drainQueue();
    }
    /**
     * Send the first packet of the queue, and wait for an acknowledgement from the server.
     * @param force - whether to resend a packet that has not been acknowledged yet
     *
     * @private
     */
    _drainQueue(force = false) {
        if (!this.connected || this._queue.length === 0) {
            return;
        }
        const packet = this._queue[0];
        if (packet.pending && !force) {
            return;
        }
        packet.pending = true;
        packet.tryCount++;
        this.flags = packet.flags;
        this.emit.apply(this, packet.args);
    }
    /**
     * Sends a packet.
     *
     * @param packet
     * @private
     */
    packet(packet) {
        packet.nsp = this.nsp;
        this.io._packet(packet);
    }
    /**
     * Called upon engine `open`.
     *
     * @private
     */
    onopen() {
        if (typeof this.auth == \"function\") {
            this.auth((data) => {
                this._sendConnectPacket(data);
            });
        }
        else {
            this._sendConnectPacket(this.auth);
        }
    }
    /**
     * Sends a CONNECT packet to initiate the Socket.IO session.
     *
     * @param data
     * @private
     */
    _sendConnectPacket(data) {
        this.packet({
            type: PacketType.CONNECT,
            data: this._pid
                ? Object.assign({ pid: this._pid, offset: this._lastOffset }, data)
                : data,
        });
    }
    /**
     * Called upon engine or manager `error`.
     *
     * @param err
     * @private
     */
    onerror(err) {
        if (!this.connected) {
            this.emitReserved(\"connect_error\", err);
        }
    }
    /**
     * Called upon engine `close`.
     *
     * @param reason
     * @param description
     * @private
     */
    onclose(reason, description) {
        this.connected = false;
        delete this.id;
        this.emitReserved(\"disconnect\", reason, description);
    }
    /**
     * Called with socket packet.
     *
     * @param packet
     * @private
     */
    onpacket(packet) {
        const sameNamespace = packet.nsp === this.nsp;
        if (!sameNamespace)
            return;
        switch (packet.type) {
            case PacketType.CONNECT:
                if (packet.data && packet.data.sid) {
                    this.onconnect(packet.data.sid, packet.data.pid);
                }
                else {
                    this.emitReserved(\"connect_error\", new Error(\"It seems you are trying to reach a Socket.IO server in v2.x with a v3.x client, but they are not compatible (more information here: https://socket.io/docs/v3/migrating-from-2-x-to-3-0/)\"));
                }
                break;
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                this.onevent(packet);
                break;
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                this.onack(packet);
                break;
            case PacketType.DISCONNECT:
                this.ondisconnect();
                break;
            case PacketType.CONNECT_ERROR:
                this.destroy();
                const err = new Error(packet.data.message);
                // @ts-ignore
                err.data = packet.data.data;
                this.emitReserved(\"connect_error\", err);
                break;
        }
    }
    /**
     * Called upon a server event.
     *
     * @param packet
     * @private
     */
    onevent(packet) {
        const args = packet.data || [];
        if (null != packet.id) {
            args.push(this.ack(packet.id));
        }
        if (this.connected) {
            this.emitEvent(args);
        }
        else {
            this.receiveBuffer.push(Object.freeze(args));
        }
    }
    emitEvent(args) {
        if (this._anyListeners && this._anyListeners.length) {
            const listeners = this._anyListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, args);
            }
        }
        super.emit.apply(this, args);
        if (this._pid && args.length && typeof args[args.length - 1] === \"string\") {
            this._lastOffset = args[args.length - 1];
        }
    }
    /**
     * Produces an ack callback to emit with an event.
     *
     * @private
     */
    ack(id) {
        const self = this;
        let sent = false;
        return function (...args) {
            // prevent double callbacks
            if (sent)
                return;
            sent = true;
            self.packet({
                type: PacketType.ACK,
                id: id,
                data: args,
            });
        };
    }
    /**
     * Called upon a server acknowlegement.
     *
     * @param packet
     * @private
     */
    onack(packet) {
        const ack = this.acks[packet.id];
        if (\"function\" === typeof ack) {
            ack.apply(this, packet.data);
            delete this.acks[packet.id];
        }
        else {
        }
    }
    /**
     * Called upon server connect.
     *
     * @private
     */
    onconnect(id, pid) {
        this.id = id;
        this.recovered = pid && this._pid === pid;
        this._pid = pid; // defined only if connection state recovery is enabled
        this.connected = true;
        this.emitBuffered();
        this.emitReserved(\"connect\");
        this._drainQueue(true);
    }
    /**
     * Emit buffered events (received and emitted).
     *
     * @private
     */
    emitBuffered() {
        this.receiveBuffer.forEach((args) => this.emitEvent(args));
        this.receiveBuffer = [];
        this.sendBuffer.forEach((packet) => {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        });
        this.sendBuffer = [];
    }
    /**
     * Called upon server disconnect.
     *
     * @private
     */
    ondisconnect() {
        this.destroy();
        this.onclose(\"io server disconnect\");
    }
    /**
     * Called upon forced client/server side disconnections,
     * this method ensures the manager stops tracking us and
     * that reconnections don't get triggered for this.
     *
     * @private
     */
    destroy() {
        if (this.subs) {
            // clean subscriptions to avoid reconnections
            this.subs.forEach((subDestroy) => subDestroy());
            this.subs = undefined;
        }
        this.io[\"_destroy\"](this);
    }
    /**
     * Disconnects the socket manually. In that case, the socket will not try to reconnect.
     *
     * If this is the last active Socket instance of the {@link Manager}, the low-level connection will be closed.
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"disconnect\", (reason) => {
     *   // console.log(reason); prints \"io client disconnect\"
     * });
     *
     * socket.disconnect();
     *
     * @return self
     */
    disconnect() {
        if (this.connected) {
            this.packet({ type: PacketType.DISCONNECT });
        }
        // remove socket from pool
        this.destroy();
        if (this.connected) {
            // fire events
            this.onclose(\"io client disconnect\");
        }
        return this;
    }
    /**
     * Alias for {@link disconnect()}.
     *
     * @return self
     */
    close() {
        return this.disconnect();
    }
    /**
     * Sets the compress flag.
     *
     * @example
     * socket.compress(false).emit(\"hello\");
     *
     * @param compress - if `true`, compresses the sending data
     * @return self
     */
    compress(compress) {
        this.flags.compress = compress;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the event message will be dropped when this socket is not
     * ready to send messages.
     *
     * @example
     * socket.volatile.emit(\"hello\"); // the server may or may not receive it
     *
     * @returns self
     */
    get volatile() {
        this.flags.volatile = true;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the callback will be called with an error when the
     * given number of milliseconds have elapsed without an acknowledgement from the server:
     *
     * @example
     * socket.timeout(5000).emit(\"my-event\", (err) => {
     *   if (err) {
     *     // the server did not acknowledge the event in the given delay
     *   }
     * });
     *
     * @returns self
     */
    timeout(timeout) {
        this.flags.timeout = timeout;
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * @example
     * socket.onAny((event, ...args) => {
     *   console.log(`got ${event}`);
     * });
     *
     * @param listener
     */
    onAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * @example
     * socket.prependAny((event, ...args) => {
     *   console.log(`got event ${event}`);
     * });
     *
     * @param listener
     */
    prependAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`got event ${event}`);
     * }
     *
     * socket.onAny(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAny(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAny();
     *
     * @param listener
     */
    offAny(listener) {
        if (!this._anyListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAny() {
        return this._anyListeners || [];
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.onAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    onAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.prependAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    prependAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`sent event ${event}`);
     * }
     *
     * socket.onAnyOutgoing(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAnyOutgoing(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAnyOutgoing();
     *
     * @param [listener] - the catch-all listener (optional)
     */
    offAnyOutgoing(listener) {
        if (!this._anyOutgoingListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyOutgoingListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyOutgoingListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAnyOutgoing() {
        return this._anyOutgoingListeners || [];
    }
    /**
     * Notify the listeners for each packet sent
     *
     * @param packet
     *
     * @private
     */
    notifyOutgoingListeners(packet) {
        if (this._anyOutgoingListeners && this._anyOutgoingListeners.length) {
            const listeners = this._anyOutgoingListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, packet.data);
            }
        }
    }
}
","/**
 * Initialize backoff timer with `opts`.
 *
 * - `min` initial timeout in milliseconds [100]
 * - `max` max timeout [10000]
 * - `jitter` [0]
 * - `factor` [2]
 *
 * @param {Object} opts
 * @api public
 */
export function Backoff(opts) {
    opts = opts || {};
    this.ms = opts.min || 100;
    this.max = opts.max || 10000;
    this.factor = opts.factor || 2;
    this.jitter = opts.jitter > 0 && opts.jitter <= 1 ? opts.jitter : 0;
    this.attempts = 0;
}
/**
 * Return the backoff duration.
 *
 * @return {Number}
 * @api public
 */
Backoff.prototype.duration = function () {
    var ms = this.ms * Math.pow(this.factor, this.attempts++);
    if (this.jitter) {
        var rand = Math.random();
        var deviation = Math.floor(rand * this.jitter * ms);
        ms = (Math.floor(rand * 10) & 1) == 0 ? ms - deviation : ms + deviation;
    }
    return Math.min(ms, this.max) | 0;
};
/**
 * Reset the number of attempts.
 *
 * @api public
 */
Backoff.prototype.reset = function () {
    this.attempts = 0;
};
/**
 * Set the minimum duration
 *
 * @api public
 */
Backoff.prototype.setMin = function (min) {
    this.ms = min;
};
/**
 * Set the maximum duration
 *
 * @api public
 */
Backoff.prototype.setMax = function (max) {
    this.max = max;
};
/**
 * Set the jitter
 *
 * @api public
 */
Backoff.prototype.setJitter = function (jitter) {
    this.jitter = jitter;
};
","import { Socket as Engine, installTimerFunctions, nextTick, } from \"engine.io-client\";
import { Socket } from \"./socket.js\";
import * as parser from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Backoff } from \"./contrib/backo2.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
export class Manager extends Emitter {
    constructor(uri, opts) {
        var _a;
        super();
        this.nsps = {};
        this.subs = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = undefined;
        }
        opts = opts || {};
        opts.path = opts.path || \"/socket.io\";
        this.opts = opts;
        installTimerFunctions(this, opts);
        this.reconnection(opts.reconnection !== false);
        this.reconnectionAttempts(opts.reconnectionAttempts || Infinity);
        this.reconnectionDelay(opts.reconnectionDelay || 1000);
        this.reconnectionDelayMax(opts.reconnectionDelayMax || 5000);
        this.randomizationFactor((_a = opts.randomizationFactor) !== null && _a !== void 0 ? _a : 0.5);
        this.backoff = new Backoff({
            min: this.reconnectionDelay(),
            max: this.reconnectionDelayMax(),
            jitter: this.randomizationFactor(),
        });
        this.timeout(null == opts.timeout ? 20000 : opts.timeout);
        this._readyState = \"closed\";
        this.uri = uri;
        const _parser = opts.parser || parser;
        this.encoder = new _parser.Encoder();
        this.decoder = new _parser.Decoder();
        this._autoConnect = opts.autoConnect !== false;
        if (this._autoConnect)
            this.open();
    }
    reconnection(v) {
        if (!arguments.length)
            return this._reconnection;
        this._reconnection = !!v;
        return this;
    }
    reconnectionAttempts(v) {
        if (v === undefined)
            return this._reconnectionAttempts;
        this._reconnectionAttempts = v;
        return this;
    }
    reconnectionDelay(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelay;
        this._reconnectionDelay = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMin(v);
        return this;
    }
    randomizationFactor(v) {
        var _a;
        if (v === undefined)
            return this._randomizationFactor;
        this._randomizationFactor = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setJitter(v);
        return this;
    }
    reconnectionDelayMax(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelayMax;
        this._reconnectionDelayMax = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMax(v);
        return this;
    }
    timeout(v) {
        if (!arguments.length)
            return this._timeout;
        this._timeout = v;
        return this;
    }
    /**
     * Starts trying to reconnect if reconnection is enabled and we have not
     * started reconnecting yet
     *
     * @private
     */
    maybeReconnectOnOpen() {
        // Only try to reconnect if it's the first time we're connecting
        if (!this._reconnecting &&
            this._reconnection &&
            this.backoff.attempts === 0) {
            // keeps reconnection from firing twice for the same reconnection loop
            this.reconnect();
        }
    }
    /**
     * Sets the current transport `socket`.
     *
     * @param {Function} fn - optional, callback
     * @return self
     * @public
     */
    open(fn) {
        if (~this._readyState.indexOf(\"open\"))
            return this;
        this.engine = new Engine(this.uri, this.opts);
        const socket = this.engine;
        const self = this;
        this._readyState = \"opening\";
        this.skipReconnect = false;
        // emit `open`
        const openSubDestroy = on(socket, \"open\", function () {
            self.onopen();
            fn && fn();
        });
        // emit `error`
        const errorSub = on(socket, \"error\", (err) => {
            self.cleanup();
            self._readyState = \"closed\";
            this.emitReserved(\"error\", err);
            if (fn) {
                fn(err);
            }
            else {
                // Only do this if there is no fn to handle the error
                self.maybeReconnectOnOpen();
            }
        });
        if (false !== this._timeout) {
            const timeout = this._timeout;
            if (timeout === 0) {
                openSubDestroy(); // prevents a race condition with the 'open' event
            }
            // set timer
            const timer = this.setTimeoutFn(() => {
                openSubDestroy();
                socket.close();
                // @ts-ignore
                socket.emit(\"error\", new Error(\"timeout\"));
            }, timeout);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
        this.subs.push(openSubDestroy);
        this.subs.push(errorSub);
        return this;
    }
    /**
     * Alias for open()
     *
     * @return self
     * @public
     */
    connect(fn) {
        return this.open(fn);
    }
    /**
     * Called upon transport open.
     *
     * @private
     */
    onopen() {
        // clear old subs
        this.cleanup();
        // mark as open
        this._readyState = \"open\";
        this.emitReserved(\"open\");
        // add new subs
        const socket = this.engine;
        this.subs.push(on(socket, \"ping\", this.onping.bind(this)), on(socket, \"data\", this.ondata.bind(this)), on(socket, \"error\", this.onerror.bind(this)), on(socket, \"close\", this.onclose.bind(this)), on(this.decoder, \"decoded\", this.ondecoded.bind(this)));
    }
    /**
     * Called upon a ping.
     *
     * @private
     */
    onping() {
        this.emitReserved(\"ping\");
    }
    /**
     * Called with data.
     *
     * @private
     */
    ondata(data) {
        try {
            this.decoder.add(data);
        }
        catch (e) {
            this.onclose(\"parse error\", e);
        }
    }
    /**
     * Called when parser fully decodes a packet.
     *
     * @private
     */
    ondecoded(packet) {
        // the nextTick call prevents an exception in a user-provided event listener from triggering a disconnection due to a \"parse error\"
        nextTick(() => {
            this.emitReserved(\"packet\", packet);
        }, this.setTimeoutFn);
    }
    /**
     * Called upon socket error.
     *
     * @private
     */
    onerror(err) {
        this.emitReserved(\"error\", err);
    }
    /**
     * Creates a new socket for the given `nsp`.
     *
     * @return {Socket}
     * @public
     */
    socket(nsp, opts) {
        let socket = this.nsps[nsp];
        if (!socket) {
            socket = new Socket(this, nsp, opts);
            this.nsps[nsp] = socket;
        }
        else if (this._autoConnect && !socket.active) {
            socket.connect();
        }
        return socket;
    }
    /**
     * Called upon a socket close.
     *
     * @param socket
     * @private
     */
    _destroy(socket) {
        const nsps = Object.keys(this.nsps);
        for (const nsp of nsps) {
            const socket = this.nsps[nsp];
            if (socket.active) {
                return;
            }
        }
        this._close();
    }
    /**
     * Writes a packet.
     *
     * @param packet
     * @private
     */
    _packet(packet) {
        const encodedPackets = this.encoder.encode(packet);
        for (let i = 0; i < encodedPackets.length; i++) {
            this.engine.write(encodedPackets[i], packet.options);
        }
    }
    /**
     * Clean up transport subscriptions and packet buffer.
     *
     * @private
     */
    cleanup() {
        this.subs.forEach((subDestroy) => subDestroy());
        this.subs.length = 0;
        this.decoder.destroy();
    }
    /**
     * Close the current socket.
     *
     * @private
     */
    _close() {
        this.skipReconnect = true;
        this._reconnecting = false;
        this.onclose(\"forced close\");
        if (this.engine)
            this.engine.close();
    }
    /**
     * Alias for close()
     *
     * @private
     */
    disconnect() {
        return this._close();
    }
    /**
     * Called upon engine close.
     *
     * @private
     */
    onclose(reason, description) {
        this.cleanup();
        this.backoff.reset();
        this._readyState = \"closed\";
        this.emitReserved(\"close\", reason, description);
        if (this._reconnection && !this.skipReconnect) {
            this.reconnect();
        }
    }
    /**
     * Attempt a reconnection.
     *
     * @private
     */
    reconnect() {
        if (this._reconnecting || this.skipReconnect)
            return this;
        const self = this;
        if (this.backoff.attempts >= this._reconnectionAttempts) {
            this.backoff.reset();
            this.emitReserved(\"reconnect_failed\");
            this._reconnecting = false;
        }
        else {
            const delay = this.backoff.duration();
            this._reconnecting = true;
            const timer = this.setTimeoutFn(() => {
                if (self.skipReconnect)
                    return;
                this.emitReserved(\"reconnect_attempt\", self.backoff.attempts);
                // check again for the case socket closed in above events
                if (self.skipReconnect)
                    return;
                self.open((err) => {
                    if (err) {
                        self._reconnecting = false;
                        self.reconnect();
                        this.emitReserved(\"reconnect_error\", err);
                    }
                    else {
                        self.onreconnect();
                    }
                });
            }, delay);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
    }
    /**
     * Called upon successful reconnect.
     *
     * @private
     */
    onreconnect() {
        const attempt = this.backoff.attempts;
        this._reconnecting = false;
        this.backoff.reset();
        this.emitReserved(\"reconnect\", attempt);
    }
}
","import { url } from \"./url.js\";
import { Manager } from \"./manager.js\";
import { Socket } from \"./socket.js\";
/**
 * Managers cache.
 */
const cache = {};
function lookup(uri, opts) {
    if (typeof uri === \"object\") {
        opts = uri;
        uri = undefined;
    }
    opts = opts || {};
    const parsed = url(uri, opts.path || \"/socket.io\");
    const source = parsed.source;
    const id = parsed.id;
    const path = parsed.path;
    const sameNamespace = cache[id] && path in cache[id][\"nsps\"];
    const newConnection = opts.forceNew ||
        opts[\"force new connection\"] ||
        false === opts.multiplex ||
        sameNamespace;
    let io;
    if (newConnection) {
        io = new Manager(source, opts);
    }
    else {
        if (!cache[id]) {
            cache[id] = new Manager(source, opts);
        }
        io = cache[id];
    }
    if (parsed.query && !opts.query) {
        opts.query = parsed.queryKey;
    }
    return io.socket(parsed.path, opts);
}
// so that \"lookup\" can be used both as a function (e.g. `io(...)`) and as a
// namespace (e.g. `io.connect(...)`), for backward compatibility
Object.assign(lookup, {
    Manager,
    Socket,
    io: lookup,
    connect: lookup,
});
/**
 * Protocol version.
 *
 * @public
 */
export { protocol } from \"socket.io-parser\";
/**
 * Expose constructors for standalone build.
 *
 * @public
 */
export { Manager, Socket, lookup as io, lookup as connect, lookup as default, };
","import { parse } from \"engine.io-client\";
/**
 * URL parser.
 *
 * @param uri - url
 * @param path - the request path of the connection
 * @param loc - An object meant to mimic window.location.
 *        Defaults to window.location.
 * @public
 */
export function url(uri, path = \"\", loc) {
    let obj = uri;
    // default to window.location
    loc = loc || (typeof location !== \"undefined\" && location);
    if (null == uri)
        uri = loc.protocol + \"//\" + loc.host;
    // relative path support
    if (typeof uri === \"string\") {
        if (\"/\" === uri.charAt(0)) {
            if (\"/\" === uri.charAt(1)) {
                uri = loc.protocol + uri;
            }
            else {
                uri = loc.host + uri;
            }
        }
        if (!/^(https?|wss?):\\/\\//.test(uri)) {
            if (\"undefined\" !== typeof loc) {
                uri = loc.protocol + \"//\" + uri;
            }
            else {
                uri = \"https://\" + uri;
            }
        }
        // parse
        obj = parse(uri);
    }
    // make sure we treat `localhost:80` and `localhost` equally
    if (!obj.port) {
        if (/^(http|ws)$/.test(obj.protocol)) {
            obj.port = \"80\";
        }
        else if (/^(http|ws)s$/.test(obj.protocol)) {
            obj.port = \"443\";
        }
    }
    obj.path = obj.path || \"/\";
    const ipv6 = obj.host.indexOf(\":\") !== -1;
    const host = ipv6 ? \"[\" + obj.host + \"]\" : obj.host;
    // define unique id
    obj.id = obj.protocol + \"://\" + host + \":\" + obj.port + path;
    // define href
    obj.href =
        obj.protocol +
            \"://\" +
            host +
            (loc && loc.port === obj.port ? \"\" : \":\" + obj.port);
    return obj;
}
"],"names":["PACKET_TYPES","Object","create","PACKET_TYPES_REVERSE","keys","forEach","key","ERROR_PACKET","type","data","withNativeBlob","Blob","prototype","toString","call","withNativeArrayBuffer","ArrayBuffer","encodePacket","supportsBinary","callback","obj","encodeBlobAsBase64","isView","buffer","fileReader","FileReader","onload","content","result","split","readAsDataURL","chars","lookup","Uint8Array","i","length","charCodeAt","decodePacket","encodedPacket","binaryType","mapBinary","charAt","decodeBase64Packet","substring","decoded","base64","encoded1","encoded2","encoded3","encoded4","bufferLength","len","p","arraybuffer","bytes","decode","SEPARATOR","String","fromCharCode","Emitter","mixin","on","addEventListener","event","fn","this","_callbacks","push","Emitter$1","once","off","apply","arguments","removeListener","removeAllListeners","removeEventListener","cb","callbacks","splice","emit","args","Array","slice","emitReserved","listeners","hasListeners","globalThisShim","self","window","Function","pick","_len","attr","_key","reduce","acc","k","hasOwnProperty","NATIVE_SET_TIMEOUT","globalThis","setTimeout","NATIVE_CLEAR_TIMEOUT","clearTimeout","installTimerFunctions","opts","useNativeTimers","setTimeoutFn","bind","clearTimeoutFn","prev","TransportError","reason","description","context","_this","_classCallCheck","_super","Error","Transport","_Emitter","_inherits","_super2","_createSuper","_this2","writable","_assertThisInitialized","query","socket","_createClass","value","_get","_getPrototypeOf","readyState","doOpen","doClose","onClose","packets","write","packet","onPacket","details","onPause","alphabet","map","seed","encode","num","encoded","Math","floor","yeast","now","Date","str","encodeURIComponent","qs","qry","pairs","l","pair","decodeURIComponent","XMLHttpRequest","err","hasCORS","XHR","xdomain","e","concat","join","empty","hasXHR2","responseType","Polling","_Transport","polling","location","isSSL","protocol","port","xd","hostname","xs","secure","forceBase64","get","poll","pause","total","doPoll","_this3","encodedPayload","encodedPackets","decodedPacket","decodePayload","onOpen","_this4","close","_this5","count","encodePayload","doWrite","schema","timestampRequests","timestampParam","sid","b64","Number","encodedQuery","indexOf","path","_extends","Request","uri","_this6","req","request","method","xhrStatus","onError","_this7","onData","pollXhr","_this8","async","undefined","_this9","xscheme","xhr","open","extraHeaders","setDisableHeaderCheck","setRequestHeader","withCredentials","requestTimeout","timeout","onreadystatechange","status","onLoad","send","document","index","requestsCount","requests","cleanup","fromError","abort","responseText","attachEvent","unloadHandler","nextTick","Promise","resolve","then","WebSocket","MozWebSocket","isReactNative","navigator","product","toLowerCase","WS","check","protocols","headers","ws","addEventListeners","onopen","autoUnref","_socket","unref","onclose","closeEvent","onmessage","ev","onerror","_loop","lastPacket","transports","websocket","re","parts","parse","src","b","replace","m","exec","source","host","authority","ipv6uri","pathNames","regx","names","queryKey","$0","$1","$2","Socket","writeBuffer","prevBufferLen","agent","upgrade","rememberUpgrade","addTrailingSlash","rejectUnauthorized","perMessageDeflate","threshold","transportOptions","closeOnBeforeunload","id","upgrades","pingInterval","pingTimeout","pingTimeoutTimer","beforeunloadEventListener","transport","offlineEventListener","name","EIO","priorWebsocketSuccess","createTransport","shift","setTransport","onDrain","failed","onTransportOpen","msg","upgrading","flush","freezeTransport","error","onTransportClose","onupgrade","to","probe","onHandshake","JSON","resetPingTimeout","sendPacket","code","filterUpgrades","maxPayload","getWritablePackets","payloadSize","c","utf8Length","ceil","byteLength","size","options","compress","cleanupAndClose","waitForUpgrade","filteredUpgrades","j","Socket$1","utf8Write","view","offset","setUint8","_encode","defers","hi","lo","_str","_length","_offset","isFinite","pow","_float","isArray","time","getTime","_bin","toJSON","allKeys","encode_1","buf","DataView","deferIndex","deferWritten","nextOffset","defer","deferLength","bin","setFloat64","Decoder","_buffer","_view","byteOffset","_array","_parse","_map","string","chr","end","byte","getUint8","utf8Read","prefix","getUint16","getUint32","getInt8","getFloat32","getFloat64","getInt16","getInt32","decode_1","decoder","lib","require$$0","require$$1","module","exports","msgpack","socket_ioMsgpackParser","PacketType","PacketType_1","CONNECT","DISCONNECT","EVENT","ACK","CONNECT_ERROR","isInteger","isString","isObject","Encoder","add","checkPacket","nsp","isDataValid","destroy","Encoder_1","Decoder_1","RESERVED_EVENTS","freeze","connect","connect_error","disconnect","disconnecting","newListener","io","connected","recovered","receiveBuffer","sendBuffer","_queue","_queueSeq","ids","acks","flags","auth","_opts","_autoConnect","subs","onpacket","subEvents","_readyState","unshift","_len2","_key2","retries","fromQueue","_addToQueue","ack","pop","_registerAckCallback","isTransportWritable","engine","discardPacket","notifyOutgoingListeners","_a","ackTimeout","timer","_len3","_key3","_len4","_key4","withErr","reject","arg1","arg2","tryCount","pending","hasError","_len5","responseArgs","_key5","_drainQueue","force","_packet","_sendConnectPacket","_pid","pid","_lastOffset","onconnect","BINARY_EVENT","onevent","BINARY_ACK","onack","ondisconnect","message","emitEvent","_anyListeners","_step","_iterator","_createForOfIteratorHelper","s","n","done","f","sent","_len6","_key6","emitBuffered","subDestroy","listener","_anyOutgoingListeners","_step2","_iterator2","Backoff","ms","min","max","factor","jitter","attempts","duration","rand","random","deviation","reset","setMin","setMax","setJitter","Manager","nsps","reconnection","reconnectionAttempts","Infinity","reconnectionDelay","reconnectionDelayMax","randomizationFactor","backoff","_parser","parser","encoder","autoConnect","v","_reconnection","_reconnectionAttempts","_reconnectionDelay","_randomizationFactor","_reconnectionDelayMax","_timeout","_reconnecting","reconnect","Engine","skipReconnect","openSubDestroy","errorSub","maybeReconnectOnOpen","onping","ondata","ondecoded","active","_i","_nsps","_close","delay","onreconnect","attempt","cache","_typeof","parsed","loc","test","href","url","sameNamespace","forceNew","multiplex"],"mappings":"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"}
./node_modules/socket.io/client-dist/socket.io.js:  function lookup(uri, opts) {
./node_modules/socket.io/client-dist/socket.io.js.map:{"version":3,"file":"socket.io.js","sources":["../node_modules/engine.io-parser/build/esm/commons.js","../node_modules/engine.io-parser/build/esm/encodePacket.browser.js","../node_modules/engine.io-parser/build/esm/contrib/base64-arraybuffer.js","../node_modules/engine.io-parser/build/esm/decodePacket.browser.js","../node_modules/engine.io-parser/build/esm/index.js","../node_modules/@socket.io/component-emitter/index.mjs","../node_modules/engine.io-client/build/esm/globalThis.browser.js","../node_modules/engine.io-client/build/esm/util.js","../node_modules/engine.io-client/build/esm/transport.js","../node_modules/engine.io-client/build/esm/contrib/yeast.js","../node_modules/engine.io-client/build/esm/contrib/parseqs.js","../node_modules/engine.io-client/build/esm/contrib/has-cors.js","../node_modules/engine.io-client/build/esm/transports/xmlhttprequest.browser.js","../node_modules/engine.io-client/build/esm/transports/polling.js","../node_modules/engine.io-client/build/esm/transports/websocket-constructor.browser.js","../node_modules/engine.io-client/build/esm/transports/websocket.js","../node_modules/engine.io-client/build/esm/transports/index.js","../node_modules/engine.io-client/build/esm/contrib/parseuri.js","../node_modules/engine.io-client/build/esm/socket.js","../node_modules/engine.io-client/build/esm/index.js","../build/esm/url.js","../node_modules/socket.io-parser/build/esm/is-binary.js","../node_modules/socket.io-parser/build/esm/binary.js","../node_modules/socket.io-parser/build/esm/index.js","../build/esm/on.js","../build/esm/socket.js","../build/esm/contrib/backo2.js","../build/esm/manager.js","../build/esm/index.js"],"sourcesContent":["const PACKET_TYPES = Object.create(null); // no Map = no polyfill
PACKET_TYPES[\"open\"] = \"0\";
PACKET_TYPES[\"close\"] = \"1\";
PACKET_TYPES[\"ping\"] = \"2\";
PACKET_TYPES[\"pong\"] = \"3\";
PACKET_TYPES[\"message\"] = \"4\";
PACKET_TYPES[\"upgrade\"] = \"5\";
PACKET_TYPES[\"noop\"] = \"6\";
const PACKET_TYPES_REVERSE = Object.create(null);
Object.keys(PACKET_TYPES).forEach(key => {
    PACKET_TYPES_REVERSE[PACKET_TYPES[key]] = key;
});
const ERROR_PACKET = { type: \"error\", data: \"parser error\" };
export { PACKET_TYPES, PACKET_TYPES_REVERSE, ERROR_PACKET };
","import { PACKET_TYPES } from \"./commons.js\";
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        Object.prototype.toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
// ArrayBuffer.isView method is not defined in IE10
const isView = obj => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj && obj.buffer instanceof ArrayBuffer;
};
const encodePacket = ({ type, data }, supportsBinary, callback) => {
    if (withNativeBlob && data instanceof Blob) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(data, callback);
        }
    }
    else if (withNativeArrayBuffer &&
        (data instanceof ArrayBuffer || isView(data))) {
        if (supportsBinary) {
            return callback(data);
        }
        else {
            return encodeBlobAsBase64(new Blob([data]), callback);
        }
    }
    // plain string
    return callback(PACKET_TYPES[type] + (data || \"\"));
};
const encodeBlobAsBase64 = (data, callback) => {
    const fileReader = new FileReader();
    fileReader.onload = function () {
        const content = fileReader.result.split(\",\")[1];
        callback(\"b\" + content);
    };
    return fileReader.readAsDataURL(data);
};
export default encodePacket;
","const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// Use a lookup table to find the index.
const lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}
export const encode = (arraybuffer) => {
    let bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = '';
    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    if (len % 3 === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    }
    else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    return base64;
};
export const decode = (base64) => {
    let bufferLength = base64.length * 0.75, len = base64.length, i, p = 0, encoded1, encoded2, encoded3, encoded4;
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    const arraybuffer = new ArrayBuffer(bufferLength), bytes = new Uint8Array(arraybuffer);
    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    return arraybuffer;
};
","import { ERROR_PACKET, PACKET_TYPES_REVERSE } from \"./commons.js\";
import { decode } from \"./contrib/base64-arraybuffer.js\";
const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const decodePacket = (encodedPacket, binaryType) => {
    if (typeof encodedPacket !== \"string\") {
        return {
            type: \"message\",
            data: mapBinary(encodedPacket, binaryType)
        };
    }
    const type = encodedPacket.charAt(0);
    if (type === \"b\") {
        return {
            type: \"message\",
            data: decodeBase64Packet(encodedPacket.substring(1), binaryType)
        };
    }
    const packetType = PACKET_TYPES_REVERSE[type];
    if (!packetType) {
        return ERROR_PACKET;
    }
    return encodedPacket.length > 1
        ? {
            type: PACKET_TYPES_REVERSE[type],
            data: encodedPacket.substring(1)
        }
        : {
            type: PACKET_TYPES_REVERSE[type]
        };
};
const decodeBase64Packet = (data, binaryType) => {
    if (withNativeArrayBuffer) {
        const decoded = decode(data);
        return mapBinary(decoded, binaryType);
    }
    else {
        return { base64: true, data }; // fallback for old browsers
    }
};
const mapBinary = (data, binaryType) => {
    switch (binaryType) {
        case \"blob\":
            return data instanceof ArrayBuffer ? new Blob([data]) : data;
        case \"arraybuffer\":
        default:
            return data; // assuming the data is already an ArrayBuffer
    }
};
export default decodePacket;
","import encodePacket from \"./encodePacket.js\";
import decodePacket from \"./decodePacket.js\";
const SEPARATOR = String.fromCharCode(30); // see https://en.wikipedia.org/wiki/Delimiter#ASCII_delimited_text
const encodePayload = (packets, callback) => {
    // some packets may be added to the array while encoding, so the initial length must be saved
    const length = packets.length;
    const encodedPackets = new Array(length);
    let count = 0;
    packets.forEach((packet, i) => {
        // force base64 encoding for binary packets
        encodePacket(packet, false, encodedPacket => {
            encodedPackets[i] = encodedPacket;
            if (++count === length) {
                callback(encodedPackets.join(SEPARATOR));
            }
        });
    });
};
const decodePayload = (encodedPayload, binaryType) => {
    const encodedPackets = encodedPayload.split(SEPARATOR);
    const packets = [];
    for (let i = 0; i < encodedPackets.length; i++) {
        const decodedPacket = decodePacket(encodedPackets[i], binaryType);
        packets.push(decodedPacket);
        if (decodedPacket.type === \"error\") {
            break;
        }
    }
    return packets;
};
export const protocol = 4;
export { encodePacket, encodePayload, decodePacket, decodePayload };
","/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

export function Emitter(obj) {
  if (obj) return mixin(obj);
}

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  function on() {
    this.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks['$' + event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks['$' + event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }

  // Remove event specific arrays for event types that no
  // one is subscribed for to avoid memory leak.
  if (callbacks.length === 0) {
    delete this._callbacks['$' + event];
  }

  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};

  var args = new Array(arguments.length - 1)
    , callbacks = this._callbacks['$' + event];

  for (var i = 1; i < arguments.length; i++) {
    args[i - 1] = arguments[i];
  }

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

// alias used for reserved events (protected method)
Emitter.prototype.emitReserved = Emitter.prototype.emit;

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks['$' + event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};
","export const globalThisShim = (() => {
    if (typeof self !== \"undefined\") {
        return self;
    }
    else if (typeof window !== \"undefined\") {
        return window;
    }
    else {
        return Function(\"return this\")();
    }
})();
","import { globalThisShim as globalThis } from \"./globalThis.js\";
export function pick(obj, ...attr) {
    return attr.reduce((acc, k) => {
        if (obj.hasOwnProperty(k)) {
            acc[k] = obj[k];
        }
        return acc;
    }, {});
}
// Keep a reference to the real timeout functions so they can be used when overridden
const NATIVE_SET_TIMEOUT = globalThis.setTimeout;
const NATIVE_CLEAR_TIMEOUT = globalThis.clearTimeout;
export function installTimerFunctions(obj, opts) {
    if (opts.useNativeTimers) {
        obj.setTimeoutFn = NATIVE_SET_TIMEOUT.bind(globalThis);
        obj.clearTimeoutFn = NATIVE_CLEAR_TIMEOUT.bind(globalThis);
    }
    else {
        obj.setTimeoutFn = globalThis.setTimeout.bind(globalThis);
        obj.clearTimeoutFn = globalThis.clearTimeout.bind(globalThis);
    }
}
// base64 encoded buffers are about 33% bigger (https://en.wikipedia.org/wiki/Base64)
const BASE64_OVERHEAD = 1.33;
// we could also have used `new Blob([obj]).size`, but it isn't supported in IE9
export function byteLength(obj) {
    if (typeof obj === \"string\") {
        return utf8Length(obj);
    }
    // arraybuffer or blob
    return Math.ceil((obj.byteLength || obj.size) * BASE64_OVERHEAD);
}
function utf8Length(str) {
    let c = 0, length = 0;
    for (let i = 0, l = str.length; i < l; i++) {
        c = str.charCodeAt(i);
        if (c < 0x80) {
            length += 1;
        }
        else if (c < 0x800) {
            length += 2;
        }
        else if (c < 0xd800 || c >= 0xe000) {
            length += 3;
        }
        else {
            i++;
            length += 4;
        }
    }
    return length;
}
","import { decodePacket } from \"engine.io-parser\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions } from \"./util.js\";
class TransportError extends Error {
    constructor(reason, description, context) {
        super(reason);
        this.description = description;
        this.context = context;
        this.type = \"TransportError\";
    }
}
export class Transport extends Emitter {
    /**
     * Transport abstract constructor.
     *
     * @param {Object} opts - options
     * @protected
     */
    constructor(opts) {
        super();
        this.writable = false;
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.query = opts.query;
        this.socket = opts.socket;
    }
    /**
     * Emits an error.
     *
     * @param {String} reason
     * @param description
     * @param context - the error context
     * @return {Transport} for chaining
     * @protected
     */
    onError(reason, description, context) {
        super.emitReserved(\"error\", new TransportError(reason, description, context));
        return this;
    }
    /**
     * Opens the transport.
     */
    open() {
        this.readyState = \"opening\";
        this.doOpen();
        return this;
    }
    /**
     * Closes the transport.
     */
    close() {
        if (this.readyState === \"opening\" || this.readyState === \"open\") {
            this.doClose();
            this.onClose();
        }
        return this;
    }
    /**
     * Sends multiple packets.
     *
     * @param {Array} packets
     */
    send(packets) {
        if (this.readyState === \"open\") {
            this.write(packets);
        }
        else {
            // this might happen if the transport was silently closed in the beforeunload event handler
        }
    }
    /**
     * Called upon open
     *
     * @protected
     */
    onOpen() {
        this.readyState = \"open\";
        this.writable = true;
        super.emitReserved(\"open\");
    }
    /**
     * Called with data.
     *
     * @param {String} data
     * @protected
     */
    onData(data) {
        const packet = decodePacket(data, this.socket.binaryType);
        this.onPacket(packet);
    }
    /**
     * Called with a decoded packet.
     *
     * @protected
     */
    onPacket(packet) {
        super.emitReserved(\"packet\", packet);
    }
    /**
     * Called upon close.
     *
     * @protected
     */
    onClose(details) {
        this.readyState = \"closed\";
        super.emitReserved(\"close\", details);
    }
    /**
     * Pauses the transport, in order not to lose packets during an upgrade.
     *
     * @param onPause
     */
    pause(onPause) { }
}
","// imported from https://github.com/unshiftio/yeast
'use strict';
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_'.split(''), length = 64, map = {};
let seed = 0, i = 0, prev;
/**
 * Return a string representing the specified number.
 *
 * @param {Number} num The number to convert.
 * @returns {String} The string representation of the number.
 * @api public
 */
export function encode(num) {
    let encoded = '';
    do {
        encoded = alphabet[num % length] + encoded;
        num = Math.floor(num / length);
    } while (num > 0);
    return encoded;
}
/**
 * Return the integer value specified by the given string.
 *
 * @param {String} str The string to convert.
 * @returns {Number} The integer value represented by the string.
 * @api public
 */
export function decode(str) {
    let decoded = 0;
    for (i = 0; i < str.length; i++) {
        decoded = decoded * length + map[str.charAt(i)];
    }
    return decoded;
}
/**
 * Yeast: A tiny growing id generator.
 *
 * @returns {String} A unique id.
 * @api public
 */
export function yeast() {
    const now = encode(+new Date());
    if (now !== prev)
        return seed = 0, prev = now;
    return now + '.' + encode(seed++);
}
//
// Map each character to its index.
//
for (; i < length; i++)
    map[alphabet[i]] = i;
","// imported from https://github.com/galkn/querystring
/**
 * Compiles a querystring
 * Returns string representation of the object
 *
 * @param {Object}
 * @api private
 */
export function encode(obj) {
    let str = '';
    for (let i in obj) {
        if (obj.hasOwnProperty(i)) {
            if (str.length)
                str += '&';
            str += encodeURIComponent(i) + '=' + encodeURIComponent(obj[i]);
        }
    }
    return str;
}
/**
 * Parses a simple querystring into an object
 *
 * @param {String} qs
 * @api private
 */
export function decode(qs) {
    let qry = {};
    let pairs = qs.split('&');
    for (let i = 0, l = pairs.length; i < l; i++) {
        let pair = pairs[i].split('=');
        qry[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
    }
    return qry;
}
","// imported from https://github.com/component/has-cors
let value = false;
try {
    value = typeof XMLHttpRequest !== 'undefined' &&
        'withCredentials' in new XMLHttpRequest();
}
catch (err) {
    // if XMLHttp support is disabled in IE then it will throw
    // when trying to create
}
export const hasCORS = value;
","// browser shim for xmlhttprequest module
import { hasCORS } from \"../contrib/has-cors.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
export function XHR(opts) {
    const xdomain = opts.xdomain;
    // XMLHttpRequest can be disabled on IE
    try {
        if (\"undefined\" !== typeof XMLHttpRequest && (!xdomain || hasCORS)) {
            return new XMLHttpRequest();
        }
    }
    catch (e) { }
    if (!xdomain) {
        try {
            return new globalThis[[\"Active\"].concat(\"Object\").join(\"X\")](\"Microsoft.XMLHTTP\");
        }
        catch (e) { }
    }
}
","import { Transport } from \"../transport.js\";
import { yeast } from \"../contrib/yeast.js\";
import { encode } from \"../contrib/parseqs.js\";
import { encodePayload, decodePayload } from \"engine.io-parser\";
import { XHR as XMLHttpRequest } from \"./xmlhttprequest.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { installTimerFunctions, pick } from \"../util.js\";
import { globalThisShim as globalThis } from \"../globalThis.js\";
function empty() { }
const hasXHR2 = (function () {
    const xhr = new XMLHttpRequest({
        xdomain: false,
    });
    return null != xhr.responseType;
})();
export class Polling extends Transport {
    /**
     * XHR Polling constructor.
     *
     * @param {Object} opts
     * @package
     */
    constructor(opts) {
        super(opts);
        this.polling = false;
        if (typeof location !== \"undefined\") {
            const isSSL = \"https:\" === location.protocol;
            let port = location.port;
            // some user agents have empty `location.port`
            if (!port) {
                port = isSSL ? \"443\" : \"80\";
            }
            this.xd =
                (typeof location !== \"undefined\" &&
                    opts.hostname !== location.hostname) ||
                    port !== opts.port;
            this.xs = opts.secure !== isSSL;
        }
        /**
         * XHR supports binary
         */
        const forceBase64 = opts && opts.forceBase64;
        this.supportsBinary = hasXHR2 && !forceBase64;
    }
    get name() {
        return \"polling\";
    }
    /**
     * Opens the socket (triggers polling). We write a PING message to determine
     * when the transport is open.
     *
     * @protected
     */
    doOpen() {
        this.poll();
    }
    /**
     * Pauses polling.
     *
     * @param {Function} onPause - callback upon buffers are flushed and transport is paused
     * @package
     */
    pause(onPause) {
        this.readyState = \"pausing\";
        const pause = () => {
            this.readyState = \"paused\";
            onPause();
        };
        if (this.polling || !this.writable) {
            let total = 0;
            if (this.polling) {
                total++;
                this.once(\"pollComplete\", function () {
                    --total || pause();
                });
            }
            if (!this.writable) {
                total++;
                this.once(\"drain\", function () {
                    --total || pause();
                });
            }
        }
        else {
            pause();
        }
    }
    /**
     * Starts polling cycle.
     *
     * @private
     */
    poll() {
        this.polling = true;
        this.doPoll();
        this.emitReserved(\"poll\");
    }
    /**
     * Overloads onData to detect payloads.
     *
     * @protected
     */
    onData(data) {
        const callback = (packet) => {
            // if its the first message we consider the transport open
            if (\"opening\" === this.readyState && packet.type === \"open\") {
                this.onOpen();
            }
            // if its a close packet, we close the ongoing requests
            if (\"close\" === packet.type) {
                this.onClose({ description: \"transport closed by the server\" });
                return false;
            }
            // otherwise bypass onData and handle the message
            this.onPacket(packet);
        };
        // decode payload
        decodePayload(data, this.socket.binaryType).forEach(callback);
        // if an event did not trigger closing
        if (\"closed\" !== this.readyState) {
            // if we got data we're not polling
            this.polling = false;
            this.emitReserved(\"pollComplete\");
            if (\"open\" === this.readyState) {
                this.poll();
            }
            else {
            }
        }
    }
    /**
     * For polling, send a close packet.
     *
     * @protected
     */
    doClose() {
        const close = () => {
            this.write([{ type: \"close\" }]);
        };
        if (\"open\" === this.readyState) {
            close();
        }
        else {
            // in case we're trying to close while
            // handshaking is in progress (GH-164)
            this.once(\"open\", close);
        }
    }
    /**
     * Writes a packets payload.
     *
     * @param {Array} packets - data packets
     * @protected
     */
    write(packets) {
        this.writable = false;
        encodePayload(packets, (data) => {
            this.doWrite(data, () => {
                this.writable = true;
                this.emitReserved(\"drain\");
            });
        });
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"https\" : \"http\";
        let port = \"\";
        // cache busting is forced
        if (false !== this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        if (!this.supportsBinary && !query.sid) {
            query.b64 = 1;
        }
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"https\" === schema && Number(this.opts.port) !== 443) ||
                (\"http\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Creates a request.
     *
     * @param {String} method
     * @private
     */
    request(opts = {}) {
        Object.assign(opts, { xd: this.xd, xs: this.xs }, this.opts);
        return new Request(this.uri(), opts);
    }
    /**
     * Sends data.
     *
     * @param {String} data to send.
     * @param {Function} called upon flush.
     * @private
     */
    doWrite(data, fn) {
        const req = this.request({
            method: \"POST\",
            data: data,
        });
        req.on(\"success\", fn);
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr post error\", xhrStatus, context);
        });
    }
    /**
     * Starts a poll cycle.
     *
     * @private
     */
    doPoll() {
        const req = this.request();
        req.on(\"data\", this.onData.bind(this));
        req.on(\"error\", (xhrStatus, context) => {
            this.onError(\"xhr poll error\", xhrStatus, context);
        });
        this.pollXhr = req;
    }
}
export class Request extends Emitter {
    /**
     * Request constructor
     *
     * @param {Object} options
     * @package
     */
    constructor(uri, opts) {
        super();
        installTimerFunctions(this, opts);
        this.opts = opts;
        this.method = opts.method || \"GET\";
        this.uri = uri;
        this.async = false !== opts.async;
        this.data = undefined !== opts.data ? opts.data : null;
        this.create();
    }
    /**
     * Creates the XHR object and sends the request.
     *
     * @private
     */
    create() {
        const opts = pick(this.opts, \"agent\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"autoUnref\");
        opts.xdomain = !!this.opts.xd;
        opts.xscheme = !!this.opts.xs;
        const xhr = (this.xhr = new XMLHttpRequest(opts));
        try {
            xhr.open(this.method, this.uri, this.async);
            try {
                if (this.opts.extraHeaders) {
                    xhr.setDisableHeaderCheck && xhr.setDisableHeaderCheck(true);
                    for (let i in this.opts.extraHeaders) {
                        if (this.opts.extraHeaders.hasOwnProperty(i)) {
                            xhr.setRequestHeader(i, this.opts.extraHeaders[i]);
                        }
                    }
                }
            }
            catch (e) { }
            if (\"POST\" === this.method) {
                try {
                    xhr.setRequestHeader(\"Content-type\", \"text/plain;charset=UTF-8\");
                }
                catch (e) { }
            }
            try {
                xhr.setRequestHeader(\"Accept\", \"*/*\");
            }
            catch (e) { }
            // ie6 check
            if (\"withCredentials\" in xhr) {
                xhr.withCredentials = this.opts.withCredentials;
            }
            if (this.opts.requestTimeout) {
                xhr.timeout = this.opts.requestTimeout;
            }
            xhr.onreadystatechange = () => {
                if (4 !== xhr.readyState)
                    return;
                if (200 === xhr.status || 1223 === xhr.status) {
                    this.onLoad();
                }
                else {
                    // make sure the `error` event handler that's user-set
                    // does not throw in the same tick and gets caught here
                    this.setTimeoutFn(() => {
                        this.onError(typeof xhr.status === \"number\" ? xhr.status : 0);
                    }, 0);
                }
            };
            xhr.send(this.data);
        }
        catch (e) {
            // Need to defer since .create() is called directly from the constructor
            // and thus the 'error' event can only be only bound *after* this exception
            // occurs.  Therefore, also, we cannot throw here at all.
            this.setTimeoutFn(() => {
                this.onError(e);
            }, 0);
            return;
        }
        if (typeof document !== \"undefined\") {
            this.index = Request.requestsCount++;
            Request.requests[this.index] = this;
        }
    }
    /**
     * Called upon error.
     *
     * @private
     */
    onError(err) {
        this.emitReserved(\"error\", err, this.xhr);
        this.cleanup(true);
    }
    /**
     * Cleans up house.
     *
     * @private
     */
    cleanup(fromError) {
        if (\"undefined\" === typeof this.xhr || null === this.xhr) {
            return;
        }
        this.xhr.onreadystatechange = empty;
        if (fromError) {
            try {
                this.xhr.abort();
            }
            catch (e) { }
        }
        if (typeof document !== \"undefined\") {
            delete Request.requests[this.index];
        }
        this.xhr = null;
    }
    /**
     * Called upon load.
     *
     * @private
     */
    onLoad() {
        const data = this.xhr.responseText;
        if (data !== null) {
            this.emitReserved(\"data\", data);
            this.emitReserved(\"success\");
            this.cleanup();
        }
    }
    /**
     * Aborts the request.
     *
     * @package
     */
    abort() {
        this.cleanup();
    }
}
Request.requestsCount = 0;
Request.requests = {};
/**
 * Aborts pending requests when unloading the window. This is needed to prevent
 * memory leaks (e.g. when using IE) and to ensure that no spurious error is
 * emitted.
 */
if (typeof document !== \"undefined\") {
    // @ts-ignore
    if (typeof attachEvent === \"function\") {
        // @ts-ignore
        attachEvent(\"onunload\", unloadHandler);
    }
    else if (typeof addEventListener === \"function\") {
        const terminationEvent = \"onpagehide\" in globalThis ? \"pagehide\" : \"unload\";
        addEventListener(terminationEvent, unloadHandler, false);
    }
}
function unloadHandler() {
    for (let i in Request.requests) {
        if (Request.requests.hasOwnProperty(i)) {
            Request.requests[i].abort();
        }
    }
}
","import { globalThisShim as globalThis } from \"../globalThis.js\";
export const nextTick = (() => {
    const isPromiseAvailable = typeof Promise === \"function\" && typeof Promise.resolve === \"function\";
    if (isPromiseAvailable) {
        return (cb) => Promise.resolve().then(cb);
    }
    else {
        return (cb, setTimeoutFn) => setTimeoutFn(cb, 0);
    }
})();
export const WebSocket = globalThis.WebSocket || globalThis.MozWebSocket;
export const usingBrowserWebSocket = true;
export const defaultBinaryType = \"arraybuffer\";
","import { Transport } from \"../transport.js\";
import { encode } from \"../contrib/parseqs.js\";
import { yeast } from \"../contrib/yeast.js\";
import { pick } from \"../util.js\";
import { defaultBinaryType, nextTick, usingBrowserWebSocket, WebSocket, } from \"./websocket-constructor.js\";
import { encodePacket } from \"engine.io-parser\";
// detect ReactNative environment
const isReactNative = typeof navigator !== \"undefined\" &&
    typeof navigator.product === \"string\" &&
    navigator.product.toLowerCase() === \"reactnative\";
export class WS extends Transport {
    /**
     * WebSocket transport constructor.
     *
     * @param {Object} opts - connection options
     * @protected
     */
    constructor(opts) {
        super(opts);
        this.supportsBinary = !opts.forceBase64;
    }
    get name() {
        return \"websocket\";
    }
    doOpen() {
        if (!this.check()) {
            // let probe timeout
            return;
        }
        const uri = this.uri();
        const protocols = this.opts.protocols;
        // React Native only supports the 'headers' option, and will print a warning if anything else is passed
        const opts = isReactNative
            ? {}
            : pick(this.opts, \"agent\", \"perMessageDeflate\", \"pfx\", \"key\", \"passphrase\", \"cert\", \"ca\", \"ciphers\", \"rejectUnauthorized\", \"localAddress\", \"protocolVersion\", \"origin\", \"maxPayload\", \"family\", \"checkServerIdentity\");
        if (this.opts.extraHeaders) {
            opts.headers = this.opts.extraHeaders;
        }
        try {
            this.ws =
                usingBrowserWebSocket && !isReactNative
                    ? protocols
                        ? new WebSocket(uri, protocols)
                        : new WebSocket(uri)
                    : new WebSocket(uri, protocols, opts);
        }
        catch (err) {
            return this.emitReserved(\"error\", err);
        }
        this.ws.binaryType = this.socket.binaryType || defaultBinaryType;
        this.addEventListeners();
    }
    /**
     * Adds event listeners to the socket
     *
     * @private
     */
    addEventListeners() {
        this.ws.onopen = () => {
            if (this.opts.autoUnref) {
                this.ws._socket.unref();
            }
            this.onOpen();
        };
        this.ws.onclose = (closeEvent) => this.onClose({
            description: \"websocket connection closed\",
            context: closeEvent,
        });
        this.ws.onmessage = (ev) => this.onData(ev.data);
        this.ws.onerror = (e) => this.onError(\"websocket error\", e);
    }
    write(packets) {
        this.writable = false;
        // encodePacket efficient as it uses WS framing
        // no need for encodePayload
        for (let i = 0; i < packets.length; i++) {
            const packet = packets[i];
            const lastPacket = i === packets.length - 1;
            encodePacket(packet, this.supportsBinary, (data) => {
                // always create a new object (GH-437)
                const opts = {};
                if (!usingBrowserWebSocket) {
                    if (packet.options) {
                        opts.compress = packet.options.compress;
                    }
                    if (this.opts.perMessageDeflate) {
                        const len = 
                        // @ts-ignore
                        \"string\" === typeof data ? Buffer.byteLength(data) : data.length;
                        if (len < this.opts.perMessageDeflate.threshold) {
                            opts.compress = false;
                        }
                    }
                }
                // Sometimes the websocket has already been closed but the browser didn't
                // have a chance of informing us about it yet, in that case send will
                // throw an error
                try {
                    if (usingBrowserWebSocket) {
                        // TypeError is thrown when passing the second argument on Safari
                        this.ws.send(data);
                    }
                    else {
                        this.ws.send(data, opts);
                    }
                }
                catch (e) {
                }
                if (lastPacket) {
                    // fake drain
                    // defer to next tick to allow Socket to clear writeBuffer
                    nextTick(() => {
                        this.writable = true;
                        this.emitReserved(\"drain\");
                    }, this.setTimeoutFn);
                }
            });
        }
    }
    doClose() {
        if (typeof this.ws !== \"undefined\") {
            this.ws.close();
            this.ws = null;
        }
    }
    /**
     * Generates uri for connection.
     *
     * @private
     */
    uri() {
        let query = this.query || {};
        const schema = this.opts.secure ? \"wss\" : \"ws\";
        let port = \"\";
        // avoid port if default for schema
        if (this.opts.port &&
            ((\"wss\" === schema && Number(this.opts.port) !== 443) ||
                (\"ws\" === schema && Number(this.opts.port) !== 80))) {
            port = \":\" + this.opts.port;
        }
        // append timestamp to URI
        if (this.opts.timestampRequests) {
            query[this.opts.timestampParam] = yeast();
        }
        // communicate binary support capabilities
        if (!this.supportsBinary) {
            query.b64 = 1;
        }
        const encodedQuery = encode(query);
        const ipv6 = this.opts.hostname.indexOf(\":\") !== -1;
        return (schema +
            \"://\" +
            (ipv6 ? \"[\" + this.opts.hostname + \"]\" : this.opts.hostname) +
            port +
            this.opts.path +
            (encodedQuery.length ? \"?\" + encodedQuery : \"\"));
    }
    /**
     * Feature detection for WebSocket.
     *
     * @return {Boolean} whether this transport is available.
     * @private
     */
    check() {
        return !!WebSocket;
    }
}
","import { Polling } from \"./polling.js\";
import { WS } from \"./websocket.js\";
export const transports = {
    websocket: WS,
    polling: Polling,
};
","// imported from https://github.com/galkn/parseuri
/**
 * Parses a URI
 *
 * Note: we could also have used the built-in URL object, but it isn't supported on all platforms.
 *
 * See:
 * - https://developer.mozilla.org/en-US/docs/Web/API/URL
 * - https://caniuse.com/url
 * - https://www.rfc-editor.org/rfc/rfc3986#appendix-B
 *
 * History of the parse() method:
 * - first commit: https://github.com/socketio/socket.io-client/commit/4ee1d5d94b3906a9c052b459f1a818b15f38f91c
 * - export into its own module: https://github.com/socketio/engine.io-client/commit/de2c561e4564efeb78f1bdb1ba39ef81b2822cb3
 * - reimport: https://github.com/socketio/engine.io-client/commit/df32277c3f6d622eec5ed09f493cae3f3391d242
 *
 * @author Steven Levithan <stevenlevithan.com> (MIT license)
 * @api private
 */
const re = /^(?:(?![^:@\\/?#]+:[^:@\\/]*@)(http|https|ws|wss):\\/\\/)?((?:(([^:@\\/?#]*)(?::([^:@\\/?#]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\\/?#]*)(?::(\\d*))?)(((\\/(?:[^?#](?![^?#\\/]*\\.[^?#\\/.]+(?:[?#]|$)))*\\/?)?([^?#\\/]*))(?:\\?([^#]*))?(?:#(.*))?)/;
const parts = [
    'source', 'protocol', 'authority', 'userInfo', 'user', 'password', 'host', 'port', 'relative', 'path', 'directory', 'file', 'query', 'anchor'
];
export function parse(str) {
    const src = str, b = str.indexOf('['), e = str.indexOf(']');
    if (b != -1 && e != -1) {
        str = str.substring(0, b) + str.substring(b, e).replace(/:/g, ';') + str.substring(e, str.length);
    }
    let m = re.exec(str || ''), uri = {}, i = 14;
    while (i--) {
        uri[parts[i]] = m[i] || '';
    }
    if (b != -1 && e != -1) {
        uri.source = src;
        uri.host = uri.host.substring(1, uri.host.length - 1).replace(/;/g, ':');
        uri.authority = uri.authority.replace('[', '').replace(']', '').replace(/;/g, ':');
        uri.ipv6uri = true;
    }
    uri.pathNames = pathNames(uri, uri['path']);
    uri.queryKey = queryKey(uri, uri['query']);
    return uri;
}
function pathNames(obj, path) {
    const regx = /\\/{2,9}/g, names = path.replace(regx, \"/\").split(\"/\");
    if (path.slice(0, 1) == '/' || path.length === 0) {
        names.splice(0, 1);
    }
    if (path.slice(-1) == '/') {
        names.splice(names.length - 1, 1);
    }
    return names;
}
function queryKey(uri, query) {
    const data = {};
    query.replace(/(?:^|&)([^&=]*)=?([^&]*)/g, function ($0, $1, $2) {
        if ($1) {
            data[$1] = $2;
        }
    });
    return data;
}
","import { transports } from \"./transports/index.js\";
import { installTimerFunctions, byteLength } from \"./util.js\";
import { decode } from \"./contrib/parseqs.js\";
import { parse } from \"./contrib/parseuri.js\";
import { Emitter } from \"@socket.io/component-emitter\";
import { protocol } from \"engine.io-parser\";
export class Socket extends Emitter {
    /**
     * Socket constructor.
     *
     * @param {String|Object} uri - uri or options
     * @param {Object} opts - options
     */
    constructor(uri, opts = {}) {
        super();
        this.writeBuffer = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = null;
        }
        if (uri) {
            uri = parse(uri);
            opts.hostname = uri.host;
            opts.secure = uri.protocol === \"https\" || uri.protocol === \"wss\";
            opts.port = uri.port;
            if (uri.query)
                opts.query = uri.query;
        }
        else if (opts.host) {
            opts.hostname = parse(opts.host).host;
        }
        installTimerFunctions(this, opts);
        this.secure =
            null != opts.secure
                ? opts.secure
                : typeof location !== \"undefined\" && \"https:\" === location.protocol;
        if (opts.hostname && !opts.port) {
            // if no port is specified manually, use the protocol default
            opts.port = this.secure ? \"443\" : \"80\";
        }
        this.hostname =
            opts.hostname ||
                (typeof location !== \"undefined\" ? location.hostname : \"localhost\");
        this.port =
            opts.port ||
                (typeof location !== \"undefined\" && location.port
                    ? location.port
                    : this.secure
                        ? \"443\"
                        : \"80\");
        this.transports = opts.transports || [\"polling\", \"websocket\"];
        this.writeBuffer = [];
        this.prevBufferLen = 0;
        this.opts = Object.assign({
            path: \"/engine.io\",
            agent: false,
            withCredentials: false,
            upgrade: true,
            timestampParam: \"t\",
            rememberUpgrade: false,
            addTrailingSlash: true,
            rejectUnauthorized: true,
            perMessageDeflate: {
                threshold: 1024,
            },
            transportOptions: {},
            closeOnBeforeunload: true,
        }, opts);
        this.opts.path =
            this.opts.path.replace(/\\/$/, \"\") +
                (this.opts.addTrailingSlash ? \"/\" : \"\");
        if (typeof this.opts.query === \"string\") {
            this.opts.query = decode(this.opts.query);
        }
        // set on handshake
        this.id = null;
        this.upgrades = null;
        this.pingInterval = null;
        this.pingTimeout = null;
        // set on heartbeat
        this.pingTimeoutTimer = null;
        if (typeof addEventListener === \"function\") {
            if (this.opts.closeOnBeforeunload) {
                // Firefox closes the connection when the \"beforeunload\" event is emitted but not Chrome. This event listener
                // ensures every browser behaves the same (no \"disconnect\" event at the Socket.IO level when the page is
                // closed/reloaded)
                this.beforeunloadEventListener = () => {
                    if (this.transport) {
                        // silently close the transport
                        this.transport.removeAllListeners();
                        this.transport.close();
                    }
                };
                addEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
            }
            if (this.hostname !== \"localhost\") {
                this.offlineEventListener = () => {
                    this.onClose(\"transport close\", {
                        description: \"network connection lost\",
                    });
                };
                addEventListener(\"offline\", this.offlineEventListener, false);
            }
        }
        this.open();
    }
    /**
     * Creates transport of the given type.
     *
     * @param {String} name - transport name
     * @return {Transport}
     * @private
     */
    createTransport(name) {
        const query = Object.assign({}, this.opts.query);
        // append engine.io protocol identifier
        query.EIO = protocol;
        // transport name
        query.transport = name;
        // session id if we already have one
        if (this.id)
            query.sid = this.id;
        const opts = Object.assign({}, this.opts.transportOptions[name], this.opts, {
            query,
            socket: this,
            hostname: this.hostname,
            secure: this.secure,
            port: this.port,
        });
        return new transports[name](opts);
    }
    /**
     * Initializes transport to use and starts probe.
     *
     * @private
     */
    open() {
        let transport;
        if (this.opts.rememberUpgrade &&
            Socket.priorWebsocketSuccess &&
            this.transports.indexOf(\"websocket\") !== -1) {
            transport = \"websocket\";
        }
        else if (0 === this.transports.length) {
            // Emit error on next tick so it can be listened to
            this.setTimeoutFn(() => {
                this.emitReserved(\"error\", \"No transports available\");
            }, 0);
            return;
        }
        else {
            transport = this.transports[0];
        }
        this.readyState = \"opening\";
        // Retry with the next transport if the transport is disabled (jsonp: false)
        try {
            transport = this.createTransport(transport);
        }
        catch (e) {
            this.transports.shift();
            this.open();
            return;
        }
        transport.open();
        this.setTransport(transport);
    }
    /**
     * Sets the current transport. Disables the existing one (if any).
     *
     * @private
     */
    setTransport(transport) {
        if (this.transport) {
            this.transport.removeAllListeners();
        }
        // set up transport
        this.transport = transport;
        // set up transport listeners
        transport
            .on(\"drain\", this.onDrain.bind(this))
            .on(\"packet\", this.onPacket.bind(this))
            .on(\"error\", this.onError.bind(this))
            .on(\"close\", (reason) => this.onClose(\"transport close\", reason));
    }
    /**
     * Probes a transport.
     *
     * @param {String} name - transport name
     * @private
     */
    probe(name) {
        let transport = this.createTransport(name);
        let failed = false;
        Socket.priorWebsocketSuccess = false;
        const onTransportOpen = () => {
            if (failed)
                return;
            transport.send([{ type: \"ping\", data: \"probe\" }]);
            transport.once(\"packet\", (msg) => {
                if (failed)
                    return;
                if (\"pong\" === msg.type && \"probe\" === msg.data) {
                    this.upgrading = true;
                    this.emitReserved(\"upgrading\", transport);
                    if (!transport)
                        return;
                    Socket.priorWebsocketSuccess = \"websocket\" === transport.name;
                    this.transport.pause(() => {
                        if (failed)
                            return;
                        if (\"closed\" === this.readyState)
                            return;
                        cleanup();
                        this.setTransport(transport);
                        transport.send([{ type: \"upgrade\" }]);
                        this.emitReserved(\"upgrade\", transport);
                        transport = null;
                        this.upgrading = false;
                        this.flush();
                    });
                }
                else {
                    const err = new Error(\"probe error\");
                    // @ts-ignore
                    err.transport = transport.name;
                    this.emitReserved(\"upgradeError\", err);
                }
            });
        };
        function freezeTransport() {
            if (failed)
                return;
            // Any callback called by transport should be ignored since now
            failed = true;
            cleanup();
            transport.close();
            transport = null;
        }
        // Handle any error that happens while probing
        const onerror = (err) => {
            const error = new Error(\"probe error: \" + err);
            // @ts-ignore
            error.transport = transport.name;
            freezeTransport();
            this.emitReserved(\"upgradeError\", error);
        };
        function onTransportClose() {
            onerror(\"transport closed\");
        }
        // When the socket is closed while we're probing
        function onclose() {
            onerror(\"socket closed\");
        }
        // When the socket is upgraded while we're probing
        function onupgrade(to) {
            if (transport && to.name !== transport.name) {
                freezeTransport();
            }
        }
        // Remove all listeners on the transport and on self
        const cleanup = () => {
            transport.removeListener(\"open\", onTransportOpen);
            transport.removeListener(\"error\", onerror);
            transport.removeListener(\"close\", onTransportClose);
            this.off(\"close\", onclose);
            this.off(\"upgrading\", onupgrade);
        };
        transport.once(\"open\", onTransportOpen);
        transport.once(\"error\", onerror);
        transport.once(\"close\", onTransportClose);
        this.once(\"close\", onclose);
        this.once(\"upgrading\", onupgrade);
        transport.open();
    }
    /**
     * Called when connection is deemed open.
     *
     * @private
     */
    onOpen() {
        this.readyState = \"open\";
        Socket.priorWebsocketSuccess = \"websocket\" === this.transport.name;
        this.emitReserved(\"open\");
        this.flush();
        // we check for `readyState` in case an `open`
        // listener already closed the socket
        if (\"open\" === this.readyState && this.opts.upgrade) {
            let i = 0;
            const l = this.upgrades.length;
            for (; i < l; i++) {
                this.probe(this.upgrades[i]);
            }
        }
    }
    /**
     * Handles a packet.
     *
     * @private
     */
    onPacket(packet) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            this.emitReserved(\"packet\", packet);
            // Socket is live - any packet counts
            this.emitReserved(\"heartbeat\");
            switch (packet.type) {
                case \"open\":
                    this.onHandshake(JSON.parse(packet.data));
                    break;
                case \"ping\":
                    this.resetPingTimeout();
                    this.sendPacket(\"pong\");
                    this.emitReserved(\"ping\");
                    this.emitReserved(\"pong\");
                    break;
                case \"error\":
                    const err = new Error(\"server error\");
                    // @ts-ignore
                    err.code = packet.data;
                    this.onError(err);
                    break;
                case \"message\":
                    this.emitReserved(\"data\", packet.data);
                    this.emitReserved(\"message\", packet.data);
                    break;
            }
        }
        else {
        }
    }
    /**
     * Called upon handshake completion.
     *
     * @param {Object} data - handshake obj
     * @private
     */
    onHandshake(data) {
        this.emitReserved(\"handshake\", data);
        this.id = data.sid;
        this.transport.query.sid = data.sid;
        this.upgrades = this.filterUpgrades(data.upgrades);
        this.pingInterval = data.pingInterval;
        this.pingTimeout = data.pingTimeout;
        this.maxPayload = data.maxPayload;
        this.onOpen();
        // In case open handler closes socket
        if (\"closed\" === this.readyState)
            return;
        this.resetPingTimeout();
    }
    /**
     * Sets and resets ping timeout timer based on server pings.
     *
     * @private
     */
    resetPingTimeout() {
        this.clearTimeoutFn(this.pingTimeoutTimer);
        this.pingTimeoutTimer = this.setTimeoutFn(() => {
            this.onClose(\"ping timeout\");
        }, this.pingInterval + this.pingTimeout);
        if (this.opts.autoUnref) {
            this.pingTimeoutTimer.unref();
        }
    }
    /**
     * Called on `drain` event
     *
     * @private
     */
    onDrain() {
        this.writeBuffer.splice(0, this.prevBufferLen);
        // setting prevBufferLen = 0 is very important
        // for example, when upgrading, upgrade packet is sent over,
        // and a nonzero prevBufferLen could cause problems on `drain`
        this.prevBufferLen = 0;
        if (0 === this.writeBuffer.length) {
            this.emitReserved(\"drain\");
        }
        else {
            this.flush();
        }
    }
    /**
     * Flush write buffers.
     *
     * @private
     */
    flush() {
        if (\"closed\" !== this.readyState &&
            this.transport.writable &&
            !this.upgrading &&
            this.writeBuffer.length) {
            const packets = this.getWritablePackets();
            this.transport.send(packets);
            // keep track of current length of writeBuffer
            // splice writeBuffer and callbackBuffer on `drain`
            this.prevBufferLen = packets.length;
            this.emitReserved(\"flush\");
        }
    }
    /**
     * Ensure the encoded size of the writeBuffer is below the maxPayload value sent by the server (only for HTTP
     * long-polling)
     *
     * @private
     */
    getWritablePackets() {
        const shouldCheckPayloadSize = this.maxPayload &&
            this.transport.name === \"polling\" &&
            this.writeBuffer.length > 1;
        if (!shouldCheckPayloadSize) {
            return this.writeBuffer;
        }
        let payloadSize = 1; // first packet type
        for (let i = 0; i < this.writeBuffer.length; i++) {
            const data = this.writeBuffer[i].data;
            if (data) {
                payloadSize += byteLength(data);
            }
            if (i > 0 && payloadSize > this.maxPayload) {
                return this.writeBuffer.slice(0, i);
            }
            payloadSize += 2; // separator + packet type
        }
        return this.writeBuffer;
    }
    /**
     * Sends a message.
     *
     * @param {String} msg - message.
     * @param {Object} options.
     * @param {Function} callback function.
     * @return {Socket} for chaining.
     */
    write(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    send(msg, options, fn) {
        this.sendPacket(\"message\", msg, options, fn);
        return this;
    }
    /**
     * Sends a packet.
     *
     * @param {String} type: packet type.
     * @param {String} data.
     * @param {Object} options.
     * @param {Function} fn - callback function.
     * @private
     */
    sendPacket(type, data, options, fn) {
        if (\"function\" === typeof data) {
            fn = data;
            data = undefined;
        }
        if (\"function\" === typeof options) {
            fn = options;
            options = null;
        }
        if (\"closing\" === this.readyState || \"closed\" === this.readyState) {
            return;
        }
        options = options || {};
        options.compress = false !== options.compress;
        const packet = {
            type: type,
            data: data,
            options: options,
        };
        this.emitReserved(\"packetCreate\", packet);
        this.writeBuffer.push(packet);
        if (fn)
            this.once(\"flush\", fn);
        this.flush();
    }
    /**
     * Closes the connection.
     */
    close() {
        const close = () => {
            this.onClose(\"forced close\");
            this.transport.close();
        };
        const cleanupAndClose = () => {
            this.off(\"upgrade\", cleanupAndClose);
            this.off(\"upgradeError\", cleanupAndClose);
            close();
        };
        const waitForUpgrade = () => {
            // wait for upgrade to finish since we can't send packets while pausing a transport
            this.once(\"upgrade\", cleanupAndClose);
            this.once(\"upgradeError\", cleanupAndClose);
        };
        if (\"opening\" === this.readyState || \"open\" === this.readyState) {
            this.readyState = \"closing\";
            if (this.writeBuffer.length) {
                this.once(\"drain\", () => {
                    if (this.upgrading) {
                        waitForUpgrade();
                    }
                    else {
                        close();
                    }
                });
            }
            else if (this.upgrading) {
                waitForUpgrade();
            }
            else {
                close();
            }
        }
        return this;
    }
    /**
     * Called upon transport error
     *
     * @private
     */
    onError(err) {
        Socket.priorWebsocketSuccess = false;
        this.emitReserved(\"error\", err);
        this.onClose(\"transport error\", err);
    }
    /**
     * Called upon transport close.
     *
     * @private
     */
    onClose(reason, description) {
        if (\"opening\" === this.readyState ||
            \"open\" === this.readyState ||
            \"closing\" === this.readyState) {
            // clear timers
            this.clearTimeoutFn(this.pingTimeoutTimer);
            // stop event from firing again for transport
            this.transport.removeAllListeners(\"close\");
            // ensure transport won't stay open
            this.transport.close();
            // ignore further transport communication
            this.transport.removeAllListeners();
            if (typeof removeEventListener === \"function\") {
                removeEventListener(\"beforeunload\", this.beforeunloadEventListener, false);
                removeEventListener(\"offline\", this.offlineEventListener, false);
            }
            // set ready state
            this.readyState = \"closed\";
            // clear session id
            this.id = null;
            // emit close event
            this.emitReserved(\"close\", reason, description);
            // clean buffers after, so users can still
            // grab the buffers on `close` event
            this.writeBuffer = [];
            this.prevBufferLen = 0;
        }
    }
    /**
     * Filters upgrades, returning only those matching client transports.
     *
     * @param {Array} upgrades - server upgrades
     * @private
     */
    filterUpgrades(upgrades) {
        const filteredUpgrades = [];
        let i = 0;
        const j = upgrades.length;
        for (; i < j; i++) {
            if (~this.transports.indexOf(upgrades[i]))
                filteredUpgrades.push(upgrades[i]);
        }
        return filteredUpgrades;
    }
}
Socket.protocol = protocol;
","import { Socket } from \"./socket.js\";
export { Socket };
export const protocol = Socket.protocol;
export { Transport } from \"./transport.js\";
export { transports } from \"./transports/index.js\";
export { installTimerFunctions } from \"./util.js\";
export { parse } from \"./contrib/parseuri.js\";
export { nextTick } from \"./transports/websocket-constructor.js\";
","import { parse } from \"engine.io-client\";
/**
 * URL parser.
 *
 * @param uri - url
 * @param path - the request path of the connection
 * @param loc - An object meant to mimic window.location.
 *        Defaults to window.location.
 * @public
 */
export function url(uri, path = \"\", loc) {
    let obj = uri;
    // default to window.location
    loc = loc || (typeof location !== \"undefined\" && location);
    if (null == uri)
        uri = loc.protocol + \"//\" + loc.host;
    // relative path support
    if (typeof uri === \"string\") {
        if (\"/\" === uri.charAt(0)) {
            if (\"/\" === uri.charAt(1)) {
                uri = loc.protocol + uri;
            }
            else {
                uri = loc.host + uri;
            }
        }
        if (!/^(https?|wss?):\\/\\//.test(uri)) {
            if (\"undefined\" !== typeof loc) {
                uri = loc.protocol + \"//\" + uri;
            }
            else {
                uri = \"https://\" + uri;
            }
        }
        // parse
        obj = parse(uri);
    }
    // make sure we treat `localhost:80` and `localhost` equally
    if (!obj.port) {
        if (/^(http|ws)$/.test(obj.protocol)) {
            obj.port = \"80\";
        }
        else if (/^(http|ws)s$/.test(obj.protocol)) {
            obj.port = \"443\";
        }
    }
    obj.path = obj.path || \"/\";
    const ipv6 = obj.host.indexOf(\":\") !== -1;
    const host = ipv6 ? \"[\" + obj.host + \"]\" : obj.host;
    // define unique id
    obj.id = obj.protocol + \"://\" + host + \":\" + obj.port + path;
    // define href
    obj.href =
        obj.protocol +
            \"://\" +
            host +
            (loc && loc.port === obj.port ? \"\" : \":\" + obj.port);
    return obj;
}
","const withNativeArrayBuffer = typeof ArrayBuffer === \"function\";
const isView = (obj) => {
    return typeof ArrayBuffer.isView === \"function\"
        ? ArrayBuffer.isView(obj)
        : obj.buffer instanceof ArrayBuffer;
};
const toString = Object.prototype.toString;
const withNativeBlob = typeof Blob === \"function\" ||
    (typeof Blob !== \"undefined\" &&
        toString.call(Blob) === \"[object BlobConstructor]\");
const withNativeFile = typeof File === \"function\" ||
    (typeof File !== \"undefined\" &&
        toString.call(File) === \"[object FileConstructor]\");
/**
 * Returns true if obj is a Buffer, an ArrayBuffer, a Blob or a File.
 *
 * @private
 */
export function isBinary(obj) {
    return ((withNativeArrayBuffer && (obj instanceof ArrayBuffer || isView(obj))) ||
        (withNativeBlob && obj instanceof Blob) ||
        (withNativeFile && obj instanceof File));
}
export function hasBinary(obj, toJSON) {
    if (!obj || typeof obj !== \"object\") {
        return false;
    }
    if (Array.isArray(obj)) {
        for (let i = 0, l = obj.length; i < l; i++) {
            if (hasBinary(obj[i])) {
                return true;
            }
        }
        return false;
    }
    if (isBinary(obj)) {
        return true;
    }
    if (obj.toJSON &&
        typeof obj.toJSON === \"function\" &&
        arguments.length === 1) {
        return hasBinary(obj.toJSON(), true);
    }
    for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key) && hasBinary(obj[key])) {
            return true;
        }
    }
    return false;
}
","import { isBinary } from \"./is-binary.js\";
/**
 * Replaces every Buffer | ArrayBuffer | Blob | File in packet with a numbered placeholder.
 *
 * @param {Object} packet - socket.io event packet
 * @return {Object} with deconstructed packet and list of buffers
 * @public
 */
export function deconstructPacket(packet) {
    const buffers = [];
    const packetData = packet.data;
    const pack = packet;
    pack.data = _deconstructPacket(packetData, buffers);
    pack.attachments = buffers.length; // number of binary 'attachments'
    return { packet: pack, buffers: buffers };
}
function _deconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (isBinary(data)) {
        const placeholder = { _placeholder: true, num: buffers.length };
        buffers.push(data);
        return placeholder;
    }
    else if (Array.isArray(data)) {
        const newData = new Array(data.length);
        for (let i = 0; i < data.length; i++) {
            newData[i] = _deconstructPacket(data[i], buffers);
        }
        return newData;
    }
    else if (typeof data === \"object\" && !(data instanceof Date)) {
        const newData = {};
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                newData[key] = _deconstructPacket(data[key], buffers);
            }
        }
        return newData;
    }
    return data;
}
/**
 * Reconstructs a binary packet from its placeholder packet and buffers
 *
 * @param {Object} packet - event packet with placeholders
 * @param {Array} buffers - binary buffers to put in placeholder positions
 * @return {Object} reconstructed packet
 * @public
 */
export function reconstructPacket(packet, buffers) {
    packet.data = _reconstructPacket(packet.data, buffers);
    delete packet.attachments; // no longer useful
    return packet;
}
function _reconstructPacket(data, buffers) {
    if (!data)
        return data;
    if (data && data._placeholder === true) {
        const isIndexValid = typeof data.num === \"number\" &&
            data.num >= 0 &&
            data.num < buffers.length;
        if (isIndexValid) {
            return buffers[data.num]; // appropriate buffer (should be natural order anyway)
        }
        else {
            throw new Error(\"illegal attachments\");
        }
    }
    else if (Array.isArray(data)) {
        for (let i = 0; i < data.length; i++) {
            data[i] = _reconstructPacket(data[i], buffers);
        }
    }
    else if (typeof data === \"object\") {
        for (const key in data) {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                data[key] = _reconstructPacket(data[key], buffers);
            }
        }
    }
    return data;
}
","import { Emitter } from \"@socket.io/component-emitter\";
import { deconstructPacket, reconstructPacket } from \"./binary.js\";
import { isBinary, hasBinary } from \"./is-binary.js\";
/**
 * These strings must not be used as event names, as they have a special meaning.
 */
const RESERVED_EVENTS = [
    \"connect\",
    \"connect_error\",
    \"disconnect\",
    \"disconnecting\",
    \"newListener\",
    \"removeListener\", // used by the Node.js EventEmitter
];
/**
 * Protocol version.
 *
 * @public
 */
export const protocol = 5;
export var PacketType;
(function (PacketType) {
    PacketType[PacketType[\"CONNECT\"] = 0] = \"CONNECT\";
    PacketType[PacketType[\"DISCONNECT\"] = 1] = \"DISCONNECT\";
    PacketType[PacketType[\"EVENT\"] = 2] = \"EVENT\";
    PacketType[PacketType[\"ACK\"] = 3] = \"ACK\";
    PacketType[PacketType[\"CONNECT_ERROR\"] = 4] = \"CONNECT_ERROR\";
    PacketType[PacketType[\"BINARY_EVENT\"] = 5] = \"BINARY_EVENT\";
    PacketType[PacketType[\"BINARY_ACK\"] = 6] = \"BINARY_ACK\";
})(PacketType || (PacketType = {}));
/**
 * A socket.io Encoder instance
 */
export class Encoder {
    /**
     * Encoder constructor
     *
     * @param {function} replacer - custom replacer to pass down to JSON.parse
     */
    constructor(replacer) {
        this.replacer = replacer;
    }
    /**
     * Encode a packet as a single string if non-binary, or as a
     * buffer sequence, depending on packet type.
     *
     * @param {Object} obj - packet object
     */
    encode(obj) {
        if (obj.type === PacketType.EVENT || obj.type === PacketType.ACK) {
            if (hasBinary(obj)) {
                return this.encodeAsBinary({
                    type: obj.type === PacketType.EVENT
                        ? PacketType.BINARY_EVENT
                        : PacketType.BINARY_ACK,
                    nsp: obj.nsp,
                    data: obj.data,
                    id: obj.id,
                });
            }
        }
        return [this.encodeAsString(obj)];
    }
    /**
     * Encode packet as string.
     */
    encodeAsString(obj) {
        // first is type
        let str = \"\" + obj.type;
        // attachments if we have them
        if (obj.type === PacketType.BINARY_EVENT ||
            obj.type === PacketType.BINARY_ACK) {
            str += obj.attachments + \"-\";
        }
        // if we have a namespace other than `/`
        // we append it followed by a comma `,`
        if (obj.nsp && \"/\" !== obj.nsp) {
            str += obj.nsp + \",\";
        }
        // immediately followed by the id
        if (null != obj.id) {
            str += obj.id;
        }
        // json data
        if (null != obj.data) {
            str += JSON.stringify(obj.data, this.replacer);
        }
        return str;
    }
    /**
     * Encode packet as 'buffer sequence' by removing blobs, and
     * deconstructing packet into object with placeholders and
     * a list of buffers.
     */
    encodeAsBinary(obj) {
        const deconstruction = deconstructPacket(obj);
        const pack = this.encodeAsString(deconstruction.packet);
        const buffers = deconstruction.buffers;
        buffers.unshift(pack); // add packet info to beginning of data list
        return buffers; // write all the buffers
    }
}
// see https://stackoverflow.com/questions/8511281/check-if-a-value-is-an-object-in-javascript
function isObject(value) {
    return Object.prototype.toString.call(value) === \"[object Object]\";
}
/**
 * A socket.io Decoder instance
 *
 * @return {Object} decoder
 */
export class Decoder extends Emitter {
    /**
     * Decoder constructor
     *
     * @param {function} reviver - custom reviver to pass down to JSON.stringify
     */
    constructor(reviver) {
        super();
        this.reviver = reviver;
    }
    /**
     * Decodes an encoded packet string into packet JSON.
     *
     * @param {String} obj - encoded packet
     */
    add(obj) {
        let packet;
        if (typeof obj === \"string\") {
            if (this.reconstructor) {
                throw new Error(\"got plaintext data when reconstructing a packet\");
            }
            packet = this.decodeString(obj);
            const isBinaryEvent = packet.type === PacketType.BINARY_EVENT;
            if (isBinaryEvent || packet.type === PacketType.BINARY_ACK) {
                packet.type = isBinaryEvent ? PacketType.EVENT : PacketType.ACK;
                // binary packet's json
                this.reconstructor = new BinaryReconstructor(packet);
                // no attachments, labeled binary but no binary data to follow
                if (packet.attachments === 0) {
                    super.emitReserved(\"decoded\", packet);
                }
            }
            else {
                // non-binary full packet
                super.emitReserved(\"decoded\", packet);
            }
        }
        else if (isBinary(obj) || obj.base64) {
            // raw binary data
            if (!this.reconstructor) {
                throw new Error(\"got binary data when not reconstructing a packet\");
            }
            else {
                packet = this.reconstructor.takeBinaryData(obj);
                if (packet) {
                    // received final buffer
                    this.reconstructor = null;
                    super.emitReserved(\"decoded\", packet);
                }
            }
        }
        else {
            throw new Error(\"Unknown type: \" + obj);
        }
    }
    /**
     * Decode a packet String (JSON data)
     *
     * @param {String} str
     * @return {Object} packet
     */
    decodeString(str) {
        let i = 0;
        // look up type
        const p = {
            type: Number(str.charAt(0)),
        };
        if (PacketType[p.type] === undefined) {
            throw new Error(\"unknown packet type \" + p.type);
        }
        // look up attachments if type binary
        if (p.type === PacketType.BINARY_EVENT ||
            p.type === PacketType.BINARY_ACK) {
            const start = i + 1;
            while (str.charAt(++i) !== \"-\" && i != str.length) { }
            const buf = str.substring(start, i);
            if (buf != Number(buf) || str.charAt(i) !== \"-\") {
                throw new Error(\"Illegal attachments\");
            }
            p.attachments = Number(buf);
        }
        // look up namespace (if any)
        if (\"/\" === str.charAt(i + 1)) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (\",\" === c)
                    break;
                if (i === str.length)
                    break;
            }
            p.nsp = str.substring(start, i);
        }
        else {
            p.nsp = \"/\";
        }
        // look up id
        const next = str.charAt(i + 1);
        if (\"\" !== next && Number(next) == next) {
            const start = i + 1;
            while (++i) {
                const c = str.charAt(i);
                if (null == c || Number(c) != c) {
                    --i;
                    break;
                }
                if (i === str.length)
                    break;
            }
            p.id = Number(str.substring(start, i + 1));
        }
        // look up json data
        if (str.charAt(++i)) {
            const payload = this.tryParse(str.substr(i));
            if (Decoder.isPayloadValid(p.type, payload)) {
                p.data = payload;
            }
            else {
                throw new Error(\"invalid payload\");
            }
        }
        return p;
    }
    tryParse(str) {
        try {
            return JSON.parse(str, this.reviver);
        }
        catch (e) {
            return false;
        }
    }
    static isPayloadValid(type, payload) {
        switch (type) {
            case PacketType.CONNECT:
                return isObject(payload);
            case PacketType.DISCONNECT:
                return payload === undefined;
            case PacketType.CONNECT_ERROR:
                return typeof payload === \"string\" || isObject(payload);
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                return (Array.isArray(payload) &&
                    (typeof payload[0] === \"number\" ||
                        (typeof payload[0] === \"string\" &&
                            RESERVED_EVENTS.indexOf(payload[0]) === -1)));
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                return Array.isArray(payload);
        }
    }
    /**
     * Deallocates a parser's resources
     */
    destroy() {
        if (this.reconstructor) {
            this.reconstructor.finishedReconstruction();
            this.reconstructor = null;
        }
    }
}
/**
 * A manager of a binary event's 'buffer sequence'. Should
 * be constructed whenever a packet of type BINARY_EVENT is
 * decoded.
 *
 * @param {Object} packet
 * @return {BinaryReconstructor} initialized reconstructor
 */
class BinaryReconstructor {
    constructor(packet) {
        this.packet = packet;
        this.buffers = [];
        this.reconPack = packet;
    }
    /**
     * Method to be called when binary data received from connection
     * after a BINARY_EVENT packet.
     *
     * @param {Buffer | ArrayBuffer} binData - the raw binary data received
     * @return {null | Object} returns null if more binary data is expected or
     *   a reconstructed packet object if all buffers have been received.
     */
    takeBinaryData(binData) {
        this.buffers.push(binData);
        if (this.buffers.length === this.reconPack.attachments) {
            // done with buffer list
            const packet = reconstructPacket(this.reconPack, this.buffers);
            this.finishedReconstruction();
            return packet;
        }
        return null;
    }
    /**
     * Cleans up binary packet reconstruction variables.
     */
    finishedReconstruction() {
        this.reconPack = null;
        this.buffers = [];
    }
}
","export function on(obj, ev, fn) {
    obj.on(ev, fn);
    return function subDestroy() {
        obj.off(ev, fn);
    };
}
","import { PacketType } from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
/**
 * Internal events.
 * These events can't be emitted by the user.
 */
const RESERVED_EVENTS = Object.freeze({
    connect: 1,
    connect_error: 1,
    disconnect: 1,
    disconnecting: 1,
    // EventEmitter reserved events: https://nodejs.org/api/events.html#events_event_newlistener
    newListener: 1,
    removeListener: 1,
});
/**
 * A Socket is the fundamental class for interacting with the server.
 *
 * A Socket belongs to a certain Namespace (by default /) and uses an underlying {@link Manager} to communicate.
 *
 * @example
 * const socket = io();
 *
 * socket.on(\"connect\", () => {
 *   console.log(\"connected\");
 * });
 *
 * // send an event to the server
 * socket.emit(\"foo\", \"bar\");
 *
 * socket.on(\"foobar\", () => {
 *   // an event was received from the server
 * });
 *
 * // upon disconnection
 * socket.on(\"disconnect\", (reason) => {
 *   console.log(`disconnected due to ${reason}`);
 * });
 */
export class Socket extends Emitter {
    /**
     * `Socket` constructor.
     */
    constructor(io, nsp, opts) {
        super();
        /**
         * Whether the socket is currently connected to the server.
         *
         * @example
         * const socket = io();
         *
         * socket.on(\"connect\", () => {
         *   console.log(socket.connected); // true
         * });
         *
         * socket.on(\"disconnect\", () => {
         *   console.log(socket.connected); // false
         * });
         */
        this.connected = false;
        /**
         * Whether the connection state was recovered after a temporary disconnection. In that case, any missed packets will
         * be transmitted by the server.
         */
        this.recovered = false;
        /**
         * Buffer for packets received before the CONNECT packet
         */
        this.receiveBuffer = [];
        /**
         * Buffer for packets that will be sent once the socket is connected
         */
        this.sendBuffer = [];
        /**
         * The queue of packets to be sent with retry in case of failure.
         *
         * Packets are sent one by one, each waiting for the server acknowledgement, in order to guarantee the delivery order.
         * @private
         */
        this._queue = [];
        /**
         * A sequence to generate the ID of the {@link QueuedPacket}.
         * @private
         */
        this._queueSeq = 0;
        this.ids = 0;
        this.acks = {};
        this.flags = {};
        this.io = io;
        this.nsp = nsp;
        if (opts && opts.auth) {
            this.auth = opts.auth;
        }
        this._opts = Object.assign({}, opts);
        if (this.io._autoConnect)
            this.open();
    }
    /**
     * Whether the socket is currently disconnected
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"connect\", () => {
     *   console.log(socket.disconnected); // false
     * });
     *
     * socket.on(\"disconnect\", () => {
     *   console.log(socket.disconnected); // true
     * });
     */
    get disconnected() {
        return !this.connected;
    }
    /**
     * Subscribe to open, close and packet events
     *
     * @private
     */
    subEvents() {
        if (this.subs)
            return;
        const io = this.io;
        this.subs = [
            on(io, \"open\", this.onopen.bind(this)),
            on(io, \"packet\", this.onpacket.bind(this)),
            on(io, \"error\", this.onerror.bind(this)),
            on(io, \"close\", this.onclose.bind(this)),
        ];
    }
    /**
     * Whether the Socket will try to reconnect when its Manager connects or reconnects.
     *
     * @example
     * const socket = io();
     *
     * console.log(socket.active); // true
     *
     * socket.on(\"disconnect\", (reason) => {
     *   if (reason === \"io server disconnect\") {
     *     // the disconnection was initiated by the server, you need to manually reconnect
     *     console.log(socket.active); // false
     *   }
     *   // else the socket will automatically try to reconnect
     *   console.log(socket.active); // true
     * });
     */
    get active() {
        return !!this.subs;
    }
    /**
     * \"Opens\" the socket.
     *
     * @example
     * const socket = io({
     *   autoConnect: false
     * });
     *
     * socket.connect();
     */
    connect() {
        if (this.connected)
            return this;
        this.subEvents();
        if (!this.io[\"_reconnecting\"])
            this.io.open(); // ensure open
        if (\"open\" === this.io._readyState)
            this.onopen();
        return this;
    }
    /**
     * Alias for {@link connect()}.
     */
    open() {
        return this.connect();
    }
    /**
     * Sends a `message` event.
     *
     * This method mimics the WebSocket.send() method.
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/send
     *
     * @example
     * socket.send(\"hello\");
     *
     * // this is equivalent to
     * socket.emit(\"message\", \"hello\");
     *
     * @return self
     */
    send(...args) {
        args.unshift(\"message\");
        this.emit.apply(this, args);
        return this;
    }
    /**
     * Override `emit`.
     * If the event is in `events`, it's emitted normally.
     *
     * @example
     * socket.emit(\"hello\", \"world\");
     *
     * // all serializable datastructures are supported (no need to call JSON.stringify)
     * socket.emit(\"hello\", 1, \"2\", { 3: [\"4\"], 5: Uint8Array.from([6]) });
     *
     * // with an acknowledgement from the server
     * socket.emit(\"hello\", \"world\", (val) => {
     *   // ...
     * });
     *
     * @return self
     */
    emit(ev, ...args) {
        if (RESERVED_EVENTS.hasOwnProperty(ev)) {
            throw new Error('\"' + ev.toString() + '\" is a reserved event name');
        }
        args.unshift(ev);
        if (this._opts.retries && !this.flags.fromQueue && !this.flags.volatile) {
            this._addToQueue(args);
            return this;
        }
        const packet = {
            type: PacketType.EVENT,
            data: args,
        };
        packet.options = {};
        packet.options.compress = this.flags.compress !== false;
        // event ack callback
        if (\"function\" === typeof args[args.length - 1]) {
            const id = this.ids++;
            const ack = args.pop();
            this._registerAckCallback(id, ack);
            packet.id = id;
        }
        const isTransportWritable = this.io.engine &&
            this.io.engine.transport &&
            this.io.engine.transport.writable;
        const discardPacket = this.flags.volatile && (!isTransportWritable || !this.connected);
        if (discardPacket) {
        }
        else if (this.connected) {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        }
        else {
            this.sendBuffer.push(packet);
        }
        this.flags = {};
        return this;
    }
    /**
     * @private
     */
    _registerAckCallback(id, ack) {
        var _a;
        const timeout = (_a = this.flags.timeout) !== null && _a !== void 0 ? _a : this._opts.ackTimeout;
        if (timeout === undefined) {
            this.acks[id] = ack;
            return;
        }
        // @ts-ignore
        const timer = this.io.setTimeoutFn(() => {
            delete this.acks[id];
            for (let i = 0; i < this.sendBuffer.length; i++) {
                if (this.sendBuffer[i].id === id) {
                    this.sendBuffer.splice(i, 1);
                }
            }
            ack.call(this, new Error(\"operation has timed out\"));
        }, timeout);
        this.acks[id] = (...args) => {
            // @ts-ignore
            this.io.clearTimeoutFn(timer);
            ack.apply(this, [null, ...args]);
        };
    }
    /**
     * Emits an event and waits for an acknowledgement
     *
     * @example
     * // without timeout
     * const response = await socket.emitWithAck(\"hello\", \"world\");
     *
     * // with a specific timeout
     * try {
     *   const response = await socket.timeout(1000).emitWithAck(\"hello\", \"world\");
     * } catch (err) {
     *   // the server did not acknowledge the event in the given delay
     * }
     *
     * @return a Promise that will be fulfilled when the server acknowledges the event
     */
    emitWithAck(ev, ...args) {
        // the timeout flag is optional
        const withErr = this.flags.timeout !== undefined || this._opts.ackTimeout !== undefined;
        return new Promise((resolve, reject) => {
            args.push((arg1, arg2) => {
                if (withErr) {
                    return arg1 ? reject(arg1) : resolve(arg2);
                }
                else {
                    return resolve(arg1);
                }
            });
            this.emit(ev, ...args);
        });
    }
    /**
     * Add the packet to the queue.
     * @param args
     * @private
     */
    _addToQueue(args) {
        let ack;
        if (typeof args[args.length - 1] === \"function\") {
            ack = args.pop();
        }
        const packet = {
            id: this._queueSeq++,
            tryCount: 0,
            pending: false,
            args,
            flags: Object.assign({ fromQueue: true }, this.flags),
        };
        args.push((err, ...responseArgs) => {
            if (packet !== this._queue[0]) {
                // the packet has already been acknowledged
                return;
            }
            const hasError = err !== null;
            if (hasError) {
                if (packet.tryCount > this._opts.retries) {
                    this._queue.shift();
                    if (ack) {
                        ack(err);
                    }
                }
            }
            else {
                this._queue.shift();
                if (ack) {
                    ack(null, ...responseArgs);
                }
            }
            packet.pending = false;
            return this._drainQueue();
        });
        this._queue.push(packet);
        this._drainQueue();
    }
    /**
     * Send the first packet of the queue, and wait for an acknowledgement from the server.
     * @param force - whether to resend a packet that has not been acknowledged yet
     *
     * @private
     */
    _drainQueue(force = false) {
        if (!this.connected || this._queue.length === 0) {
            return;
        }
        const packet = this._queue[0];
        if (packet.pending && !force) {
            return;
        }
        packet.pending = true;
        packet.tryCount++;
        this.flags = packet.flags;
        this.emit.apply(this, packet.args);
    }
    /**
     * Sends a packet.
     *
     * @param packet
     * @private
     */
    packet(packet) {
        packet.nsp = this.nsp;
        this.io._packet(packet);
    }
    /**
     * Called upon engine `open`.
     *
     * @private
     */
    onopen() {
        if (typeof this.auth == \"function\") {
            this.auth((data) => {
                this._sendConnectPacket(data);
            });
        }
        else {
            this._sendConnectPacket(this.auth);
        }
    }
    /**
     * Sends a CONNECT packet to initiate the Socket.IO session.
     *
     * @param data
     * @private
     */
    _sendConnectPacket(data) {
        this.packet({
            type: PacketType.CONNECT,
            data: this._pid
                ? Object.assign({ pid: this._pid, offset: this._lastOffset }, data)
                : data,
        });
    }
    /**
     * Called upon engine or manager `error`.
     *
     * @param err
     * @private
     */
    onerror(err) {
        if (!this.connected) {
            this.emitReserved(\"connect_error\", err);
        }
    }
    /**
     * Called upon engine `close`.
     *
     * @param reason
     * @param description
     * @private
     */
    onclose(reason, description) {
        this.connected = false;
        delete this.id;
        this.emitReserved(\"disconnect\", reason, description);
    }
    /**
     * Called with socket packet.
     *
     * @param packet
     * @private
     */
    onpacket(packet) {
        const sameNamespace = packet.nsp === this.nsp;
        if (!sameNamespace)
            return;
        switch (packet.type) {
            case PacketType.CONNECT:
                if (packet.data && packet.data.sid) {
                    this.onconnect(packet.data.sid, packet.data.pid);
                }
                else {
                    this.emitReserved(\"connect_error\", new Error(\"It seems you are trying to reach a Socket.IO server in v2.x with a v3.x client, but they are not compatible (more information here: https://socket.io/docs/v3/migrating-from-2-x-to-3-0/)\"));
                }
                break;
            case PacketType.EVENT:
            case PacketType.BINARY_EVENT:
                this.onevent(packet);
                break;
            case PacketType.ACK:
            case PacketType.BINARY_ACK:
                this.onack(packet);
                break;
            case PacketType.DISCONNECT:
                this.ondisconnect();
                break;
            case PacketType.CONNECT_ERROR:
                this.destroy();
                const err = new Error(packet.data.message);
                // @ts-ignore
                err.data = packet.data.data;
                this.emitReserved(\"connect_error\", err);
                break;
        }
    }
    /**
     * Called upon a server event.
     *
     * @param packet
     * @private
     */
    onevent(packet) {
        const args = packet.data || [];
        if (null != packet.id) {
            args.push(this.ack(packet.id));
        }
        if (this.connected) {
            this.emitEvent(args);
        }
        else {
            this.receiveBuffer.push(Object.freeze(args));
        }
    }
    emitEvent(args) {
        if (this._anyListeners && this._anyListeners.length) {
            const listeners = this._anyListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, args);
            }
        }
        super.emit.apply(this, args);
        if (this._pid && args.length && typeof args[args.length - 1] === \"string\") {
            this._lastOffset = args[args.length - 1];
        }
    }
    /**
     * Produces an ack callback to emit with an event.
     *
     * @private
     */
    ack(id) {
        const self = this;
        let sent = false;
        return function (...args) {
            // prevent double callbacks
            if (sent)
                return;
            sent = true;
            self.packet({
                type: PacketType.ACK,
                id: id,
                data: args,
            });
        };
    }
    /**
     * Called upon a server acknowlegement.
     *
     * @param packet
     * @private
     */
    onack(packet) {
        const ack = this.acks[packet.id];
        if (\"function\" === typeof ack) {
            ack.apply(this, packet.data);
            delete this.acks[packet.id];
        }
        else {
        }
    }
    /**
     * Called upon server connect.
     *
     * @private
     */
    onconnect(id, pid) {
        this.id = id;
        this.recovered = pid && this._pid === pid;
        this._pid = pid; // defined only if connection state recovery is enabled
        this.connected = true;
        this.emitBuffered();
        this.emitReserved(\"connect\");
        this._drainQueue(true);
    }
    /**
     * Emit buffered events (received and emitted).
     *
     * @private
     */
    emitBuffered() {
        this.receiveBuffer.forEach((args) => this.emitEvent(args));
        this.receiveBuffer = [];
        this.sendBuffer.forEach((packet) => {
            this.notifyOutgoingListeners(packet);
            this.packet(packet);
        });
        this.sendBuffer = [];
    }
    /**
     * Called upon server disconnect.
     *
     * @private
     */
    ondisconnect() {
        this.destroy();
        this.onclose(\"io server disconnect\");
    }
    /**
     * Called upon forced client/server side disconnections,
     * this method ensures the manager stops tracking us and
     * that reconnections don't get triggered for this.
     *
     * @private
     */
    destroy() {
        if (this.subs) {
            // clean subscriptions to avoid reconnections
            this.subs.forEach((subDestroy) => subDestroy());
            this.subs = undefined;
        }
        this.io[\"_destroy\"](this);
    }
    /**
     * Disconnects the socket manually. In that case, the socket will not try to reconnect.
     *
     * If this is the last active Socket instance of the {@link Manager}, the low-level connection will be closed.
     *
     * @example
     * const socket = io();
     *
     * socket.on(\"disconnect\", (reason) => {
     *   // console.log(reason); prints \"io client disconnect\"
     * });
     *
     * socket.disconnect();
     *
     * @return self
     */
    disconnect() {
        if (this.connected) {
            this.packet({ type: PacketType.DISCONNECT });
        }
        // remove socket from pool
        this.destroy();
        if (this.connected) {
            // fire events
            this.onclose(\"io client disconnect\");
        }
        return this;
    }
    /**
     * Alias for {@link disconnect()}.
     *
     * @return self
     */
    close() {
        return this.disconnect();
    }
    /**
     * Sets the compress flag.
     *
     * @example
     * socket.compress(false).emit(\"hello\");
     *
     * @param compress - if `true`, compresses the sending data
     * @return self
     */
    compress(compress) {
        this.flags.compress = compress;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the event message will be dropped when this socket is not
     * ready to send messages.
     *
     * @example
     * socket.volatile.emit(\"hello\"); // the server may or may not receive it
     *
     * @returns self
     */
    get volatile() {
        this.flags.volatile = true;
        return this;
    }
    /**
     * Sets a modifier for a subsequent event emission that the callback will be called with an error when the
     * given number of milliseconds have elapsed without an acknowledgement from the server:
     *
     * @example
     * socket.timeout(5000).emit(\"my-event\", (err) => {
     *   if (err) {
     *     // the server did not acknowledge the event in the given delay
     *   }
     * });
     *
     * @returns self
     */
    timeout(timeout) {
        this.flags.timeout = timeout;
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * @example
     * socket.onAny((event, ...args) => {
     *   console.log(`got ${event}`);
     * });
     *
     * @param listener
     */
    onAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * @example
     * socket.prependAny((event, ...args) => {
     *   console.log(`got event ${event}`);
     * });
     *
     * @param listener
     */
    prependAny(listener) {
        this._anyListeners = this._anyListeners || [];
        this._anyListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`got event ${event}`);
     * }
     *
     * socket.onAny(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAny(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAny();
     *
     * @param listener
     */
    offAny(listener) {
        if (!this._anyListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAny() {
        return this._anyListeners || [];
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.onAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    onAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.push(listener);
        return this;
    }
    /**
     * Adds a listener that will be fired when any event is emitted. The event name is passed as the first argument to the
     * callback. The listener is added to the beginning of the listeners array.
     *
     * Note: acknowledgements sent to the server are not included.
     *
     * @example
     * socket.prependAnyOutgoing((event, ...args) => {
     *   console.log(`sent event ${event}`);
     * });
     *
     * @param listener
     */
    prependAnyOutgoing(listener) {
        this._anyOutgoingListeners = this._anyOutgoingListeners || [];
        this._anyOutgoingListeners.unshift(listener);
        return this;
    }
    /**
     * Removes the listener that will be fired when any event is emitted.
     *
     * @example
     * const catchAllListener = (event, ...args) => {
     *   console.log(`sent event ${event}`);
     * }
     *
     * socket.onAnyOutgoing(catchAllListener);
     *
     * // remove a specific listener
     * socket.offAnyOutgoing(catchAllListener);
     *
     * // or remove all listeners
     * socket.offAnyOutgoing();
     *
     * @param [listener] - the catch-all listener (optional)
     */
    offAnyOutgoing(listener) {
        if (!this._anyOutgoingListeners) {
            return this;
        }
        if (listener) {
            const listeners = this._anyOutgoingListeners;
            for (let i = 0; i < listeners.length; i++) {
                if (listener === listeners[i]) {
                    listeners.splice(i, 1);
                    return this;
                }
            }
        }
        else {
            this._anyOutgoingListeners = [];
        }
        return this;
    }
    /**
     * Returns an array of listeners that are listening for any event that is specified. This array can be manipulated,
     * e.g. to remove listeners.
     */
    listenersAnyOutgoing() {
        return this._anyOutgoingListeners || [];
    }
    /**
     * Notify the listeners for each packet sent
     *
     * @param packet
     *
     * @private
     */
    notifyOutgoingListeners(packet) {
        if (this._anyOutgoingListeners && this._anyOutgoingListeners.length) {
            const listeners = this._anyOutgoingListeners.slice();
            for (const listener of listeners) {
                listener.apply(this, packet.data);
            }
        }
    }
}
","/**
 * Initialize backoff timer with `opts`.
 *
 * - `min` initial timeout in milliseconds [100]
 * - `max` max timeout [10000]
 * - `jitter` [0]
 * - `factor` [2]
 *
 * @param {Object} opts
 * @api public
 */
export function Backoff(opts) {
    opts = opts || {};
    this.ms = opts.min || 100;
    this.max = opts.max || 10000;
    this.factor = opts.factor || 2;
    this.jitter = opts.jitter > 0 && opts.jitter <= 1 ? opts.jitter : 0;
    this.attempts = 0;
}
/**
 * Return the backoff duration.
 *
 * @return {Number}
 * @api public
 */
Backoff.prototype.duration = function () {
    var ms = this.ms * Math.pow(this.factor, this.attempts++);
    if (this.jitter) {
        var rand = Math.random();
        var deviation = Math.floor(rand * this.jitter * ms);
        ms = (Math.floor(rand * 10) & 1) == 0 ? ms - deviation : ms + deviation;
    }
    return Math.min(ms, this.max) | 0;
};
/**
 * Reset the number of attempts.
 *
 * @api public
 */
Backoff.prototype.reset = function () {
    this.attempts = 0;
};
/**
 * Set the minimum duration
 *
 * @api public
 */
Backoff.prototype.setMin = function (min) {
    this.ms = min;
};
/**
 * Set the maximum duration
 *
 * @api public
 */
Backoff.prototype.setMax = function (max) {
    this.max = max;
};
/**
 * Set the jitter
 *
 * @api public
 */
Backoff.prototype.setJitter = function (jitter) {
    this.jitter = jitter;
};
","import { Socket as Engine, installTimerFunctions, nextTick, } from \"engine.io-client\";
import { Socket } from \"./socket.js\";
import * as parser from \"socket.io-parser\";
import { on } from \"./on.js\";
import { Backoff } from \"./contrib/backo2.js\";
import { Emitter, } from \"@socket.io/component-emitter\";
export class Manager extends Emitter {
    constructor(uri, opts) {
        var _a;
        super();
        this.nsps = {};
        this.subs = [];
        if (uri && \"object\" === typeof uri) {
            opts = uri;
            uri = undefined;
        }
        opts = opts || {};
        opts.path = opts.path || \"/socket.io\";
        this.opts = opts;
        installTimerFunctions(this, opts);
        this.reconnection(opts.reconnection !== false);
        this.reconnectionAttempts(opts.reconnectionAttempts || Infinity);
        this.reconnectionDelay(opts.reconnectionDelay || 1000);
        this.reconnectionDelayMax(opts.reconnectionDelayMax || 5000);
        this.randomizationFactor((_a = opts.randomizationFactor) !== null && _a !== void 0 ? _a : 0.5);
        this.backoff = new Backoff({
            min: this.reconnectionDelay(),
            max: this.reconnectionDelayMax(),
            jitter: this.randomizationFactor(),
        });
        this.timeout(null == opts.timeout ? 20000 : opts.timeout);
        this._readyState = \"closed\";
        this.uri = uri;
        const _parser = opts.parser || parser;
        this.encoder = new _parser.Encoder();
        this.decoder = new _parser.Decoder();
        this._autoConnect = opts.autoConnect !== false;
        if (this._autoConnect)
            this.open();
    }
    reconnection(v) {
        if (!arguments.length)
            return this._reconnection;
        this._reconnection = !!v;
        return this;
    }
    reconnectionAttempts(v) {
        if (v === undefined)
            return this._reconnectionAttempts;
        this._reconnectionAttempts = v;
        return this;
    }
    reconnectionDelay(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelay;
        this._reconnectionDelay = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMin(v);
        return this;
    }
    randomizationFactor(v) {
        var _a;
        if (v === undefined)
            return this._randomizationFactor;
        this._randomizationFactor = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setJitter(v);
        return this;
    }
    reconnectionDelayMax(v) {
        var _a;
        if (v === undefined)
            return this._reconnectionDelayMax;
        this._reconnectionDelayMax = v;
        (_a = this.backoff) === null || _a === void 0 ? void 0 : _a.setMax(v);
        return this;
    }
    timeout(v) {
        if (!arguments.length)
            return this._timeout;
        this._timeout = v;
        return this;
    }
    /**
     * Starts trying to reconnect if reconnection is enabled and we have not
     * started reconnecting yet
     *
     * @private
     */
    maybeReconnectOnOpen() {
        // Only try to reconnect if it's the first time we're connecting
        if (!this._reconnecting &&
            this._reconnection &&
            this.backoff.attempts === 0) {
            // keeps reconnection from firing twice for the same reconnection loop
            this.reconnect();
        }
    }
    /**
     * Sets the current transport `socket`.
     *
     * @param {Function} fn - optional, callback
     * @return self
     * @public
     */
    open(fn) {
        if (~this._readyState.indexOf(\"open\"))
            return this;
        this.engine = new Engine(this.uri, this.opts);
        const socket = this.engine;
        const self = this;
        this._readyState = \"opening\";
        this.skipReconnect = false;
        // emit `open`
        const openSubDestroy = on(socket, \"open\", function () {
            self.onopen();
            fn && fn();
        });
        // emit `error`
        const errorSub = on(socket, \"error\", (err) => {
            self.cleanup();
            self._readyState = \"closed\";
            this.emitReserved(\"error\", err);
            if (fn) {
                fn(err);
            }
            else {
                // Only do this if there is no fn to handle the error
                self.maybeReconnectOnOpen();
            }
        });
        if (false !== this._timeout) {
            const timeout = this._timeout;
            if (timeout === 0) {
                openSubDestroy(); // prevents a race condition with the 'open' event
            }
            // set timer
            const timer = this.setTimeoutFn(() => {
                openSubDestroy();
                socket.close();
                // @ts-ignore
                socket.emit(\"error\", new Error(\"timeout\"));
            }, timeout);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
        this.subs.push(openSubDestroy);
        this.subs.push(errorSub);
        return this;
    }
    /**
     * Alias for open()
     *
     * @return self
     * @public
     */
    connect(fn) {
        return this.open(fn);
    }
    /**
     * Called upon transport open.
     *
     * @private
     */
    onopen() {
        // clear old subs
        this.cleanup();
        // mark as open
        this._readyState = \"open\";
        this.emitReserved(\"open\");
        // add new subs
        const socket = this.engine;
        this.subs.push(on(socket, \"ping\", this.onping.bind(this)), on(socket, \"data\", this.ondata.bind(this)), on(socket, \"error\", this.onerror.bind(this)), on(socket, \"close\", this.onclose.bind(this)), on(this.decoder, \"decoded\", this.ondecoded.bind(this)));
    }
    /**
     * Called upon a ping.
     *
     * @private
     */
    onping() {
        this.emitReserved(\"ping\");
    }
    /**
     * Called with data.
     *
     * @private
     */
    ondata(data) {
        try {
            this.decoder.add(data);
        }
        catch (e) {
            this.onclose(\"parse error\", e);
        }
    }
    /**
     * Called when parser fully decodes a packet.
     *
     * @private
     */
    ondecoded(packet) {
        // the nextTick call prevents an exception in a user-provided event listener from triggering a disconnection due to a \"parse error\"
        nextTick(() => {
            this.emitReserved(\"packet\", packet);
        }, this.setTimeoutFn);
    }
    /**
     * Called upon socket error.
     *
     * @private
     */
    onerror(err) {
        this.emitReserved(\"error\", err);
    }
    /**
     * Creates a new socket for the given `nsp`.
     *
     * @return {Socket}
     * @public
     */
    socket(nsp, opts) {
        let socket = this.nsps[nsp];
        if (!socket) {
            socket = new Socket(this, nsp, opts);
            this.nsps[nsp] = socket;
        }
        else if (this._autoConnect && !socket.active) {
            socket.connect();
        }
        return socket;
    }
    /**
     * Called upon a socket close.
     *
     * @param socket
     * @private
     */
    _destroy(socket) {
        const nsps = Object.keys(this.nsps);
        for (const nsp of nsps) {
            const socket = this.nsps[nsp];
            if (socket.active) {
                return;
            }
        }
        this._close();
    }
    /**
     * Writes a packet.
     *
     * @param packet
     * @private
     */
    _packet(packet) {
        const encodedPackets = this.encoder.encode(packet);
        for (let i = 0; i < encodedPackets.length; i++) {
            this.engine.write(encodedPackets[i], packet.options);
        }
    }
    /**
     * Clean up transport subscriptions and packet buffer.
     *
     * @private
     */
    cleanup() {
        this.subs.forEach((subDestroy) => subDestroy());
        this.subs.length = 0;
        this.decoder.destroy();
    }
    /**
     * Close the current socket.
     *
     * @private
     */
    _close() {
        this.skipReconnect = true;
        this._reconnecting = false;
        this.onclose(\"forced close\");
        if (this.engine)
            this.engine.close();
    }
    /**
     * Alias for close()
     *
     * @private
     */
    disconnect() {
        return this._close();
    }
    /**
     * Called upon engine close.
     *
     * @private
     */
    onclose(reason, description) {
        this.cleanup();
        this.backoff.reset();
        this._readyState = \"closed\";
        this.emitReserved(\"close\", reason, description);
        if (this._reconnection && !this.skipReconnect) {
            this.reconnect();
        }
    }
    /**
     * Attempt a reconnection.
     *
     * @private
     */
    reconnect() {
        if (this._reconnecting || this.skipReconnect)
            return this;
        const self = this;
        if (this.backoff.attempts >= this._reconnectionAttempts) {
            this.backoff.reset();
            this.emitReserved(\"reconnect_failed\");
            this._reconnecting = false;
        }
        else {
            const delay = this.backoff.duration();
            this._reconnecting = true;
            const timer = this.setTimeoutFn(() => {
                if (self.skipReconnect)
                    return;
                this.emitReserved(\"reconnect_attempt\", self.backoff.attempts);
                // check again for the case socket closed in above events
                if (self.skipReconnect)
                    return;
                self.open((err) => {
                    if (err) {
                        self._reconnecting = false;
                        self.reconnect();
                        this.emitReserved(\"reconnect_error\", err);
                    }
                    else {
                        self.onreconnect();
                    }
                });
            }, delay);
            if (this.opts.autoUnref) {
                timer.unref();
            }
            this.subs.push(function subDestroy() {
                clearTimeout(timer);
            });
        }
    }
    /**
     * Called upon successful reconnect.
     *
     * @private
     */
    onreconnect() {
        const attempt = this.backoff.attempts;
        this._reconnecting = false;
        this.backoff.reset();
        this.emitReserved(\"reconnect\", attempt);
    }
}
","import { url } from \"./url.js\";
import { Manager } from \"./manager.js\";
import { Socket } from \"./socket.js\";
/**
 * Managers cache.
 */
const cache = {};
function lookup(uri, opts) {
    if (typeof uri === \"object\") {
        opts = uri;
        uri = undefined;
    }
    opts = opts || {};
    const parsed = url(uri, opts.path || \"/socket.io\");
    const source = parsed.source;
    const id = parsed.id;
    const path = parsed.path;
    const sameNamespace = cache[id] && path in cache[id][\"nsps\"];
    const newConnection = opts.forceNew ||
        opts[\"force new connection\"] ||
        false === opts.multiplex ||
        sameNamespace;
    let io;
    if (newConnection) {
        io = new Manager(source, opts);
    }
    else {
        if (!cache[id]) {
            cache[id] = new Manager(source, opts);
        }
        io = cache[id];
    }
    if (parsed.query && !opts.query) {
        opts.query = parsed.queryKey;
    }
    return io.socket(parsed.path, opts);
}
// so that \"lookup\" can be used both as a function (e.g. `io(...)`) and as a
// namespace (e.g. `io.connect(...)`), for backward compatibility
Object.assign(lookup, {
    Manager,
    Socket,
    io: lookup,
    connect: lookup,
});
/**
 * Protocol version.
 *
 * @public
 */
export { protocol } from \"socket.io-parser\";
/**
 * Expose constructors for standalone build.
 *
 * @public
 */
export { Manager, Socket, lookup as io, lookup as connect, lookup as default, };
"],"names":["PACKET_TYPES","Object","create","PACKET_TYPES_REVERSE","keys","forEach","key","ERROR_PACKET","type","data","withNativeBlob","Blob","prototype","toString","call","withNativeArrayBuffer","ArrayBuffer","isView","obj","buffer","encodePacket","supportsBinary","callback","encodeBlobAsBase64","fileReader","FileReader","onload","content","result","split","readAsDataURL","chars","lookup","Uint8Array","i","length","charCodeAt","decode","base64","bufferLength","len","p","encoded1","encoded2","encoded3","encoded4","arraybuffer","bytes","decodePacket","encodedPacket","binaryType","mapBinary","charAt","decodeBase64Packet","substring","packetType","decoded","SEPARATOR","String","fromCharCode","encodePayload","packets","encodedPackets","Array","count","packet","join","decodePayload","encodedPayload","decodedPacket","push","protocol","Emitter","mixin","on","addEventListener","event","fn","_callbacks","once","off","apply","arguments","removeListener","removeAllListeners","removeEventListener","callbacks","cb","splice","emit","args","slice","emitReserved","listeners","hasListeners","globalThisShim","self","window","Function","pick","attr","reduce","acc","k","hasOwnProperty","NATIVE_SET_TIMEOUT","globalThis","setTimeout","NATIVE_CLEAR_TIMEOUT","clearTimeout","installTimerFunctions","opts","useNativeTimers","setTimeoutFn","bind","clearTimeoutFn","BASE64_OVERHEAD","byteLength","utf8Length","Math","ceil","size","str","c","l","TransportError","reason","description","context","Error","Transport","writable","query","socket","readyState","doOpen","doClose","onClose","write","onPacket","details","onPause","alphabet","map","seed","prev","encode","num","encoded","floor","yeast","now","Date","encodeURIComponent","qs","qry","pairs","pair","decodeURIComponent","value","XMLHttpRequest","err","hasCORS","XHR","xdomain","e","concat","empty","hasXHR2","xhr","responseType","Polling","polling","location","isSSL","port","xd","hostname","xs","secure","forceBase64","poll","pause","total","doPoll","onOpen","close","doWrite","schema","timestampRequests","timestampParam","sid","b64","Number","encodedQuery","ipv6","indexOf","path","Request","uri","req","request","method","xhrStatus","onError","onData","pollXhr","async","undefined","xscheme","open","extraHeaders","setDisableHeaderCheck","setRequestHeader","withCredentials","requestTimeout","timeout","onreadystatechange","status","onLoad","send","document","index","requestsCount","requests","cleanup","fromError","abort","responseText","attachEvent","unloadHandler","terminationEvent","nextTick","isPromiseAvailable","Promise","resolve","then","WebSocket","MozWebSocket","usingBrowserWebSocket","defaultBinaryType","isReactNative","navigator","product","toLowerCase","WS","check","protocols","headers","ws","addEventListeners","onopen","autoUnref","_socket","unref","onclose","closeEvent","onmessage","ev","onerror","lastPacket","transports","websocket","re","parts","parse","src","b","replace","m","exec","source","host","authority","ipv6uri","pathNames","queryKey","regx","names","$0","$1","$2","Socket","writeBuffer","prevBufferLen","agent","upgrade","rememberUpgrade","addTrailingSlash","rejectUnauthorized","perMessageDeflate","threshold","transportOptions","closeOnBeforeunload","id","upgrades","pingInterval","pingTimeout","pingTimeoutTimer","beforeunloadEventListener","transport","offlineEventListener","name","EIO","priorWebsocketSuccess","createTransport","shift","setTransport","onDrain","failed","onTransportOpen","msg","upgrading","flush","freezeTransport","error","onTransportClose","onupgrade","to","probe","onHandshake","JSON","resetPingTimeout","sendPacket","code","filterUpgrades","maxPayload","getWritablePackets","shouldCheckPayloadSize","payloadSize","options","compress","cleanupAndClose","waitForUpgrade","filteredUpgrades","j","url","loc","test","href","withNativeFile","File","isBinary","hasBinary","toJSON","isArray","deconstructPacket","buffers","packetData","pack","_deconstructPacket","attachments","placeholder","_placeholder","newData","reconstructPacket","_reconstructPacket","isIndexValid","RESERVED_EVENTS","PacketType","Encoder","replacer","EVENT","ACK","encodeAsBinary","BINARY_EVENT","BINARY_ACK","nsp","encodeAsString","stringify","deconstruction","unshift","isObject","Decoder","reviver","reconstructor","decodeString","isBinaryEvent","BinaryReconstructor","takeBinaryData","start","buf","next","payload","tryParse","substr","isPayloadValid","finishedReconstruction","CONNECT","DISCONNECT","CONNECT_ERROR","reconPack","binData","subDestroy","freeze","connect","connect_error","disconnect","disconnecting","newListener","io","connected","recovered","receiveBuffer","sendBuffer","_queue","_queueSeq","ids","acks","flags","auth","_opts","_autoConnect","subs","onpacket","subEvents","_readyState","retries","fromQueue","_addToQueue","ack","pop","_registerAckCallback","isTransportWritable","engine","discardPacket","notifyOutgoingListeners","_a","ackTimeout","timer","withErr","reject","arg1","arg2","tryCount","pending","hasError","responseArgs","_drainQueue","force","_packet","_sendConnectPacket","_pid","pid","offset","_lastOffset","sameNamespace","onconnect","onevent","onack","ondisconnect","destroy","message","emitEvent","_anyListeners","listener","sent","emitBuffered","_anyOutgoingListeners","Backoff","ms","min","max","factor","jitter","attempts","duration","pow","rand","random","deviation","reset","setMin","setMax","setJitter","Manager","nsps","reconnection","reconnectionAttempts","Infinity","reconnectionDelay","reconnectionDelayMax","randomizationFactor","backoff","_parser","parser","encoder","decoder","autoConnect","v","_reconnection","_reconnectionAttempts","_reconnectionDelay","_randomizationFactor","_reconnectionDelayMax","_timeout","_reconnecting","reconnect","Engine","skipReconnect","openSubDestroy","errorSub","maybeReconnectOnOpen","onping","ondata","ondecoded","add","active","_close","delay","onreconnect","attempt","cache","parsed","newConnection","forceNew","multiplex"],"mappings":"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"}
