(function (root, factory) {
  'use strict';

  var api = factory();
  if (root) root.NumOJRepositorySha256 = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
})(
  typeof window !== 'undefined'
    ? window
    : typeof globalThis !== 'undefined'
      ? globalThis
      : this,
  function () {
    'use strict';

    var ROUND_CONSTANTS = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    function rotateRight(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }

    function asBytes(value) {
      if (value instanceof Uint8Array) return value;
      if (
        typeof ArrayBuffer !== 'undefined' &&
        typeof ArrayBuffer.isView === 'function' &&
        ArrayBuffer.isView(value)
      ) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      }
      if (
        typeof ArrayBuffer !== 'undefined' &&
        value instanceof ArrayBuffer
      ) {
        return new Uint8Array(value);
      }
      throw new TypeError('SHA-256 输入必须是 ArrayBuffer 或字节视图');
    }

    function wordHex(value) {
      return (value >>> 0).toString(16).padStart(8, '0');
    }

    function digestHex(value) {
      var bytes = asBytes(value);
      var byteLength = bytes.byteLength;
      var paddedLength = Math.ceil((byteLength + 9) / 64) * 64;
      var message = new Uint8Array(paddedLength);
      message.set(bytes);
      message[byteLength] = 0x80;

      var view = new DataView(message.buffer);
      var bitLengthLow = (byteLength << 3) >>> 0;
      var bitLengthHigh = Math.floor(byteLength / 0x20000000) >>> 0;
      view.setUint32(paddedLength - 8, bitLengthHigh, false);
      view.setUint32(paddedLength - 4, bitLengthLow, false);

      var hash0 = 0x6a09e667;
      var hash1 = 0xbb67ae85;
      var hash2 = 0x3c6ef372;
      var hash3 = 0xa54ff53a;
      var hash4 = 0x510e527f;
      var hash5 = 0x9b05688c;
      var hash6 = 0x1f83d9ab;
      var hash7 = 0x5be0cd19;
      var words = new Uint32Array(64);

      for (var offset = 0; offset < paddedLength; offset += 64) {
        var index;
        for (index = 0; index < 16; index += 1) {
          words[index] = view.getUint32(offset + index * 4, false);
        }
        for (index = 16; index < 64; index += 1) {
          var sigma0 =
            rotateRight(words[index - 15], 7) ^
            rotateRight(words[index - 15], 18) ^
            (words[index - 15] >>> 3);
          var sigma1 =
            rotateRight(words[index - 2], 17) ^
            rotateRight(words[index - 2], 19) ^
            (words[index - 2] >>> 10);
          words[index] = (
            words[index - 16] +
            sigma0 +
            words[index - 7] +
            sigma1
          ) >>> 0;
        }

        var a = hash0;
        var b = hash1;
        var c = hash2;
        var d = hash3;
        var e = hash4;
        var f = hash5;
        var g = hash6;
        var h = hash7;

        for (index = 0; index < 64; index += 1) {
          var sum1 =
            rotateRight(e, 6) ^
            rotateRight(e, 11) ^
            rotateRight(e, 25);
          var choose = (e & f) ^ (~e & g);
          var temporary1 = (
            h +
            sum1 +
            choose +
            ROUND_CONSTANTS[index] +
            words[index]
          ) >>> 0;
          var sum0 =
            rotateRight(a, 2) ^
            rotateRight(a, 13) ^
            rotateRight(a, 22);
          var majority = (a & b) ^ (a & c) ^ (b & c);
          var temporary2 = (sum0 + majority) >>> 0;

          h = g;
          g = f;
          f = e;
          e = (d + temporary1) >>> 0;
          d = c;
          c = b;
          b = a;
          a = (temporary1 + temporary2) >>> 0;
        }

        hash0 = (hash0 + a) >>> 0;
        hash1 = (hash1 + b) >>> 0;
        hash2 = (hash2 + c) >>> 0;
        hash3 = (hash3 + d) >>> 0;
        hash4 = (hash4 + e) >>> 0;
        hash5 = (hash5 + f) >>> 0;
        hash6 = (hash6 + g) >>> 0;
        hash7 = (hash7 + h) >>> 0;
      }

      return [
        hash0, hash1, hash2, hash3,
        hash4, hash5, hash6, hash7,
      ].map(wordHex).join('');
    }

    return Object.freeze({ digestHex: digestHex });
  }
);
