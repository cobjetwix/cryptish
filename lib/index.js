'use strict';
var Crypto = require("crypto");

var cryptish = (function () {

  // Constant members
  var SALT_BITS = 64;
  var ITERATIONS = 10000;
  var KEY_LENGTH_BITS = 128;
  var internals = {};

  internals.binaryToBase64 = function( binary ) {
    return new Buffer( binary, "binary" ).toString("base64");
  };

  internals.base64toBinary = function ( base64 ){
    return new Buffer( base64, "base64" ).toString("binary");
  };

  internals.fixedTimeComparison = function (a, b) {

    if (typeof a !== 'string' ||
        typeof b !== 'string') {

      return false;
    }

    var mismatch = (a.length === b.length ? 0 : 1);
    if (mismatch) {
      b = a;
    }

    for (var i = 0, il = a.length; i < il; ++i) {
      var ac = a.charCodeAt(i);
      var bc = b.charCodeAt(i);
      mismatch |= (ac ^ bc);
    }

    return (mismatch === 0);
  };

  return {

    randomString: function (size) {
      var buffer = cryptish.randomBits((size + 1) * 6);
      if (buffer instanceof Error) {
        return buffer;
      }

      var string = internals.binaryToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
      return string.slice(0, size);
    },

    randomBits: function (bits) {
      var bytes = Math.ceil(bits / 8);
      return Crypto.randomBytes(bytes);
    },

    generateSalt: function(bits) {
      var buffer = cryptish.randomBits(bits);
      return internals.binaryToBase64(buffer);
    },

    hashPassword: function( value, salt ) {
      // if salt was not supplied, generate it now.
      if (salt == null ) {
        salt = cryptish.generateSalt(SALT_BITS);
      }

      var derivedKey = internals.binaryToBase64(Crypto.pbkdf2Sync( value, salt, ITERATIONS, KEY_LENGTH_BITS));
      return 'pbkdf2::' + salt + '::' + ITERATIONS + '::' + derivedKey;
    },

    verifyPassword: function( value, stored) {
      // if salt was not supplied, generate it now.
      var parts = stored.split('::');
      var salt = parts[1];
      var iterations = parseInt(parts[2]);
      var key = parts[3];
      var derivedKey = internals.binaryToBase64(Crypto.pbkdf2Sync( value, salt, iterations, KEY_LENGTH_BITS));
      return internals.fixedTimeComparison(derivedKey, key);
    },

    binaryToBase64: function(buffer) {
      return internals.binaryToBase64(buffer);
    },

    base64toBinary: function(string) {
      return internals.base64toBinary(string);
    },

    sha256: function(string) {
        if (!string) return string;
        return Crypto
            .createHash('sha256')
            .update(name)
            .digest('hex');
    }
  };

})();

module.exports = cryptish;