"use strict";
!(function (m) {
  function t(i) {
    if (n[i]) {
      return n[i].exports;
    }
    var module = (n[i] = { i: i, l: false, exports: {} });
    return (
      m[i].call(module.exports, module, module.exports, t),
      (module.l = true),
      module.exports
    );
  }
  var n = {};
  t.m = m;
  t.c = n;
  t.d = function (d, name, n) {
    if (!t.o(d, name)) {
      Object.defineProperty(d, name, { enumerable: true, get: n });
    }
  };
  t.r = function (val) {
    if ("undefined" != typeof Symbol && Symbol.toStringTag) {
      Object.defineProperty(val, Symbol.toStringTag, { value: "Module" });
    }
    Object.defineProperty(val, "__esModule", { value: true });
  };
  t.t = function (val, byteOffset) {
    if ((1 & byteOffset && (val = t(val)), 8 & byteOffset)) {
      return val;
    }
    if (4 & byteOffset && "object" == typeof val && val && val.__esModule) {
      return val;
    }
    var d = Object.create(null);
    if (
      (t.r(d),
      Object.defineProperty(d, "default", { enumerable: true, value: val }),
      2 & byteOffset && "string" != typeof val)
    ) {
      var s;
      for (s in val) {
        t.d(
          d,
          s,
          function (attrPropertyName) {
            return val[attrPropertyName];
          }["bind"](null, s)
        );
      }
    }
    return d;
  };
  t.n = function (module) {
    var n =
      module && module.__esModule
        ? function () {
            return module.default;
          }
        : function () {
            return module;
          };
    return t.d(n, "a", n), n;
  };
  t.o = function (object, property) {
    return Object.prototype.hasOwnProperty.call(object, property);
  };
  t.p = "/";
  t((t.s = 9));
})([
  function (module, canCreateDiscussions, isSlidingUp) {
    var _module$exports;
    module.exports =
      ((_module$exports =
        _module$exports ||
        (function (Math, canCreateDiscussions) {
          var extend =
            Object.create ||
            (function () {
              function shader() {}
              return function (material) {
                var shobj;
                return (
                  (shader.prototype = material),
                  (shobj = new shader()),
                  (shader.prototype = null),
                  shobj
                );
              };
            })();
          var p = {};
          var j = (p.lib = {});
          var f = (j.Base = {
            extend: function (opts) {
              var proto = extend(this);
              return (
                opts && proto.mixIn(opts),
                (proto.hasOwnProperty("init") && this.init !== proto.init) ||
                  (proto.init = function () {
                    proto.$super.init.apply(this, arguments);
                  }),
                (proto.init.prototype = proto),
                (proto.$super = this),
                proto
              );
            },
            create: function () {
              var res = this.extend();
              return res.init.apply(res, arguments), res;
            },
            init: function () {},
            mixIn: function (properties) {
              var property;
              for (property in properties) {
                if (properties.hasOwnProperty(property)) {
                  this[property] = properties[property];
                }
              }
              if (properties.hasOwnProperty("toString")) {
                this.toString = properties.toString;
              }
            },
            clone: function () {
              return this.init.prototype.extend(this);
            },
          });
          var WordArray = (j.WordArray = f.extend({
            init: function (a, e) {
              a = this.words = a || [];
              this.sigBytes = null != e ? e : 4 * a.length;
            },
            toString: function (encoder) {
              return (encoder || Hex).stringify(this);
            },
            concat: function (wordArray) {
              var thisWords = this.words;
              var thatWords = wordArray.words;
              var c = this.sigBytes;
              var thatSigBytes = wordArray.sigBytes;
              if ((this.clamp(), c % 4)) {
                var i = 0;
                for (; i < thatSigBytes; i++) {
                  var thatByte =
                    (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 255;
                  thisWords[(c + i) >>> 2] |=
                    thatByte << (24 - ((c + i) % 4) * 8);
                }
              } else {
                i = 0;
                for (; i < thatSigBytes; i = i + 4) {
                  thisWords[(c + i) >>> 2] = thatWords[i >>> 2];
                }
              }
              return (this.sigBytes += thatSigBytes), this;
            },
            clamp: function () {
              var a = this.words;
              var c = this.sigBytes;
              a[c >>> 2] &= 4294967295 << (32 - (c % 4) * 8);
              a.length = Math.ceil(c / 4);
            },
            clone: function () {
              var transformedMasterKey = f.clone.call(this);
              return (
                (transformedMasterKey.words = this.words.slice(0)),
                transformedMasterKey
              );
            },
            random: function (nBytes) {
              var w;
              var hashWords = [];
              var r = function (m_w) {
                m_w = m_w;
                var nxt = 987654321;
                var mask = 4294967295;
                return function () {
                  var result =
                    (((nxt = (36969 * (65535 & nxt) + (nxt >> 16)) & mask) <<
                      16) +
                      (m_w = (18e3 * (65535 & m_w) + (m_w >> 16)) & mask)) &
                    mask;
                  return (
                    (result = result / 4294967296),
                    (result = result + 0.5) * (Math.random() > 0.5 ? 1 : -1)
                  );
                };
              };
              var i = 0;
              for (; i < nBytes; i = i + 4) {
                var _r = r(4294967296 * (w || Math.random()));
                w = 987654071 * _r();
                hashWords.push((4294967296 * _r()) | 0);
              }
              return new WordArray.init(hashWords, nBytes);
            },
          }));
          var b = (p.enc = {});
          var Hex = (b.Hex = {
            stringify: function (a) {
              var q = a.words;
              var d = a.sigBytes;
              var outChance = [];
              var b = 0;
              for (; b < d; b++) {
                var a = (q[b >>> 2] >>> (24 - (b % 4) * 8)) & 255;
                outChance.push((a >>> 4).toString(16));
                outChance.push((15 & a).toString(16));
              }
              return outChance.join("");
            },
            parse: function (hexStr) {
              var hexStrLength = hexStr.length;
              var words = [];
              var i = 0;
              for (; i < hexStrLength; i = i + 2) {
                words[i >>> 3] |=
                  parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
              }
              return new WordArray.init(words, hexStrLength / 2);
            },
          });
          var g = (b.Latin1 = {
            stringify: function (a) {
              var q = a.words;
              var d = a.sigBytes;
              var commandNames = [];
              var b = 0;
              for (; b < d; b++) {
                var item = (q[b >>> 2] >>> (24 - (b % 4) * 8)) & 255;
                commandNames.push(String.fromCharCode(item));
              }
              return commandNames.join("");
            },
            parse: function (latin1Str) {
              var latin1StrLength = latin1Str.length;
              var words = [];
              var i = 0;
              for (; i < latin1StrLength; i++) {
                words[i >>> 2] |=
                  (255 & latin1Str.charCodeAt(i)) << (24 - (i % 4) * 8);
              }
              return new WordArray.init(words, latin1StrLength);
            },
          });
          var primParser = (b.Utf8 = {
            stringify: function (a) {
              try {
                return decodeURIComponent(escape(g.stringify(a)));
              } catch (aB) {
                throw new Error("Malformed UTF-8 data");
              }
            },
            parse: function (text) {
              return g.parse(unescape(encodeURIComponent(text)));
            },
          });
          var k = (j.BufferedBlockAlgorithm = f.extend({
            reset: function () {
              this._data = new WordArray.init();
              this._nDataBytes = 0;
            },
            _append: function (data) {
              if ("string" == typeof data) {
                data = primParser.parse(data);
              }
              this._data.concat(data);
              this._nDataBytes += data.sigBytes;
            },
            _process: function (i) {
              var data = this._data;
              var b = data.words;
              var dataSigBytes = data.sigBytes;
              var blockSize = this.blockSize;
              var s = dataSigBytes / (4 * blockSize);
              var index =
                (s = i
                  ? Math.ceil(s)
                  : Math.max((0 | s) - this._minBufferSize, 0)) * blockSize;
              var nBytesReady = Math.min(4 * index, dataSigBytes);
              if (index) {
                var offset = 0;
                for (; offset < index; offset = offset + blockSize) {
                  this._doProcessBlock(b, offset);
                }
                var left = b.splice(0, index);
                data.sigBytes -= nBytesReady;
              }
              return new WordArray.init(left, nBytesReady);
            },
            clone: function () {
              var funcThread = f.clone.call(this);
              return (funcThread._data = this._data.clone()), funcThread;
            },
            _minBufferSize: 0,
          }));
          var s =
            ((j.Hasher = k.extend({
              cfg: f.extend(),
              init: function (cfg) {
                this.cfg = this.cfg.extend(cfg);
                this.reset();
              },
              reset: function () {
                k.reset.call(this);
                this._doReset();
              },
              update: function (buffer) {
                return this._append(buffer), this._process(), this;
              },
              finalize: function (a) {
                return a && this._append(a), this._doFinalize();
              },
              blockSize: 16,
              _createHelper: function (hasher) {
                return function (b, cfg) {
                  return new hasher.init(cfg).finalize(b);
                };
              },
              _createHmacHelper: function (hasher) {
                return function (b, f) {
                  return new s.HMAC.init(hasher, f).finalize(b);
                };
              },
            })),
            (p.algo = {}));
          return p;
        })(Math)),
      _module$exports);
  },
  function (mixin, canCreateDiscussions, Var) {
    var node;
    mixin.exports =
      ((node = Var(0)),
      Var(4),
      Var(5),
      Var(2),
      Var(8),
      (function () {
        var C = node;
        var BlockCipher = C.lib.BlockCipher;
        var C_algo = C.algo;
        var SBOX = [];
        var INV_SBOX = [];
        var SUB_MIX_0 = [];
        var SUB_MIX_1 = [];
        var SUB_MIX_2 = [];
        var SUB_MIX_3 = [];
        var INV_SUB_MIX_0 = [];
        var INV_SUB_MIX_1 = [];
        var INV_SUB_MIX_2 = [];
        var INV_SUB_MIX_3 = [];
        !(function () {
          var d = [];
          var search_lemma = 0;
          for (; search_lemma < 256; search_lemma++) {
            d[search_lemma] =
              search_lemma < 128
                ? search_lemma << 1
                : (search_lemma << 1) ^ 283;
          }
          var x = 0;
          var xi = 0;
          search_lemma = 0;
          for (; search_lemma < 256; search_lemma++) {
            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
            sx = (sx >>> 8) ^ (255 & sx) ^ 99;
            SBOX[x] = sx;
            INV_SBOX[sx] = x;
            var x2 = d[x];
            var x4 = d[x2];
            var x8 = d[x4];
            var t = (257 * d[sx]) ^ (16843008 * sx);
            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
            SUB_MIX_2[x] = (t << 8) | (t >>> 24);
            SUB_MIX_3[x] = t;
            t = (16843009 * x8) ^ (65537 * x4) ^ (257 * x2) ^ (16843008 * x);
            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
            INV_SUB_MIX_2[sx] = (t << 8) | (t >>> 24);
            INV_SUB_MIX_3[sx] = t;
            if (x) {
              x = x2 ^ d[d[d[x8 ^ x2]]];
              xi = xi ^ d[d[xi]];
            } else {
              x = xi = 1;
            }
          }
        })();
        var bo = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];
        var AES = (C_algo.AES = BlockCipher.extend({
          _doReset: function () {
            if (!this._nRounds || this._keyPriorReset !== this._key) {
              var key = (this._keyPriorReset = this._key);
              var keyWords = key.words;
              var keySize = key.sigBytes / 4;
              var ksRows = 4 * ((this._nRounds = keySize + 6) + 1);
              var keySchedule = (this._keySchedule = []);
              var ksRow = 0;
              for (; ksRow < ksRows; ksRow++) {
                if (ksRow < keySize) {
                  keySchedule[ksRow] = keyWords[ksRow];
                } else {
                  var t = keySchedule[ksRow - 1];
                  if (ksRow % keySize) {
                    if (keySize > 6 && ksRow % keySize == 4) {
                      t =
                        (SBOX[t >>> 24] << 24) |
                        (SBOX[(t >>> 16) & 255] << 16) |
                        (SBOX[(t >>> 8) & 255] << 8) |
                        SBOX[255 & t];
                    }
                  } else {
                    t =
                      (SBOX[(t = (t << 8) | (t >>> 24)) >>> 24] << 24) |
                      (SBOX[(t >>> 16) & 255] << 16) |
                      (SBOX[(t >>> 8) & 255] << 8) |
                      SBOX[255 & t];
                    t = t ^ (bo[(ksRow / keySize) | 0] << 24);
                  }
                  keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
                }
              }
              var invKeySchedule = (this._invKeySchedule = []);
              var invKsRow = 0;
              for (; invKsRow < ksRows; invKsRow++) {
                ksRow = ksRows - invKsRow;
                t = invKsRow % 4 ? keySchedule[ksRow] : keySchedule[ksRow - 4];
                invKeySchedule[invKsRow] =
                  invKsRow < 4 || ksRow <= 4
                    ? t
                    : INV_SUB_MIX_0[SBOX[t >>> 24]] ^
                      INV_SUB_MIX_1[SBOX[(t >>> 16) & 255]] ^
                      INV_SUB_MIX_2[SBOX[(t >>> 8) & 255]] ^
                      INV_SUB_MIX_3[SBOX[255 & t]];
              }
            }
          },
          encryptBlock: function (M, offset) {
            this._doCryptBlock(
              M,
              offset,
              this._keySchedule,
              SUB_MIX_0,
              SUB_MIX_1,
              SUB_MIX_2,
              SUB_MIX_3,
              SBOX
            );
          },
          decryptBlock: function (M, offset) {
            var t = M[offset + 1];
            M[offset + 1] = M[offset + 3];
            M[offset + 3] = t;
            this._doCryptBlock(
              M,
              offset,
              this._invKeySchedule,
              INV_SUB_MIX_0,
              INV_SUB_MIX_1,
              INV_SUB_MIX_2,
              INV_SUB_MIX_3,
              INV_SBOX
            );
            t = M[offset + 1];
            M[offset + 1] = M[offset + 3];
            M[offset + 3] = t;
          },
          _doCryptBlock: function (
            M,
            offset,
            keySchedule,
            SUB_MIX_0,
            SUB_MIX_1,
            SUB_MIX_2,
            SUB_MIX_3,
            SBOX
          ) {
            var nRounds = this._nRounds;
            var s1 = M[offset] ^ keySchedule[0];
            var s2 = M[offset + 1] ^ keySchedule[1];
            var s3 = M[offset + 2] ^ keySchedule[2];
            var s0 = M[offset + 3] ^ keySchedule[3];
            var ksRow = 4;
            var round = 1;
            for (; round < nRounds; round++) {
              var t =
                SUB_MIX_0[s1 >>> 24] ^
                SUB_MIX_1[(s2 >>> 16) & 255] ^
                SUB_MIX_2[(s3 >>> 8) & 255] ^
                SUB_MIX_3[255 & s0] ^
                keySchedule[ksRow++];
              var t2 =
                SUB_MIX_0[s2 >>> 24] ^
                SUB_MIX_1[(s3 >>> 16) & 255] ^
                SUB_MIX_2[(s0 >>> 8) & 255] ^
                SUB_MIX_3[255 & s1] ^
                keySchedule[ksRow++];
              var t3 =
                SUB_MIX_0[s3 >>> 24] ^
                SUB_MIX_1[(s0 >>> 16) & 255] ^
                SUB_MIX_2[(s1 >>> 8) & 255] ^
                SUB_MIX_3[255 & s2] ^
                keySchedule[ksRow++];
              var t0 =
                SUB_MIX_0[s0 >>> 24] ^
                SUB_MIX_1[(s1 >>> 16) & 255] ^
                SUB_MIX_2[(s2 >>> 8) & 255] ^
                SUB_MIX_3[255 & s3] ^
                keySchedule[ksRow++];
              s1 = t;
              s2 = t2;
              s3 = t3;
              s0 = t0;
            }
            t =
              ((SBOX[s1 >>> 24] << 24) |
                (SBOX[(s2 >>> 16) & 255] << 16) |
                (SBOX[(s3 >>> 8) & 255] << 8) |
                SBOX[255 & s0]) ^
              keySchedule[ksRow++];
            t2 =
              ((SBOX[s2 >>> 24] << 24) |
                (SBOX[(s3 >>> 16) & 255] << 16) |
                (SBOX[(s0 >>> 8) & 255] << 8) |
                SBOX[255 & s1]) ^
              keySchedule[ksRow++];
            t3 =
              ((SBOX[s3 >>> 24] << 24) |
                (SBOX[(s0 >>> 16) & 255] << 16) |
                (SBOX[(s1 >>> 8) & 255] << 8) |
                SBOX[255 & s2]) ^
              keySchedule[ksRow++];
            t0 =
              ((SBOX[s0 >>> 24] << 24) |
                (SBOX[(s1 >>> 16) & 255] << 16) |
                (SBOX[(s2 >>> 8) & 255] << 8) |
                SBOX[255 & s3]) ^
              keySchedule[ksRow++];
            M[offset] = t;
            M[offset + 1] = t2;
            M[offset + 2] = t3;
            M[offset + 3] = t0;
          },
          keySize: 8,
        }));
        C.AES = BlockCipher._createHelper(AES);
      })(),
      node.AES);
  },
  function (mixin, canCreateDiscussions, Var) {
    var C;
    var _ref;
    var Base;
    var WordArray;
    var C_algo;
    var SHA1;
    var PBKDF1;
    var node;
    mixin.exports =
      ((node = Var(0)),
      Var(6),
      Var(7),
      (_ref = (C = node).lib),
      (Base = _ref.Base),
      (WordArray = _ref.WordArray),
      (C_algo = C.algo),
      (SHA1 = C_algo.MD5),
      (PBKDF1 = C_algo.EvpKDF =
        Base.extend({
          cfg: Base.extend({ keySize: 4, hasher: SHA1, iterations: 1 }),
          init: function (cfg) {
            this.cfg = this.cfg.extend(cfg);
          },
          compute: function (data, key) {
            var cfg = this.cfg;
            var sha256 = cfg.hasher.create();
            var a = WordArray.create();
            var derivedKeyWords = a.words;
            var keySize = cfg.keySize;
            var iterations = cfg.iterations;
            for (; derivedKeyWords.length < keySize; ) {
              if (b) {
                sha256.update(b);
              }
              var b = sha256.update(data).finalize(key);
              sha256.reset();
              var iteration = 1;
              for (; iteration < iterations; iteration++) {
                b = sha256.finalize(b);
                sha256.reset();
              }
              a.concat(b);
            }
            return (a.sigBytes = 4 * keySize), a;
          },
        })),
      (C.EvpKDF = function (password, salt, cfg) {
        return PBKDF1.create(cfg).compute(password, salt);
      }),
      node.EvpKDF);
  },
  function (mixin, canCreateDiscussions, wrapper) {
    var C;
    mixin.exports = ((C = wrapper(0)), C.enc.Utf8);
  },
  function (mixin, canCreateDiscussions, new_val_func) {
    var C;
    var WordArray;
    var h;
    mixin.exports =
      ((h = new_val_func(0)),
      (WordArray = (C = h).lib.WordArray),
      (C.enc.Base64 = {
        stringify: function (b) {
          var c = b.words;
          var r = b.sigBytes;
          var map = this._map;
          b.clamp();
          var result = [];
          var d = 0;
          for (; d < r; d = d + 3) {
            var cC =
              (((c[d >>> 2] >>> (24 - (d % 4) * 8)) & 255) << 16) |
              (((c[(d + 1) >>> 2] >>> (24 - ((d + 1) % 4) * 8)) & 255) << 8) |
              ((c[(d + 2) >>> 2] >>> (24 - ((d + 2) % 4) * 8)) & 255);
            var dx = 0;
            for (; dx < 4 && d + 0.75 * dx < r; dx++) {
              result.push(map.charAt((cC >>> (6 * (3 - dx))) & 63));
            }
          }
          var embedResult = map.charAt(64);
          if (embedResult) {
            for (; result.length % 4; ) {
              result.push(embedResult);
            }
          }
          return result.join("");
        },
        parse: function (data) {
          var res = data.length;
          var m = this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            reverseMap = this._reverseMap = [];
            var j = 0;
            for (; j < m.length; j++) {
              reverseMap[m.charCodeAt(j)] = j;
            }
          }
          var level = m.charAt(64);
          if (level) {
            var label = data.indexOf(level);
            if (-1 !== label) {
              res = label;
            }
          }
          return (function (base64Str, bin, reverseMap) {
            var words = [];
            var nBytes = 0;
            var i = 0;
            for (; i < bin; i++) {
              if (i % 4) {
                var cL =
                  reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
                var dL =
                  reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
                words[nBytes >>> 2] |= (cL | dL) << (24 - (nBytes % 4) * 8);
                nBytes++;
              }
            }
            return WordArray.create(words, nBytes);
          })(data, res, reverseMap);
        },
        _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      }),
      h.enc.Base64);
  },
  function (mixin, canCreateDiscussions, require) {
    var CryptoJS;
    mixin.exports =
      ((CryptoJS = require(0)),
      (function (m) {
        function debug(i, d, a, b, name, s, end) {
          var n = i + ((d & a) | (~d & b)) + name + end;
          return ((n << s) | (n >>> (32 - s))) + d;
        }
        function fn(v, d, t, a, id, n, start) {
          var x = v + ((d & a) | (t & ~a)) + id + start;
          return ((x << n) | (x >>> (32 - n))) + d;
        }
        function format(uri, d, a, b, name, n, start) {
          var x = uri + (d ^ a ^ b) + name + start;
          return ((x << n) | (x >>> (32 - n))) + d;
        }
        function extend(s, n, t, name, a, l, id) {
          var h = s + (t ^ (n | ~name)) + a + id;
          return ((h << l) | (h >>> (32 - l))) + n;
        }
        var C = CryptoJS;
        var m = C.lib;
        var p = m.WordArray;
        var j = m.Hasher;
        var C_algo = C.algo;
        var a = [];
        !(function () {
          var r = 0;
          for (; r < 64; r++) {
            a[r] = (4294967296 * m.abs(m.sin(r + 1))) | 0;
          }
        })();
        var MD5 = (C_algo.MD5 = j.extend({
          _doReset: function () {
            this._hash = new p.init([
              1732584193, 4023233417, 2562383102, 271733878,
            ]);
          },
          _doProcessBlock: function (args, n) {
            var offset = 0;
            for (; offset < 16; offset++) {
              var i = n + offset;
              var sqlParam = args[i];
              args[i] =
                (16711935 & ((sqlParam << 8) | (sqlParam >>> 24))) |
                (4278255360 & ((sqlParam << 24) | (sqlParam >>> 8)));
            }
            var pair = this._hash.words;
            var self = args[n + 0];
            var status = args[n + 1];
            var k = args[n + 2];
            var type = args[n + 3];
            var index = args[n + 4];
            var options = args[n + 5];
            var t = args[n + 6];
            var url = args[n + 7];
            var i = args[n + 8];
            var count = args[n + 9];
            var y = args[n + 10];
            var callback = args[n + 11];
            var name = args[n + 12];
            var key = args[n + 13];
            var config = args[n + 14];
            var user = args[n + 15];
            var value = pair[0];
            var result = pair[1];
            var obj = pair[2];
            var data = pair[3];
            value = debug(value, result, obj, data, self, 7, a[0]);
            data = debug(data, value, result, obj, status, 12, a[1]);
            obj = debug(obj, data, value, result, k, 17, a[2]);
            result = debug(result, obj, data, value, type, 22, a[3]);
            value = debug(value, result, obj, data, index, 7, a[4]);
            data = debug(data, value, result, obj, options, 12, a[5]);
            obj = debug(obj, data, value, result, t, 17, a[6]);
            result = debug(result, obj, data, value, url, 22, a[7]);
            value = debug(value, result, obj, data, i, 7, a[8]);
            data = debug(data, value, result, obj, count, 12, a[9]);
            obj = debug(obj, data, value, result, y, 17, a[10]);
            result = debug(result, obj, data, value, callback, 22, a[11]);
            value = debug(value, result, obj, data, name, 7, a[12]);
            data = debug(data, value, result, obj, key, 12, a[13]);
            obj = debug(obj, data, value, result, config, 17, a[14]);
            value = fn(
              value,
              (result = debug(result, obj, data, value, user, 22, a[15])),
              obj,
              data,
              status,
              5,
              a[16]
            );
            data = fn(data, value, result, obj, t, 9, a[17]);
            obj = fn(obj, data, value, result, callback, 14, a[18]);
            result = fn(result, obj, data, value, self, 20, a[19]);
            value = fn(value, result, obj, data, options, 5, a[20]);
            data = fn(data, value, result, obj, y, 9, a[21]);
            obj = fn(obj, data, value, result, user, 14, a[22]);
            result = fn(result, obj, data, value, index, 20, a[23]);
            value = fn(value, result, obj, data, count, 5, a[24]);
            data = fn(data, value, result, obj, config, 9, a[25]);
            obj = fn(obj, data, value, result, type, 14, a[26]);
            result = fn(result, obj, data, value, i, 20, a[27]);
            value = fn(value, result, obj, data, key, 5, a[28]);
            data = fn(data, value, result, obj, k, 9, a[29]);
            obj = fn(obj, data, value, result, url, 14, a[30]);
            value = format(
              value,
              (result = fn(result, obj, data, value, name, 20, a[31])),
              obj,
              data,
              options,
              4,
              a[32]
            );
            data = format(data, value, result, obj, i, 11, a[33]);
            obj = format(obj, data, value, result, callback, 16, a[34]);
            result = format(result, obj, data, value, config, 23, a[35]);
            value = format(value, result, obj, data, status, 4, a[36]);
            data = format(data, value, result, obj, index, 11, a[37]);
            obj = format(obj, data, value, result, url, 16, a[38]);
            result = format(result, obj, data, value, y, 23, a[39]);
            value = format(value, result, obj, data, key, 4, a[40]);
            data = format(data, value, result, obj, self, 11, a[41]);
            obj = format(obj, data, value, result, type, 16, a[42]);
            result = format(result, obj, data, value, t, 23, a[43]);
            value = format(value, result, obj, data, count, 4, a[44]);
            data = format(data, value, result, obj, name, 11, a[45]);
            obj = format(obj, data, value, result, user, 16, a[46]);
            value = extend(
              value,
              (result = format(result, obj, data, value, k, 23, a[47])),
              obj,
              data,
              self,
              6,
              a[48]
            );
            data = extend(data, value, result, obj, url, 10, a[49]);
            obj = extend(obj, data, value, result, config, 15, a[50]);
            result = extend(result, obj, data, value, options, 21, a[51]);
            value = extend(value, result, obj, data, name, 6, a[52]);
            data = extend(data, value, result, obj, type, 10, a[53]);
            obj = extend(obj, data, value, result, y, 15, a[54]);
            result = extend(result, obj, data, value, status, 21, a[55]);
            value = extend(value, result, obj, data, i, 6, a[56]);
            data = extend(data, value, result, obj, user, 10, a[57]);
            obj = extend(obj, data, value, result, t, 15, a[58]);
            result = extend(result, obj, data, value, key, 21, a[59]);
            value = extend(value, result, obj, data, index, 6, a[60]);
            data = extend(data, value, result, obj, callback, 10, a[61]);
            obj = extend(obj, data, value, result, k, 15, a[62]);
            result = extend(result, obj, data, value, count, 21, a[63]);
            pair[0] = (pair[0] + value) | 0;
            pair[1] = (pair[1] + result) | 0;
            pair[2] = (pair[2] + obj) | 0;
            pair[3] = (pair[3] + data) | 0;
          },
          _doFinalize: function () {
            var d = this._data;
            var q = d.words;
            var c = 8 * this._nDataBytes;
            var b = 8 * d.sigBytes;
            q[b >>> 5] |= 128 << (24 - (b % 32));
            var d2 = m.floor(c / 4294967296);
            var a = c;
            q[15 + (((b + 64) >>> 9) << 4)] =
              (16711935 & ((d2 << 8) | (d2 >>> 24))) |
              (4278255360 & ((d2 << 24) | (d2 >>> 8)));
            q[14 + (((b + 64) >>> 9) << 4)] =
              (16711935 & ((a << 8) | (a >>> 24))) |
              (4278255360 & ((a << 24) | (a >>> 8)));
            d.sigBytes = 4 * (q.length + 1);
            this._process();
            var hash = this._hash;
            var H = hash.words;
            var j = 0;
            for (; j < 4; j++) {
              var a = H[j];
              H[j] =
                (16711935 & ((a << 8) | (a >>> 24))) |
                (4278255360 & ((a << 24) | (a >>> 8)));
            }
            return hash;
          },
          clone: function () {
            var _this = j.clone.call(this);
            return (_this._hash = this._hash.clone()), _this;
          },
        }));
        C.MD5 = j._createHelper(MD5);
        C.HmacMD5 = j._createHmacHelper(MD5);
      })(Math),
      CryptoJS.MD5);
  },
  function (mixin, canCreateDiscussions, sameLevelNextIndex) {
    var e;
    var b;
    var WordArray;
    var j;
    var _ref;
    var l;
    var m;
    var i;
    mixin.exports =
      ((i = sameLevelNextIndex(0)),
      (b = (e = i).lib),
      (WordArray = b.WordArray),
      (j = b.Hasher),
      (_ref = e.algo),
      (l = []),
      (m = _ref.SHA1 =
        j.extend({
          _doReset: function () {
            this._hash = new WordArray.init([
              1732584193, 4023233417, 2562383102, 271733878, 3285377520,
            ]);
          },
          _doProcessBlock: function (f, n) {
            var b = this._hash.words;
            var h = b[0];
            var g = b[1];
            var e = b[2];
            var k = b[3];
            var j = b[4];
            var a = 0;
            for (; a < 80; a++) {
              if (a < 16) {
                l[a] = 0 | f[n + a];
              } else {
                var et = l[a - 3] ^ l[a - 8] ^ l[a - 14] ^ l[a - 16];
                l[a] = (et << 1) | (et >>> 31);
              }
              var deltaY = ((h << 5) | (h >>> 27)) + j + l[a];
              deltaY =
                deltaY +
                (a < 20
                  ? 1518500249 + ((g & e) | (~g & k))
                  : a < 40
                  ? 1859775393 + (g ^ e ^ k)
                  : a < 60
                  ? ((g & e) | (g & k) | (e & k)) - 1894007588
                  : (g ^ e ^ k) - 899497514);
              j = k;
              k = e;
              e = (g << 30) | (g >>> 2);
              g = h;
              h = deltaY;
            }
            b[0] = (b[0] + h) | 0;
            b[1] = (b[1] + g) | 0;
            b[2] = (b[2] + e) | 0;
            b[3] = (b[3] + k) | 0;
            b[4] = (b[4] + j) | 0;
          },
          _doFinalize: function () {
            var f = this._data;
            var d = f.words;
            var b = 8 * this._nDataBytes;
            var c = 8 * f.sigBytes;
            return (
              (d[c >>> 5] |= 128 << (24 - (c % 32))),
              (d[14 + (((c + 64) >>> 9) << 4)] = Math.floor(b / 4294967296)),
              (d[15 + (((c + 64) >>> 9) << 4)] = b),
              (f.sigBytes = 4 * d.length),
              this._process(),
              this._hash
            );
          },
          clone: function () {
            var _this = j.clone.call(this);
            return (_this._hash = this._hash.clone()), _this;
          },
        })),
      (e.SHA1 = j._createHelper(m)),
      (e.HmacSHA1 = j._createHmacHelper(m)),
      i.SHA1);
  },
  function (mixin, canCreateDiscussions, makeButton) {
    var b;
    var C;
    var Base;
    var primParser;
    mixin.exports =
      ((b = makeButton(0)),
      (Base = (C = b).lib.Base),
      (primParser = C.enc.Utf8),
      void (C.algo.HMAC = Base.extend({
        init: function (e, data) {
          e = this._hasher = new e.init();
          if ("string" == typeof data) {
            data = primParser.parse(data);
          }
          var i = e.blockSize;
          var k = 4 * i;
          if (data.sigBytes > k) {
            data = e.finalize(data);
          }
          data.clamp();
          var o = (this._oKey = data.clone());
          var d = (this._iKey = data.clone());
          var c = o.words;
          var h = d.words;
          var j = 0;
          for (; j < i; j++) {
            c[j] ^= 1549556828;
            h[j] ^= 909522486;
          }
          o.sigBytes = d.sigBytes = k;
          this.reset();
        },
        reset: function () {
          var hasher = this._hasher;
          hasher.reset();
          hasher.update(this._iKey);
        },
        update: function (buf) {
          return this._hasher.update(buf), this;
        },
        finalize: function (obj) {
          var f = this._hasher;
          var data = f.finalize(obj);
          return f.reset(), f.finalize(this._oKey.clone().concat(data));
        },
      })));
  },
  function (mixin, canCreateDiscussions, require) {
    var CryptoJS;
    mixin.exports =
      ((CryptoJS = require(0)),
      require(2),
      void (
        CryptoJS.lib.Cipher ||
        (function (undefined) {
          var C = CryptoJS;
          var C_lib = C.lib;
          var Base = C_lib.Base;
          var WordArray = C_lib.WordArray;
          var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
          var C_enc = C.enc;
          var Base64 = (C_enc.Utf8, C_enc.Base64);
          var EvpKDF = C.algo.EvpKDF;
          var Cipher = (C_lib.Cipher = BufferedBlockAlgorithm.extend({
            cfg: Base.extend(),
            createEncryptor: function (cfg, key) {
              return this.create(this._ENC_XFORM_MODE, cfg, key);
            },
            createDecryptor: function (cfg, key) {
              return this.create(this._DEC_XFORM_MODE, cfg, key);
            },
            init: function (xformMode, key, cfg) {
              this.cfg = this.cfg.extend(cfg);
              this._xformMode = xformMode;
              this._key = key;
              this.reset();
            },
            reset: function () {
              BufferedBlockAlgorithm.reset.call(this);
              this._doReset();
            },
            process: function (dataUpdate) {
              return this._append(dataUpdate), this._process();
            },
            finalize: function (a) {
              return a && this._append(a), this._doFinalize();
            },
            keySize: 4,
            ivSize: 4,
            _ENC_XFORM_MODE: 1,
            _DEC_XFORM_MODE: 2,
            _createHelper: (function () {
              function selectCipherStrategy(key) {
                return "string" == typeof key ? index : SerializableCipher;
              }
              return function (cipher) {
                return {
                  encrypt: function (message, key, cfg) {
                    return selectCipherStrategy(key).encrypt(
                      cipher,
                      message,
                      key,
                      cfg
                    );
                  },
                  decrypt: function (ciphertext, key, cfg) {
                    return selectCipherStrategy(key).decrypt(
                      cipher,
                      ciphertext,
                      key,
                      cfg
                    );
                  },
                };
              };
            })(),
          }));
          var C_mode =
            ((C_lib.StreamCipher = Cipher.extend({
              _doFinalize: function () {
                return this._process(true);
              },
              blockSize: 1,
            })),
            (C.mode = {}));
          var BufferedNode = (C_lib.BlockCipherMode = Base.extend({
            createEncryptor: function (cipher, iv) {
              return this.Encryptor.create(cipher, iv);
            },
            createDecryptor: function (cipher, iv) {
              return this.Decryptor.create(cipher, iv);
            },
            init: function (cipher, iv) {
              this._cipher = cipher;
              this._iv = iv;
            },
          }));
          var MODE_DRAWING_LINE = (C_mode.CBC = (function () {
            function generateKeystreamAndEncrypt(words, offset, blockSize) {
              var iv = this._iv;
              if (iv) {
                var block = iv;
                this._iv = undefined;
              } else {
                block = this._prevBlock;
              }
              var i = 0;
              for (; i < blockSize; i++) {
                words[offset + i] ^= block[i];
              }
            }
            var CTRGladman = BufferedNode.extend();
            return (
              (CTRGladman.Encryptor = CTRGladman.extend({
                processBlock: function (words, offset) {
                  var cipher = this._cipher;
                  var blockSize = cipher.blockSize;
                  generateKeystreamAndEncrypt.call(
                    this,
                    words,
                    offset,
                    blockSize
                  );
                  cipher.encryptBlock(words, offset);
                  this._prevBlock = words.slice(offset, offset + blockSize);
                },
              })),
              (CTRGladman.Decryptor = CTRGladman.extend({
                processBlock: function (words, offset) {
                  var cipher = this._cipher;
                  var blockSize = cipher.blockSize;
                  var thisBlock = words.slice(offset, offset + blockSize);
                  cipher.decryptBlock(words, offset);
                  generateKeystreamAndEncrypt.call(
                    this,
                    words,
                    offset,
                    blockSize
                  );
                  this._prevBlock = thisBlock;
                },
              })),
              CTRGladman
            );
          })());
          var padding = ((C.pad = {}).Pkcs7 = {
            pad: function (data, callback) {
              var blockSizeBytes = 4 * callback;
              var nPaddingBytes =
                blockSizeBytes - (data.sigBytes % blockSizeBytes);
              var paddingWord =
                (nPaddingBytes << 24) |
                (nPaddingBytes << 16) |
                (nPaddingBytes << 8) |
                nPaddingBytes;
              var paddingWords = [];
              var i = 0;
              for (; i < nPaddingBytes; i = i + 4) {
                paddingWords.push(paddingWord);
              }
              var padding = WordArray.create(paddingWords, nPaddingBytes);
              data.concat(padding);
            },
            unpad: function (data) {
              var nBytesReady = 255 & data.words[(data.sigBytes - 1) >>> 2];
              data.sigBytes -= nBytesReady;
            },
          });
          var CipherParams =
            ((C_lib.BlockCipher = Cipher.extend({
              cfg: Cipher.cfg.extend({
                mode: MODE_DRAWING_LINE,
                padding: padding,
              }),
              reset: function () {
                Cipher.reset.call(this);
                var cfg = this.cfg;
                var iv = cfg.iv;
                var mode = cfg.mode;
                if (this._xformMode == this._ENC_XFORM_MODE) {
                  var modeCreator = mode.createEncryptor;
                } else {
                  modeCreator = mode.createDecryptor;
                  this._minBufferSize = 1;
                }
                if (this._mode && this._mode.__creator == modeCreator) {
                  this._mode.init(this, iv && iv.words);
                } else {
                  this._mode = modeCreator.call(mode, this, iv && iv.words);
                  this._mode.__creator = modeCreator;
                }
              },
              _doProcessBlock: function (words, offset) {
                this._mode.processBlock(words, offset);
              },
              _doFinalize: function () {
                var padding = this.cfg.padding;
                if (this._xformMode == this._ENC_XFORM_MODE) {
                  padding.pad(this._data, this.blockSize);
                  var finalProcessedBlocks = this._process(true);
                } else {
                  finalProcessedBlocks = this._process(true);
                  padding.unpad(finalProcessedBlocks);
                }
                return finalProcessedBlocks;
              },
              blockSize: 4,
            })),
            (C_lib.CipherParams = Base.extend({
              init: function (cipherParams) {
                this.mixIn(cipherParams);
              },
              toString: function (formatter) {
                return (formatter || this.formatter).stringify(this);
              },
            })));
          var sourceFormat = ((C.format = {}).OpenSSL = {
            stringify: function (options) {
              var ciphertext = options.ciphertext;
              var salt = options.salt;
              if (salt) {
                var wordArray = WordArray.create([1398893684, 1701076831])
                  .concat(salt)
                  .concat(ciphertext);
              } else {
                wordArray = ciphertext;
              }
              return wordArray.toString(Base64);
            },
            parse: function (data) {
              var ciphertext = Base64.parse(data);
              var ciphertextWords = ciphertext.words;
              if (
                1398893684 == ciphertextWords[0] &&
                1701076831 == ciphertextWords[1]
              ) {
                var generatedSalt = WordArray.create(
                  ciphertextWords.slice(2, 4)
                );
                ciphertextWords.splice(0, 4);
                ciphertext.sigBytes -= 16;
              }
              return CipherParams.create({
                ciphertext: ciphertext,
                salt: generatedSalt,
              });
            },
          });
          var SerializableCipher = (C_lib.SerializableCipher = Base.extend({
            cfg: Base.extend({ format: sourceFormat }),
            encrypt: function (cipher, message, key, cfg) {
              cfg = this.cfg.extend(cfg);
              var encryptor = cipher.createEncryptor(key, cfg);
              var ciphertext = encryptor.finalize(message);
              var cipherCfg = encryptor.cfg;
              return CipherParams.create({
                ciphertext: ciphertext,
                key: key,
                iv: cipherCfg.iv,
                algorithm: cipher,
                mode: cipherCfg.mode,
                padding: cipherCfg.padding,
                blockSize: cipher.blockSize,
                formatter: cfg.format,
              });
            },
            decrypt: function (cipher, ciphertext, key, cfg) {
              return (
                (cfg = this.cfg.extend(cfg)),
                (ciphertext = this._parse(ciphertext, cfg.format)),
                cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext)
              );
            },
            _parse: function (data, address) {
              return "string" == typeof data ? address.parse(data, this) : data;
            },
          }));
          var OpenSSLKdf = ((C.kdf = {}).OpenSSL = {
            execute: function (password, keySize, ivSize, salt) {
              if (!salt) {
                salt = WordArray.random(8);
              }
              var hash = EvpKDF.create({ keySize: keySize + ivSize }).compute(
                password,
                salt
              );
              var iv = WordArray.create(hash.words.slice(keySize), 4 * ivSize);
              return (
                (hash.sigBytes = 4 * keySize),
                CipherParams.create({ key: hash, iv: iv, salt: salt })
              );
            },
          });
          var index = (C_lib.PasswordBasedCipher = SerializableCipher.extend({
            cfg: SerializableCipher.cfg.extend({ kdf: OpenSSLKdf }),
            encrypt: function (cipher, message, password, cfg) {
              var derivedParams = (cfg = this.cfg.extend(cfg)).kdf.execute(
                password,
                cipher.keySize,
                cipher.ivSize
              );
              cfg.iv = derivedParams.iv;
              var ciphertext = SerializableCipher.encrypt.call(
                this,
                cipher,
                message,
                derivedParams.key,
                cfg
              );
              return ciphertext.mixIn(derivedParams), ciphertext;
            },
            decrypt: function (cipher, ciphertext, key, cfg) {
              cfg = this.cfg.extend(cfg);
              ciphertext = this._parse(ciphertext, cfg.format);
              var res = cfg.kdf.execute(
                key,
                cipher.keySize,
                cipher.ivSize,
                ciphertext.salt
              );
              return (
                (cfg.iv = res.iv),
                SerializableCipher.decrypt.call(
                  this,
                  cipher,
                  ciphertext,
                  res.key,
                  cfg
                )
              );
            },
          }));
        })()
      ));
  },
  function (canCreateDiscussions, d, __webpack_require__) {
    __webpack_require__.r(d);
    var __WEBPACK_IMPORTED_MODULE_1_jsmidgen__ = __webpack_require__(1);
    var app = __webpack_require__.n(__WEBPACK_IMPORTED_MODULE_1_jsmidgen__);
    var __WEBPACK_IMPORTED_MODULE_2__foundation_util_mediaQuery__ =
      __webpack_require__(3);
    var vop = __webpack_require__.n(
      __WEBPACK_IMPORTED_MODULE_2__foundation_util_mediaQuery__
    );
    document.addEventListener("DOMContentLoaded", function () {
      var init = function (name, url) {
        if (!url) {
          url = location.href;
        }
        name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
        var linkedInUrl = new RegExp("[\\?&]" + name + "=([^&#]*)").exec(url);
        return null == linkedInUrl ? null : linkedInUrl[1];
      };
      var data = document.querySelector(
        "script#universalsafelink[data-copyright=anasrar][data-version]"
      );
      var getAttribute = function (elem, key) {
        return elem.getAttribute("data-"["concat"](key));
      };
      if (data) {
        if ("1" === init("safelink")) {
          var multiRows = getAttribute(data, "page").split("|");
          var fontEl = document.createElement("style");
          fontEl.appendChild(
            document.createTextNode(
              ".universalsafelinkbtn{display:none;position:fixed;bottom:1rem;left:1rem;box-sizing:border-box;margin:0;text-transform:none;-webkit-appearance:button;cursor:pointer;background:#fff;align-items:center;padding:.5rem .75rem;color:#333;transition:all .2s linear}.universalsafelinkbtn.tampilkan{display:inline-block}.universalsafelinkbtn *{box-sizing:border-box}.universalsafelinkbtn,.universalsafelinkcontainer{background:#fff;border-radius:.25rem;border-bottom:2px #f56565 solid;box-shadow:0 4px 6px -1px rgba(0,0,0,.4),0 2px 4px -1px rgba(0,0,0,.36)}.universalsafelinkbtn:hover{background:#f56565;border-bottom:2px #e53e3e solid;color:#fff}.universalsafelinkbtn:focus,.universalsafelinkcontainer>form>input[type=text]:focus,#universalsafelinkclosebtn{outline:none}.universalsafelinkdrawer{display:none;align-items:center;justify-content:center;position:fixed;top:0;left:0;width:100%;height:100%;padding:1rem;background:rgba(0,0,0,.8);z-index:999999}.universalsafelinkdrawer.tampilkan{display:flex}.universalsafelinkcontainer{position:relative;padding:1rem 1rem 0;box-shadow:0 4px 6px -1px rgba(0,0,0,.4),0 2px 4px -1px rgba(0,0,0,.36)}#universalsafelinkclosebtn{position:absolute;right:-1rem;top:-1rem;color:#fff;background:#e53e3e;padding:.5rem;border-radius:99999px;border-bottom:2px #8b1313 solid;-webkit-appearance:button}#universalsafelinkclosebtn:hover,.universalsafelinkcontainer>form>button:hover{background:#e01f1f}.universalsafelinkcontainer>h3{border-radius:.15rem .15rem 0 0;color:#fff;background:#e53e3e;font-size:1.25rem;text-transform:uppercase;font-weight:600;margin:-1rem -1rem 1rem;padding:1rem}.universalsafelinkcontainer>form>input[type=text],.universalsafelinkcontainer>.wrapresult>input[type=text]{display:block;background:#eee;width:100%;padding:.5rem;border-radius:.25rem;border:1px #ddd solid;margin-bottom:1rem}.universalsafelinkcontainer>form>button{display:block;color:#fff;background:#e53e3e;width:100%;padding:.5rem;border-radius:.25rem;border:1px #d31d1d solid;margin-bottom:1rem;font-size:1rem;text-transform:uppercase;font-weight:600}"
            )
          );
          document.head.appendChild(fontEl);
          var section = document.createElement("section");
          var btnPause = document.createElement("button");
          section.setAttribute("class", "universalsafelinkdrawer");
          section.innerHTML = `<div class='universalsafelinkcontainer'><button id="universalsafelinkclosebtn"><svg style="width:1.5rem;height:1.5rem" viewBox="0 0 24 24"><path fill="currentColor" d="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z" /></svg></button><h3><svg style="width:1.5rem;height:1.5rem;display: inline" viewBox="0 0 24 24"><path fill="currentColor" d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.1 14.8,9.5V11C15.4,11 16,11.6 16,12.3V15.8C16,16.4 15.4,17 14.7,17H9.2C8.6,17 8,16.4 8,15.7V12.2C8,11.6 8.6,11 9.2,11V9.5C9.2,8.1 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,9.5V11H13.5V9.5C13.5,8.7 12.8,8.2 12,8.2Z" /></svg> Universal Safelink</h3><form><input type="text" name="url" placeholder="http or https" /><button type="submit">Convert</button></form><div class="wrapresult"><input type="text" name="result" /></div></div>`;
          section
            .querySelector("form")
            .addEventListener("submit", function (event) {
              if (
                (event.preventDefault(),
                event.target.querySelector("[name=url]").value.length)
              ) {
                var otpUrl = app.a
                  .encrypt(
                    event.target.querySelector("[name=url]").value,
                    "anasrar"
                  )
                  .toString();
                event.target.parentNode.querySelector("[name=result]").value =
                  ""
                    ["concat"](location.protocol, "//")
                    .concat(location.hostname)
                    .concat(
                      multiRows[~~(Math.random() * multiRows.length)],
                      "?u="
                    )
                    .concat(encodeURIComponent(otpUrl));
              }
            });
          section
            .querySelector("#universalsafelinkclosebtn")
            .addEventListener("click", function (event) {
              event.preventDefault();
              section.classList.remove("tampilkan");
              btnPause.classList.add("tampilkan");
            });
          document.body.appendChild(section);
          btnPause.setAttribute("class", "universalsafelinkbtn tampilkan");
          btnPause.innerHTML =
            '<svg style="width:24px;height:24px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.1 14.8,9.5V11C15.4,11 16,11.6 16,12.3V15.8C16,16.4 15.4,17 14.7,17H9.2C8.6,17 8,16.4 8,15.7V12.2C8,11.6 8.6,11 9.2,11V9.5C9.2,8.1 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,9.5V11H13.5V9.5C13.5,8.7 12.8,8.2 12,8.2Z" /></svg>';
          btnPause.addEventListener("click", function (event) {
            event.preventDefault();
            section.classList.add("tampilkan");
            btnPause.classList.remove("tampilkan");
          });
          document.body.appendChild(btnPause);
        }
        var lnkDiv = document.querySelector("#universalsafelinkoutput");
        if (init("u") && lnkDiv) {
          var res = app.a
            .decrypt(decodeURIComponent(init("u")), "anasrar")
            .toString(vop.a);
          if (parseInt(getAttribute(data, "countdown"))) {
            var whiteRating = parseInt(getAttribute(data, "countdown"));
            var chat_retry = setInterval(function () {
              lnkDiv.innerHTML = '<span class="savelinkoutputcountdown">'[
                "concat"
              ](
                getAttribute(data, "counttext").replace(
                  "{{time}}",
                  whiteRating
                ),
                "</span>"
              );
              if (whiteRating < 1) {
                if ("true" === getAttribute(data, "autodirect")) {
                  window.location = res;
                } else {
                  lnkDiv.innerHTML = '<a href="'
                    ["concat"](res, '" class="savelinkoutputlink">')
                    .concat(getAttribute(data, "gotext"), "</a>");
                }
                clearInterval(chat_retry);
              }
              whiteRating = whiteRating - 1;
            }, 1e3);
          } else {
            if ("true" === getAttribute(data, "autodirect")) {
              window.location = res;
            } else {
              lnkDiv.innerHTML = '<a href="'
                ["concat"](res, '" class="savelinkoutputlink">')
                .concat(getAttribute(data, "gotext"), "</a>");
            }
          }
        }
        if (
          "true" === getAttribute(data, "autogenerate") &&
          getAttribute(data, "blacklist")
        ) {
          var related_node_ids = getAttribute(data, "blacklist").split("|");
          var multiRows = getAttribute(data, "page").split("|");
          Array.prototype.forEach.call(
            document.querySelectorAll("a"),
            function (result) {
              if (
                result.hostname.length &&
                -1 === related_node_ids.indexOf(result.hostname.toLowerCase())
              ) {
                var otpUrl = app.a.encrypt(result.href, "anasrar").toString();
                result.href = ""
                  ["concat"](location.protocol, "//")
                  .concat(location.hostname)
                  .concat(
                    multiRows[~~(Math.random() * multiRows.length)],
                    "?u="
                  )
                  .concat(encodeURIComponent(otpUrl));
              }
            }
          );
        }
      } else {
        window.location = "https://anasrar.github.io/blog/";
      }
      data.remove();
    });
  },
]);
