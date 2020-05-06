using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JWT
{
    public JwtHashAlgorithm
    {
        HS256,
        HS384,
        HS512
    }

    public static class JsonWebToken
    {
        private static readonly IDictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;
        public static IJsonSerializer JsonSerializer = new DefaultJsonSerializer();
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        static JsonWebToken()
        {
            HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
            {
                { JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
                { JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
            };
        }

        public static string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            var segments = new List<string>();
            var header = new Dictionary<string, object>(extraHeaders)
            {
                { "typ", "JWT" },
                { "alg", algorithm.ToString() }
            };

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = HashAlgorithms[algorithm](key, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public static string Encode(object payload, byte[] key, JwtHashAlgorithm algorithm)
        {
            return Encode(new Dictionary<string, object>(), payload, key, algorithm);
        }

        public static string Encode(IDictionary<string, object> extraHeaders, object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(extraHeaders, payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        public static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return Encode(new Dictionary<string, object>(), payload, Encoding.UTF8.GetBytes(key), algorithm);
        }

        public static string Decode(string token, byte[] key, bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }
            var header = parts[0];
            var payload = parts[1];
            var crypto = Base64UrlDecode(parts[2]);

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

            var headerData = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

            if (verify)
            {
                var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                var algorithm = (string)headerData["alg"];

                var signature = HashAlgorithms[GetHashAlgorithm(algorithm)](key, bytesToSign);
                var decodedCrypto = Convert.ToBase64String(crypto);
                var decodedSignature = Convert.ToBase64String(signature);

                Verify(decodedCrypto, decodedSignature, payloadJson);
            }

            return payloadJson;
        }

        private static void Verify(string decodedCrypto, string decodedSignature, string payloadJson)
        {
            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
            }

            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            if (payloadData.ContainsKey("exp") && payloadData["exp"] != null)
            {
                int exp;
                try
                {
                    exp = Convert.ToInt32(payloadData["exp"]);
                }
                catch (Exception)
                {
                    throw new SignatureVerificationException("Claim 'exp' must be an integer.");
                }

                var secondsSinceEpoch = Math.Round((DateTime.UtcNow - UnixEpoch).TotalSeconds);
                if (secondsSinceEpoch >= exp)
                {
                    throw new SignatureVerificationException("Token has expired.");
                }
            }
        }

        public static string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        public static object DecodeToObject(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            return payloadData;
        }

        public static object DecodeToObject(string token, string key, bool verify = true)
        {
            return DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);
        }

        public static T DecodeToObject<T>(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            var payloadData = JsonSerializer.Deserialize<T>(payloadJson);
            return payloadData;
        }

        public static T DecodeToObject<T>(string token, string key, bool verify = true)
        {
            return DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);
        }

        private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "HS256": return JwtHashAlgorithm.HS256;
                case "HS384": return JwtHashAlgorithm.HS384;
                case "HS512": return JwtHashAlgorithm.HS512;
                default: throw new SignatureVerificationException("Algorithm not supported.");
            }
        }

        public static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0];
            output = output.Replace('+', '-');
            output = output.Replace('/', '_');
            return output;
        }

        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break;
                case 2: output += "=="; break;
                case 3: output += "="; break;
                default: throw new Exception("Illegal base64url string!");
            }

            var converted = Convert.FromBase64String(output);
            return converted;
        }
    }
}
