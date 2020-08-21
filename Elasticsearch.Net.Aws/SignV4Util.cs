using Amazon.Runtime;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Elasticsearch.Net.Aws
{
    internal static class SignV4Util
    {
        private static readonly char[] _datePartSplitChars = {'T'};
        private static readonly UTF8Encoding _encoding = new UTF8Encoding(false);
        private static readonly byte[] _emptyBytes = new byte[0];

        public static void SignRequest(IRequest request, byte[] body, ImmutableCredentials credentials, string region, string service)
        {
            DateTime date = DateTime.UtcNow;
            string dateStamp = date.ToString("yyyyMMdd");
            string amzDate = date.ToString("yyyyMMddTHHmmssZ");
            request.Headers.XAmzDate = amzDate;

            byte[] signingKey = GetSigningKey(credentials.SecretKey, dateStamp, region, service);
            string stringToSign = GetStringToSign(request, body, region, service);
            string signature = signingKey.GetHmacSha256Hash(stringToSign).ToLowercaseHex();
            string auth = string.Format(
                "AWS4-HMAC-SHA256 Credential={0}/{1}, SignedHeaders={2}, Signature={3}",
                credentials.AccessKey,
                GetCredentialScope(dateStamp, region, service),
                GetSignedHeaders(request),
                signature);

            request.Headers.Authorization = auth;
            if (!string.IsNullOrWhiteSpace(credentials.Token))
            {
                request.Headers.XAmzSecurityToken = credentials.Token;
            }
        }

        private static byte[] GetSigningKey(string secretKey, string dateStamp, string region, string service)
        {
            return _encoding.GetBytes("AWS4" + secretKey)
                .GetHmacSha256Hash(dateStamp)
                .GetHmacSha256Hash(region)
                .GetHmacSha256Hash(service)
                .GetHmacSha256Hash("aws4_request");
        }

        private static string GetStringToSign(IRequest request, byte[] data, string region, string service)
        {
            string canonicalRequest = GetCanonicalRequest(request, data);
            string awsDate = request.Headers.XAmzDate;
            string datePart = awsDate.Split(_datePartSplitChars, 2)[0];
            return string.Join("\n",
                "AWS4-HMAC-SHA256",
                awsDate,
                GetCredentialScope(datePart, region, service),
                GetHash(canonicalRequest).ToLowercaseHex()
            );
        }

        private static string GetCanonicalRequest(IRequest request, byte[] data)
        {
            Dictionary<string, string> canonicalHeaders = request.GetCanonicalHeaders();
            StringBuilder result = new StringBuilder();
            result.Append(request.Method);
            result.Append('\n');
            result.Append(GetPath(request.RequestUri));
            result.Append('\n');
            result.Append(request.RequestUri.GetCanonicalQueryString());
            result.Append('\n');
            WriteCanonicalHeaders(canonicalHeaders, result);
            result.Append('\n');
            WriteSignedHeaders(canonicalHeaders, result);
            result.Append('\n');
            WriteRequestPayloadHash(data, result);
            return result.ToString();
        }

        private static Dictionary<string, string> GetCanonicalHeaders(this IRequest request)
        {
            var headers = from string key in request.Headers.Keys
                          let headerName = key.ToLowerInvariant()
                          where headerName != "connection" && headerName != "user-agent"
                          let headerValues = string.Join(",",
                              request.Headers
                              .GetValues(key) ?? Enumerable.Empty<string>()
                              .Select(v => v.Trimall())
                          )
                          select new { headerName, headerValues };

            Dictionary<string, string> result = headers.ToDictionary(v => v.headerName, v => v.headerValues);
            result["host"] = request.RequestUri.Host.ToLowerInvariant();
            return result;
        }

        private static string GetCanonicalQueryString(this Uri uri)
        {
            StringBuilder result = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(uri.Query))
            {
                NameValueCollection queryParams = ParseQueryString(uri.Query);
                var queryValues = from string key in queryParams
                                  orderby key
                                  from value in queryParams.GetValues(key)
                                  select new { key, value };

                foreach (var param in queryValues)
                {
                    if (result.Length > 0)
                    {
                        result.Append('&');
                    }
                    result.WriteEncoded(param.key);
                    result.Append('=');
                    result.WriteEncoded(param.value);
                }
            }
            return result.ToString();
        }

        private static string Trimall(this string value)
        {
            StringBuilder result = new StringBuilder();
            value = value.Trim();
            using (StringReader reader = new StringReader(value))
            {
                while (true)
                {
                    int next = reader.Peek();
                    if (next < 0)
                    {
                        break;
                    }

                    char c = (char)next;
                    if (c == '"')
                    {
                        ReadQuotedString(reader, result);
                    }
                    else if (char.IsWhiteSpace(c))
                    {
                        ReadWhitespace(reader, result);
                    }
                    else
                    {
                        result.Append((char)reader.Read());
                    }
                }
            }
            return result.ToString();
        }

        private static void ReadQuotedString(StringReader reader, StringBuilder builder)
        {
            _ = reader.Read();
            builder.Append('"');
            bool escape = false;
            while (true)
            {
                int next = reader.Read();
                if (next < 0)
                {
                    break;
                }

                char c = (char)next;
                builder.Append(c);
                if (escape)
                {
                    escape = false;
                }
                else
                {
                    if (c == '"') break;
                    if (c == '\\') escape = true;
                }
            }
        }

        private static void ReadWhitespace(StringReader reader, StringBuilder builder)
        {
            int lastWhitespace = (char)reader.Read();
            while (true)
            {
                int next = reader.Peek();
                if (next < 0)
                {
                    break;
                }

                char c = (char)next;
                if (!char.IsWhiteSpace(c))
                {
                    break;
                }
                lastWhitespace = c;
                reader.Read();
            }
            builder.Append(lastWhitespace);
        }

        private static string GetPath(Uri uri)
        {
            string path = uri.AbsolutePath;
            if (path.Length == 0)
            {
                return "/";
            }

            IEnumerable<string> segments = path
                .Split('/')
                .Select(segment =>
                    {
                        string escaped = WebUtility.UrlEncode(segment);
                        escaped = escaped.Replace("*", "%2A");
                        return escaped;
                    }
                );
            return string.Join("/", segments);
        }

        private static NameValueCollection ParseQueryString(string query) =>
            QueryHelpers.ParseQuery(query)
                .Aggregate(new NameValueCollection(), (col, kv) =>
                {
                    kv.Value.ToList().ForEach(v => col.Add(kv.Key, v));
                    return col;
                });

        private static void WriteEncoded(this StringBuilder builder, string value)
        {
            for (int i = 0; i < value.Length; ++i)
            {
                if (value[i].RequiresEncoding())
                {
                    builder.Append(Uri.EscapeDataString(value[i].ToString()));
                }
                else
                {
                    builder.Append(value[i]);
                }
            }
        }

        private static bool RequiresEncoding(this char value)
        {
            if ('A' <= value && value <= 'Z') return false;
            if ('a' <= value && value <= 'z') return false;
            if ('0' <= value && value <= '9') return false;
            switch (value)
            {
                case '-':
                case '_':
                case '.':
                case '~':
                    return false;
            }
            return true;
        }

        private static byte[] GetHash(string data)
        {
            return GetHash(_encoding.GetBytes(data));
        }

        private static byte[] GetHash(this byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        private static byte[] GetHmacSha256Hash(this byte[] key, string data)
        {
            using (HMACSHA256 hmacsha256 = new HMACSHA256())
            {
                hmacsha256.Key = key;
                return hmacsha256.ComputeHash(_encoding.GetBytes(data));
            }
        }

        private static string GetCredentialScope(string date, string region, string service)
        {
            return string.Format("{0}/{1}/{2}/aws4_request", date, region, service);
        }

        private static string GetSignedHeaders(IRequest request)
        {
            Dictionary<string, string> canonicalHeaders = request.GetCanonicalHeaders();
            StringBuilder result = new StringBuilder();
            WriteSignedHeaders(canonicalHeaders, result);
            return result.ToString();
        }

        private static string ToLowercaseHex(this byte[] data)
        {
            StringBuilder result = new StringBuilder();
            foreach (byte b in data)
            {
                result.AppendFormat("{0:x2}", b);
            }
            return result.ToString();
        }

        private static void WriteRequestPayloadHash(byte[] data, StringBuilder builder)
        {
            data = data ?? _emptyBytes;
            byte[] hash = GetHash(data);
            foreach (byte b in hash)
            {
                builder.AppendFormat("{0:x2}", b);
            }
        }

        private static void WriteSignedHeaders(Dictionary<string, string> canonicalHeaders, StringBuilder builder)
        {
            bool started = false;
            foreach (KeyValuePair<string, string> pair in canonicalHeaders.OrderBy(v => v.Key))
            {
                if (started)
                {
                    builder.Append(';');
                }
                builder.Append(pair.Key.ToLowerInvariant());
                started = true;
            }
        }

        private static void WriteCanonicalHeaders(Dictionary<string, string> canonicalHeaders, StringBuilder builder)
        {
            IEnumerable<string> headers = from pair in canonicalHeaders
                                          orderby pair.Key ascending
                                          select string.Format("{0}:{1}\n", pair.Key, pair.Value);

            foreach (string header in headers)
            {
                builder.Append(header);
            }
        }
    }
}