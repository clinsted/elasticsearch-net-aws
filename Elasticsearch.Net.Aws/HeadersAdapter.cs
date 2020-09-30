using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Elasticsearch.Net.Aws
{
    internal class HeadersAdapter : IHeaders
    {
        private readonly HttpRequestMessage _message;

        public HeadersAdapter(HttpRequestMessage message)
        {
            this._message = message;
        }

        private string ToSingleValue(IEnumerable<string> values) => String.Join(",", values);

        public string XAmzDate
        {
            get
            {
                return ToSingleValue(this._message.Headers.GetValues("x-amz-date"));
            }
            set
            {
                this._message.Headers.TryAddWithoutValidation("x-amz-date", value);
            }
        }

        public string Authorization
        {
            get
            {
                return ToSingleValue(this._message.Headers.GetValues("Authorization"));
            }
            set
            {
                this._message.Headers.TryAddWithoutValidation("Authorization", value);
            }
        }

        public string XAmzSecurityToken
        {
            get
            {
                return ToSingleValue(this._message.Headers.GetValues("x-amz-security-token"));
            }
            set
            {
                this._message.Headers.TryAddWithoutValidation("x-amz-security-token", value);
            }
        }

        public IEnumerable<string> GetValues(string name)
        {
            _ = this._message.Headers.TryGetValues(name, out IEnumerable<string> values) || (this._message.Content?.Headers.TryGetValues(name, out values) ?? false);
            return values;
        }

        public IEnumerable<string> Keys => this._message.Headers.Select(h => h.Key).Concat(this._message.Content?.Headers.Select(h => h.Key) ?? Enumerable.Empty<string>());
    }
}