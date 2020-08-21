using System;
using System.Net.Http;

namespace Elasticsearch.Net.Aws
{
    internal class HttpRequestMessageAdapter : IRequest
    {
        private readonly HttpRequestMessage _message;

        public HttpRequestMessageAdapter(HttpRequestMessage message)
        {
            this._message = message;
            Headers = new HeadersAdapter(this._message);
        }

        public IHeaders Headers { get; private set; }

        public string Method => this._message.Method.ToString();

        public Uri RequestUri => this._message.RequestUri;
    }
}