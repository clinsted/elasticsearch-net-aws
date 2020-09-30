using Amazon.Runtime;
using System.IO;
using System.Net.Http;

namespace Elasticsearch.Net.Aws
{
    public class AwsHttpConnection : HttpConnection
    {
        private readonly string _region;

        private readonly ImmutableCredentials _awsCredentials;

        public AwsHttpConnection(ImmutableCredentials awsCredentials, string region)
        {
            this._awsCredentials = awsCredentials;
            this._region = region;
        }

        protected override HttpRequestMessage CreateHttpRequestMessage(RequestData requestData)
        {
            HttpRequestMessage request = base.CreateHttpRequestMessage(requestData);
            this.SignRequest(new HttpRequestMessageAdapter(request), requestData);
            return request;
        }

        private void SignRequest(IRequest request, RequestData requestData)
        {
            byte[] data = null;
            if (requestData.PostData != null)
            {
                data = requestData.PostData.WrittenBytes;
                if (data == null)
                {
                    using MemoryStream ms = new MemoryStream();
                    requestData.PostData.Write(ms, requestData.ConnectionSettings);
                    data = ms.ToArray();
                }
            }
            SignV4Util.SignRequest(request, data, this._awsCredentials, this._region, "es");
        }
    }
}