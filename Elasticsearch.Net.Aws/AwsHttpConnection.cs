using Amazon.Runtime;
using System.IO;
using System.Net.Http;

namespace Elasticsearch.Net.Aws
{
    public class AwsHttpConnection : HttpConnection
    {
        private readonly string _awsAccessKeyId;
        private readonly string _awsSecretAccessKey;
        private readonly string _region;

        public AwsHttpConnection(string awsAccessKeyId, string awsSecretAccessKey, string region)
        {
            this._awsAccessKeyId = awsAccessKeyId;
            this._awsSecretAccessKey = awsSecretAccessKey;
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
                    using (MemoryStream ms = new MemoryStream())
                    {
                        requestData.PostData.Write(ms, requestData.ConnectionSettings);
                        data = ms.ToArray();
                    }
                }
            }
            ImmutableCredentials credentials = new ImmutableCredentials(this._awsAccessKeyId, this._awsSecretAccessKey, null);
            SignV4Util.SignRequest(request, data, credentials, this._region, "es");
        }
    }
}