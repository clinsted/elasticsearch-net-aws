# Forked from bcuff/elasticsearch-net-aws

https://github.com/bcuff/elasticsearch-net-aws

Full credit goes to bcuff

Changes:
netstandard2.0 => netstandard2.1
removed support for net461
some code changes, mainly code style changes except for AwsHttpConnection (explained below).
dependencies updated:
	Elasticsearch.Net 7.0.0 => 7.* (7.9.0 at time of writing this)
	Microsoft.AspNetCore.WebUtilities 2.1.1 => 2.2.0
AwsHttpConnection changes
	The original implementation relies on AWSOptions or AWSCredentials, this implementation takes awsAccessKeyId, awsSecretAccessKey and region strings.
separated out the HeadersAdapter class
incorporated the StringUtil methods into SignV4Util
