using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Azure.Services.AppAuthentication;
using System.Threading;
using System.Text;

namespace KeyVaultBlobEncrypt
{
    public static class TestBlobEncDec
    {
        [FunctionName("TestBlobEncDec")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "{actionType}" )] HttpRequest req, string actionType,
            ILogger log)
        {
            var storageAccount = Microsoft.Azure.Storage.CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("StorageAccountConnectionString"));
            var blobClient = storageAccount.CreateCloudBlobClient();
            var blobContainer = blobClient.GetContainerReference(Environment.GetEnvironmentVariable("BlobContainer"));

            if(actionType == "store")
            {
                var text = await req.ReadAsStringAsync();
                var id = Guid.NewGuid().ToString();
                await EncryptAndStore(blobContainer, text, id);
                return (ActionResult)new OkObjectResult($"{id}");
            }
            else
            {
                var id = await req.ReadAsStringAsync();
                string res = await RetrieveAndDecrypt(blobContainer, id);
                return (ActionResult)new OkObjectResult($"{res}");
            }
        }

        private static async Task<string> RetrieveAndDecrypt(CloudBlobContainer blobContainer, string id)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var resolver = new KeyVaultKeyResolver(client);
            //no need to provide key vault key id - stored in blob meta data
            var policy = new BlobEncryptionPolicy(null, resolver);
            var options = new BlobRequestOptions() { EncryptionPolicy = policy };
            var blobRef = blobContainer.GetBlockBlobReference(id);
            var ms = new MemoryStream();
            await blobRef.DownloadToStreamAsync(ms, null, options, null);
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        private static async Task EncryptAndStore(CloudBlobContainer blobContainer, string text, string id)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var resolver = new KeyVaultKeyResolver(client);

            var rsa = await resolver.ResolveKeyAsync(Environment.GetEnvironmentVariable("RsaVaultKey"), CancellationToken.None);
            var policy = new BlobEncryptionPolicy(rsa, null);
            var options = new BlobRequestOptions() { EncryptionPolicy = policy };
          
            var blob = blobContainer.GetBlockBlobReference(id);

            var bytes = Encoding.UTF8.GetBytes(text);
            using (Stream stream = new MemoryStream(bytes))
            {
                await blob.UploadFromStreamAsync(stream, bytes.Length, null, options, null);
            }
        }
    }
}
