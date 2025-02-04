const { app } = require('@azure/functions');
const validateToken = require('../lib/validateToken');
const { BlobServiceClient } = require('@azure/storage-blob');
const jwt = require('jsonwebtoken');

app.http('nbTranscript', {
    methods: ['GET', 'POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            const accesstoken = request.headers.get('Authorization');
            await validateToken(accesstoken, { role: [`${process.env.appName}.admin`] });


            // Payload fra klienten
            const formPayload = await request.formData();
            const fileStreams = formPayload.get('filer');
            const filnavn = formPayload.get('filnavn');
            const spraak = formPayload.get('spraak');
            const format = formPayload.get('format');
            const upn = formPayload.get('upn');

            console.log(fileStreams);
            console.log(filnavn);
            console.log(spraak);
            console.log(format);
            console.log(upn);
            const blob = fileStreams;
            const data = await blob.arrayBuffer();

            // Initialize BlobServiceClient
            const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);
            const containerClient = blobServiceClient.getContainerClient(process.env.AZURE_STORAGE_CONTAINER_NAME);

            // Upload array buffer as a file named with timestamp and original filename
            const timestamp = Date.now();
            const metadata = { spraak: spraak, format: format, upn: upn };
            const blockBlobClient = containerClient.getBlockBlobClient(`${timestamp}-${filnavn}`);
            await blockBlobClient.uploadData(data, {
                metadata: metadata
            });

            // Get the URL of the uploaded blob
            const blobUrl = blockBlobClient.url;

            // const response = await fetch(
            //     process.env.base_url_hf_nbtranscript,
            //     {
            //         headers: { 
            //             "Accept" : "application/json",
            //             "Authorization": `Bearer ${process.env.HUGGINGFACEHUB_API_TOKEN}`,
            //             "Content-Type": "audio/flac" 
            //         },
            //         method: "POST",
            //         body: data,
            //     }
            // );
            // const result = await response.json();
            // console.log("Her er resultatet: ");

            const respons = {
                data: result,
                blobUrl: blobUrl
            };
            console.log(respons);
            return { jsonBody: respons };
        } catch (error) {
            return {
                status: 401,
                body: JSON.stringify({ error: error.message })
            };
        }
    }
});
