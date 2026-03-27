const { app } = require('@azure/functions')
const validateToken = require('../lib/validateToken')
const { BlobServiceClient } = require('@azure/storage-blob')

app.http('nbTranscript', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const accesstoken = request.headers.get('Authorization')
      await validateToken(accesstoken, { role: [`${process.env.appName}.admin`, `${process.env.appName}.transkripsjon`] }, [])

      // Payload fra klienten
      const formPayload = await request.formData()
      const fileStreams = formPayload.get('filer')
      const filnavn = formPayload.get('filnavn')
      const spraak = formPayload.get('spraak')
      const format = formPayload.get('format')
      const upn = formPayload.get('upn')

      const blob = fileStreams
      const data = await blob.arrayBuffer()

      // Initialize BlobServiceClient
      const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING)
      const containerClient = blobServiceClient.getContainerClient(process.env.AZURE_STORAGE_CONTAINER_NAME)

      // Upload array buffer as a file named with timestamp and original filename
      const timestamp = Date.now()
      const metadata = { spraak, format, upn }
      const blockBlobClient = containerClient.getBlockBlobClient(`${timestamp}-${filnavn}`)
      await blockBlobClient.uploadData(data, {
        metadata
      })

      // Get the URL of the uploaded blob
      const blobUrl = blockBlobClient.url

      const respons = {
        data: 'Alt gikk bra',
        blobUrl
      }
      return { jsonBody: respons }
    } catch (error) {
      return {
        status: 401,
        body: JSON.stringify({ error: error.message })
      }
    }
  }
})
