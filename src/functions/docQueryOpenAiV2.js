const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const withAuth = require('../lib/withAuth')
const { logger } = require('@vtfk/logger')

const roles = [`${process.env.appName}.admin`, `${process.env.appName}.dokumentchat`]

app.http('docQueryOpenAiV2', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: withAuth(roles, async (request) => {
    try {
      const openai = new OpenAI()

      let VS, result

      // Payload fra klienten
      const formPayload = await request.formData()
      const fileStreams = formPayload.getAll('filer')
      const new_thread = formPayload.get('new_thread')
      let vectorStore = formPayload.get('vectorStore_id')
      const response_id = formPayload.get('response_id')
      const userMessage = formPayload.get('userMessage')

      // Sjekker om vi skal lage ny tråd og vectorstore eller bruke eksisterende
      logger('info', ['docQueryOpenAiV2', 'Ny tråd:', new_thread])
      if (new_thread === 'true') {
        // Lager vector store
        try {
          VS = await openai.vectorStores.create({
            name: 'docQueryVectorStore',
            expires_after: {
              anchor: 'last_active_at',
              days: 1
            }
          })
          vectorStore = VS.id
        } catch (error) {
          logger('error', ['docQueryOpenAiV2', 'Error creating vector store', error.message])
          throw new Error('Failed to create vector store')
        }

        // Lastert opp fil(er) til vector store og oppdaterer
        try {
          const filListe = []
          for (const file of fileStreams) {
            // Upload the file to OpenAI
            result = await openai.files.create({
              file,
              purpose: 'assistants'
            })
            filListe.push(result.id)

            // Upload the file to the vector store
            const myVectorStoreFile = await openai.vectorStores.files.create(
              vectorStore,
              {
                file_id: result.id
              }
            )
            logger('info', ['docQueryOpenAiV2', 'File uploaded to vector store:', myVectorStoreFile.id])
          }
        } catch (error) {
          logger('error', ['docQueryOpenAiV2', 'Error uploading files to vector store', error.message])
          throw new Error('Failed to upload files to vector store')
        }
      } else {
        console.log('Bruker eksisterende vector store')
      }

      const queryObject = {
        model: 'gpt-4.1',
        input: userMessage,
        tools: [{
          type: 'file_search',
          vector_store_ids: [vectorStore]
        }]
      }

      if (response_id !== 'null' && response_id !== undefined) {
        queryObject.previous_response_id = response_id
      }

      const response = await openai.responses.create(queryObject)

      logger('info', ['docQueryOpenAiV2', 'Success'])
      return { jsonBody: response }
    } catch (error) {
      return { status: 500, jsonBody: { error: error.message } }
    }
  })
})
