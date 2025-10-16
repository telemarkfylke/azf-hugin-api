const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const { logger } = require('@vtfk/logger')
const validateToken = require('../lib/validateToken')

require('dotenv').config()

app.http('responseOpenAi', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const openai = new OpenAI()
    const params = await JSON.parse(await request.text())

    // Validate the token and the role of the user
    try {
      const accesstoken = request.headers.get('Authorization')
      await validateToken(accesstoken, { role: [`${process.env.appName}.basic`, `${process.env.appName}.admin`, `${process.env.appName}.dokumentchat`] })
    } catch (error) {
      logger('error', ['responseOpenAi', 'Error validating token:', error])
      return {
        status: 401,
        jsonBody: { error: error.response?.data || error?.stack || error.message }
      }
    }

    // Bygger input-objektet
    const input = []
    const imagesInput = []
    const doksInput = []

    if (params.imageBase64.length > 0) {
      // Sjekker om det er bilder i params.imageBase64 og legger dem til i input-arrayet
      for (const bildeB64 of params.imageBase64) {
        imagesInput.push({ type: 'input_image', image_url: bildeB64 })
      }
      input.push({
        role: 'user',
        content: [
          { type: 'input_text', text: params.userMessage },
          // Spread imagesInput for å få med alle bildene i input-arrayet
          ...imagesInput
        ]
      })
    } else if (params.dokFiles.length > 0) {
      // Sjekker om det er dokumenter i params.dokFiles og legger dem til i input-arrayet
      // Convert base64 files to File objects for compatibility with the OpenAI API
      for (const dokFile of params.dokFiles) {
        doksInput.push({ type: 'input_file', filename: 'test.pdf', file_data: dokFile })
      }
      input.push({
        role: 'user',
        content: [
          // Spread doksInput to include all uploaded documents
          ...doksInput,
          { type: 'input_text', text: params.userMessage }
        ]
      })
    } else {
      input.push({ role: 'user', content: params.userMessage })
    }

    const response = await openai.responses.create({
      model: params.model,
      tools: [{
        type: 'web_search_preview',
        user_location: {
          type: 'approximate',
          country: 'NO'
        }
      }],
      previous_response_id: params.response_id,
      input
    })
    logger('info', ['responseOpenAi', 'Response:', response.id])
    return { body: JSON.stringify(response) }
  }
})
