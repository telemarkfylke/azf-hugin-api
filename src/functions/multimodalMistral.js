const { app } = require('@azure/functions')
const { Mistral } = require('@mistralai/mistralai')
const withAuth = require('../lib/withAuth')
const { logger } = require('@vtfk/logger')

const roles = [`${process.env.appName}.basic`, `${process.env.appName}.admin`]

app.http('multimodalMistral', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: withAuth(roles, async (request) => {
    const pixtral = new Mistral({ apiKey: process.env.MISTRAL_API_KEY })
    const params = await JSON.parse(await request.text())
    let msg

    try {
      msg = [{ role: 'system', content: params.kontekst }]
      msg.push(...params.messageHistory)

      if (params.bilde_base64String.length > 0) {
        logger('info', ['multimodalMistral', 'Bilde er sendt med brukerinput'])
        msg.push(
          {
            role: 'user',
            content: [
              { type: 'text', text: params.message },
              {
                type: 'image_url',
                imageUrl: params.bilde_base64String[0]
              }
            ]
          }
        )
      }
    } catch (error) {
      logger('error', ['multimodalMistral - Noe gikk galt med melding/bilde'])
    }
    try {
      const completion = await pixtral.chat.complete({
        messages: msg,
        model: params.model,
        temperature: params.temperature
      })
      logger('info', ['multimodalMistral', 'success'])
      return { jsonBody: completion }
    } catch (error) {
      logger('error', ['multimodalMistral - Noe gikk galt med chat.complete'])
    }
  })
})
