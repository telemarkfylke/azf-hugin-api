const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const { logger } = require('@vtfk/logger')
const withAuth = require('../lib/withAuth')

const roles = [`${process.env.appName}.basic`, `${process.env.appName}.admin`]

app.http('multimodalOpenAi', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: withAuth(roles, async (request) => {
    const openai = new OpenAI()
    const params = await JSON.parse(await request.text())
    let msg

    try {
      msg = [{ role: 'system', content: params.kontekst }]
      msg.push(...params.messageHistory)

      if (params.bilde_base64String !== '') {
        logger('info', ['multimodalOpenAi', 'Bilde er sendt med brukerinput'])
        msg.push({
          role: 'user',
          content: [
            { type: 'text', text: params.message },
            {
              type: 'image_url',
              image_url: {
                url: params.bilde_base64String
              }
            }
          ]
        })
      } else {
        msg.push({ role: 'user', content: params.message })
      }
    } catch (error) {
      logger('error', ['multimodalOpenAi', error?.message, error?.stack])
      return { jsonBody: { error: error.response?.data || error?.stack || error.message } }
    }
    try {
      const completion = await openai.chat.completions.create({
        messages: msg,
        model: params.model,
        temperature: params.temperature
      })
      logger('info', ['multimodalOpenAi', 'success'])
      return { jsonBody: completion }
    } catch (error) {
      logger('error', ['multimodalOpenAi', error?.message, error?.stack])
      return { jsonBody: { error: error.response?.data || error?.stack || error.message } }
    }
  })
})
