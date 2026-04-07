const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const withAuth = require('../lib/withAuth')

const roles = [`${process.env.appName}.basic`, `${process.env.appName}.admin`]

app.http('structuredOpenAi', {
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
      return { jsonBody: { error: error.response?.data || error?.stack || error.message } }
    }
    try {
      const completion = await openai.beta.chat.completions.parse({
        messages: msg,
        model: params.model,
        temperature: params.temperature,
        response_format: params.response_format
      })

      return { jsonBody: completion }
    } catch (error) {
      return { jsonBody: { error: error.response?.data || error?.stack || error.message } }
    }
  })
})
