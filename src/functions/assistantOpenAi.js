const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const validateToken = require('../lib/validateToken')
const { logger } = require('@vtfk/logger')

app.http('assistantOpenAi', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const accesstoken = request.headers.get('Authorization')
      await validateToken(accesstoken, { role: [`${process.env.appName}.basic`, `${process.env.appName}.admin`, `${process.env.appName}.skolebotter`, `${process.env.appName}.orgbotter`, `${process.env.appName}.labs`] })
      logger('info', ['assistantOpenAi', 'Token validert'])
      const params = JSON.parse(await request.text())
      let thread // = formPayload.get('thread_id')

      // Velger riktig api-nøkkel basert på flis
      const tile = params.tile
      let assistant_apiKey = process.env.OPENAI_API_KEY

      if (tile === 'labs') {
        assistant_apiKey = process.env.OPENAI_API_KEY_LABS
      } else if (tile === 'orgbotter') {
        assistant_apiKey = process.env.OPENAI_API_KEY_ORGBOTTER
      } else if (tile === 'skolebotter') {
        assistant_apiKey = process.env.OPENAI_API_KEY_SKOLEBOTTER
      } else if (tile === 'fartebot') {
        assistant_apiKey = process.env.OPENAI_API_KEY_KOLLEKTIV
      } else assistant_apiKey = process.env.OPENAI_API_KEY

      const openai = new OpenAI({
        apiKey: assistant_apiKey
      })

      // Sjekker om det skal opprettes en ny tråd eller om det skal brukes en eksisterende
      if (params.new_thread) {
        // Lager en ny tråd
        logger('info', ['assistantOpenAi', 'Ny tråd:', params.new_thread])
        try {
          thread = await openai.beta.threads.create({
            messages: params.messageHistory.map(({ role, content }) => ({ role, content })) // Map only role and content from messageHistory
          })
        } catch (error) {
          logger('error', ['assistantOpenAi', 'Failed to create thread', error.message])
          return {
            status: 400,
            body: JSON.stringify({ error: 'Failed to create thread' })
          }
        }
      } else {
        // Henter en eksisterende tråd
        try {
          thread = await openai.beta.threads.retrieve(params.thread_id)
        } catch (error) {
          logger('error', ['assistantOpenAi', 'Failed to retrieve thread', error.message])
          return {
            status: 400,
            body: JSON.stringify({ error: 'Failed to retrieve thread' })
          }
        }
        // Oppdaterer tråden med siste melding i messageHistory
        const messageLength = params.messageHistory.length
        try {
          await openai.beta.threads.messages.create(thread.id, {
            role: 'user',
            content: params.messageHistory[messageLength - 1].content // Siste melding i messageHistory
          })
        } catch (error) {
          logger('error', ['assistantOpenAi', 'Failed to create message', error.message])
          return {
            status: 400,
            body: JSON.stringify({ error: 'Failed to create message' })
          }
        }
      }

      // Kjører tråden på valgt assistent
      let run
      try {
        run = await openai.beta.threads.runs.createAndPoll(
          thread.id,
          {
            assistant_id: params.assistant_id
          }
        )
      } catch (error) {
        logger('error', ['assistantOpenAi', 'Failed to run assistant', error.message])
        return {
          status: 400,
          body: JSON.stringify({ error: 'Failed to run assistant' })
        }
      }

      // List messages in thread
      let messages // Global variabel for å lagre meldingene
      try {
        if (run.status === 'completed') {
          messages = await openai.beta.threads.messages.list(run.thread_id)
        }
      } catch (error) {
        logger('error', ['assistantOpenAi', 'Failed to list messages', error.message])
        return {
          status: 400,
          body: JSON.stringify({ error: 'Failed to list messages' })
        }
      }

      const respons = {
        run: run.status,
        thread_id: thread.id,
        assistant_id: run.assistant_id,
        messages: messages.data
      }
      logger('info', ['assistantOpenAi', 'Success'])
      return {
        body: JSON.stringify(respons)
      }
    } catch (error) {
      logger('error', ['assistantOpenAi', error.message])
      return {
        status: 400,
        body: JSON.stringify({ error: error.message })
      }
    }
  }
})
