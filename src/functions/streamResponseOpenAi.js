const { app } = require('@azure/functions')
const { OpenAI } = require('openai')
const { logger } = require('@vtfk/logger')
const validateToken = require('../lib/validateToken')
const { Readable } = require('stream')

require('dotenv').config()

// Enable HTTP streaming
app.setup({ enableHttpStream: true })

app.http('streamResponseOpenAi', {
  methods: ['POST'],
  authLevel: 'anonymous',
  handler: async (request) => {
    try {
      const openai = new OpenAI()
      const params = await JSON.parse(await request.text())

      // Validate the token and the role of the user
      try {
        const accesstoken = request.headers.get('Authorization')
        await validateToken(accesstoken, { role: [`${process.env.appName}.basic`, `${process.env.appName}.admin`, `${process.env.appName}.dokumentchat`] })
      } catch (error) {
        logger('error', ['streamResponseOpenAi', 'Error validating token:', error])
        return {
          status: 401,
          jsonBody: { error: error.response?.data || error?.stack || error.message }
        }
      }

      // Build messages array from params
      const messages = []

      if (params.messages && Array.isArray(params.messages)) {
        messages.push(...params.messages)
      } else if (params.userMessage) {
        const content = []

        if (params.imageBase64 && params.imageBase64.length > 0) {
          content.push({ type: 'text', text: params.userMessage })
          for (const imageB64 of params.imageBase64) {
            content.push({
              type: 'image_url',
              image_url: { url: imageB64 }
            })
          }
        } else {
          content.push({ type: 'text', text: params.userMessage })
        }

        messages.push({
          role: 'user',
          content: content.length === 1 ? params.userMessage : content
        })
      } else {
        throw new Error('No messages or userMessage provided')
      }

      // Create streaming completion
      const completionParams = {
        model: params.model || 'gpt-4o-mini',
        messages,
        stream: true,
        max_tokens: params.max_tokens || undefined
      }

      // Only add temperature for non-GPT-5 models
      if (!params.model || !params.model.includes('gpt-5')) {
        completionParams.temperature = params.temperature || 0.7
      }

      const stream = await openai.chat.completions.create(completionParams)

      logger('info', ['streamResponseOpenAi', 'Starting stream for model:', params.model || 'gpt-4o-mini'])

      // Create a Node.js Readable stream for Azure Functions v4
      const nodeStream = new Readable({
        read () {}
      })

      // Process the OpenAI stream and push to nodeStream
      ;(async () => {
        try {
          for await (const chunk of stream) {
            const delta = chunk.choices[0]?.delta

            if (delta) {
              // Format as Server-Sent Events
              const data = JSON.stringify({
                id: chunk.id,
                object: chunk.object,
                created: chunk.created,
                model: chunk.model,
                choices: [{
                  index: chunk.choices[0].index,
                  delta,
                  finish_reason: chunk.choices[0].finish_reason
                }]
              })

              const sseChunk = `data: ${data}\n\n`
              nodeStream.push(sseChunk)
            }

            // Send [DONE] when stream is finished
            if (chunk.choices[0]?.finish_reason) {
              nodeStream.push('data: [DONE]\n\n')
              nodeStream.push(null) // End the stream
              break
            }
          }
        } catch (error) {
          logger('error', ['streamResponseOpenAi', 'Streaming error:', error])
          const errorChunk = `data: ${JSON.stringify({ error: error.message })}\n\n`
          nodeStream.push(errorChunk)
          nodeStream.push(null) // End the stream
        }
      })()

      // Return streaming response with just the body
      return {
        body: nodeStream,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      }
    } catch (error) {
      logger('error', ['streamResponseOpenAi', 'Error:', error])
      return {
        status: 500,
        jsonBody: { error: error.message || 'Internal server error' }
      }
    }
  }
})
