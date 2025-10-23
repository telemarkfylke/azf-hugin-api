const { app } = require('@azure/functions');
const { Mistral } = require('@mistralai/mistralai')
const { responseFormatFromZodObject } = require ('@mistralai/mistralai/extra/structChat.js')
const z = require('zod') 

app.http('mistralOCR', {
    methods: ['POST'],
    authLevel: 'anonymous',

    handler: async (request, context) => {
        const mistral = new Mistral({
            apiKey: process.env.MISTRAL_API_KEY
        });

        const ImageSchema = z.object({
            image_type: z.string(),
            short_description: z.string(),
            summary: z.string(),
        });

        const result = await mistral.ocr.process({
        model: "mistral-ocr-latest",
        includeImageBase64: false,
        // documentAnnotationFormat: "json_object",
        // pages: [1],
        bboxAnnotationFormat: responseFormatFromZodObject(ImageSchema),
        document: {
            documentUrl: "https://raw.githubusercontent.com/mistralai/cookbook/refs/heads/main/mistral/ocr/mistral7b.pdf",
            type: "document_url",
        },
        });
        console.log(result)
        return {status: result.status, jsonBody: result}
    }
});

app.http('images', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'mistralOCR/images',
    handler: async (request, context) => {
        const mistral = new Mistral({
            apiKey: process.env.MISTRAL_API_KEY
        });

        const result = await mistral.ocr.process({
        model: "mistral-ocr-latest",
        includeImageBase64: true,
        documentAnnotationFormat: "json_object",
        document: {
            documentUrl: "https://raw.githubusercontent.com/mistralai/cookbook/refs/heads/main/mistral/ocr/mistral7b.pdf",
            type: "document_url",
        },
        });
    }
})
app.http('questions', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'mistralOCR/questions',
    handler: async (request, context) => {
        const mistral = new Mistral({
            apiKey: process.env.MISTRAL_API_KEY,
        });

        const result = await mistral.ocr.process({
        model: "mistral-ocr-latest",
        includeImageBase64: true,
        documentAnnotationFormat: "json_object",
        document: {
            documentUrl: "https://raw.githubusercontent.com/mistralai/cookbook/refs/heads/main/mistral/ocr/mistral7b.pdf",
            type: "document_url",
        },
        });
    }
})

