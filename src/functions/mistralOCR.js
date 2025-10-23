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

        // ToDo Lage ulike schema for ulike dokumenttyper slik at disse kan velges dynamisk basert på input
        const ImageSchema = z.object({
            image_type: z.string(),
            short_description: z.string(),
            summary: z.string(),
        });

        const formSchema = z.object({
            referanseid: z.string().optional(),
            skjemaid: z.string().optional(),
            fornavn: z.string().optional(),
            etternavn: z.string().optional(),
            adresse: z.string().optional(),
            postnummer: z.string().optional(),
            poststed: z.string().optional(),
            telefonnummer: z.string().optional(),
            epost: z.string().optional(),
            fodselsdato: z.string().describe("De seks første sifferne i fødselsnummeret. Formatet er DDMMYYxxxxx").optional(),
            fodselsnummer: z.string().describe("11 siffer"),
            bekreftelse: z.boolean().describe("Om sjekkboksen er merket").optional(),
        })

        const body = await request.json();
        const base64Pdf = body.base64Pdf;

        const result = await mistral.ocr.process({
        model: "mistral-ocr-latest",
        includeImageBase64: false,
        // documentAnnotationFormat: "json_object",
        // pages: [1],
        bboxAnnotationFormat: responseFormatFromZodObject(ImageSchema),
        documentAnnotationFormat: responseFormatFromZodObject(formSchema),
        document: {
            type: "document_url",
            documentUrl: "data:application/pdf;base64," + base64Pdf
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
        console.log("Processing questions...")

        const body = await request.json();
        const base64Pdf = body.base64Pdf;
        console.log("Received PDF of length: " + base64Pdf.length)
        const result = await mistral.chat.complete({
            model: "mistral-small-latest",
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: "What is the last sentence in the document?",
                        },
                        {
                            type: "document_url",
                            documentUrl: "data:application/pdf;base64," + base64Pdf,
                        },
                    ],
                },
            ],
        });
        console.log(result)
        return {status: result.status, jsonBody: result}
    }
})

