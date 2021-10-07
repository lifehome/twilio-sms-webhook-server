import Fastify from 'fastify'
import Twilio from 'twilio'
import bs3 from 'better-sqlite3'
import dotenv from 'dotenv'
import * as argon2 from 'argon2'

// Initialize all environment variables with .env file
dotenv.config()

// Pop envrionment variables into usable names
const {
  FASTIFY_LISTENING_PORT,
  TWILIO_AUTH_TOKEN,
  WEBHOOK_ENDPOINT,
  MESSAGE_STORE_DB
} = process.env

// Set some global constants for the app
const fastify = Fastify()
const db = bs3(MESSAGE_STORE_DB)

// Initialize database
// DEV NOTE: It is deliberately designed that the schema contains no primary keys,
//             so that the host can review and audit if there is a replay attack.
db.prepare(
  `
    CREATE TABLE IF NOT EXISTS 'twilio_messages' (
      'recevied_on' TEXT NOT NULL,
      'twilio_signature' TEXT NOT NULL,
      'twilio_idempotency_token' TEXT NOT NULL,
      'twilio_sms_message_sid' TEXT NOT NULL,
      'twilio_account_sid' TEXT NOT NULL,
      'twilio_api_version' TEXT NOT NULL,
      'webhook_endpoint' TEXT NOT NULL,
      'is_authentic_request' INTEGER NOT NULL,
      'raw_request' TEXT NOT NULL
    );
  `
).run()
db.prepare(
  `
    CREATE TABLE IF NOT EXISTS 'sms' (
      'hash_id' TEXT NOT NULL,
      'sender' TEXT NOT NULL,
      'receiver' TEXT NOT NULL,
      'body' TEXT NOT NULL,
      'received_on' TEXT NOT NULL
    );
  `
).run()

// Prepare insert statement for incoming messages
const twilioRequestInsertStatement = db.prepare(
  `
    INSERT INTO 'twilio_messages' VALUES (
      :received_on,
      :signature,
      :idempotency_token,
      :sms_message_sid,
      :account_sid,
      :api_version,
      :webhook_endpoint,
      :is_authentic_request,
      :raw_request
    );
  `
)
const smsInsertStatement = db.prepare(
  `
    INSERT INTO 'sms' VALUES (
      :requestUID,
      :sender,
      :receiver,
      :body,
      :received_on
    );
  `
)
const insertSMS = db.transaction(t => {
  twilioRequestInsertStatement.run({
    received_on: t.receivedOn,
    signature: t.TwilioSignature,
    idempotency_token: t.TwilioIdempotencyToken,
    sms_message_sid: t.requestBody.SmsMessageSid,
    account_sid: t.requestBody.AccountSid,
    api_version: t.requestBody.ApiVersion,
    webhook_endpoint: t.webhookEndpoint,
    is_authentic_request: +t.isAuthenticTwilioResponse,
    raw_request: JSON.stringify(t)
  })
  smsInsertStatement.run({
    requestUID: t.requestUID,
    sender: t.requestBody.From,
    receiver: t.requestBody.To,
    body: t.requestBody.Body,
    received_on: t.receivedOn
  })
})

// Override and enable SECURE_DELETE
db.pragma('secure_delete = TRUE')

// Enable fastify to parse form body
fastify.register(import('fastify-formbody'))

// Catch-all route for all incoming HTTP requests
fastify.all('*', async (request, reply) => {
  // Always return in JSON format
  reply.type('application/json')

  // Check if this is a Twilio request
  if (
    Object.keys(request.headers).some(k => ~k.indexOf('twilio'))
  ) {
    // Construct Twilio Object for later use
    const t = {}

    // Stuff inbound data from the request object
    t.receivedOn = new Date() / 1000
    t.TwilioSignature = request.headers['x-twilio-signature']
    t.TwilioIdempotencyToken = request.headers['i-twilio-idempotency-token']
    t.requestBody = request.body
    t.webhookEndpoint = WEBHOOK_ENDPOINT

    // Construct boolean from Twilio request validation response
    t.isAuthenticTwilioResponse = Twilio.validateRequest(
      TWILIO_AUTH_TOKEN,
      t.TwilioSignature,
      t.webhookEndpoint,
      t.requestBody
    )

    // Construct and inject hashed unique identifier for this request to form a controlled record
    t.requestUID = await argon2.hash(
      `${t.TwilioSignature}###${t.TwilioIdempotencyToken}###${t.requestBody.SmsMessageSid}`,
      {
        type: 2,
        hashLength: 384
      }
    )

    // Twilio Object is finalized, insert it into the database
    insertSMS(t)

    // Prompt the console we have inserted a record
    console.log(`[+] Inserted a ${t.isAuthenticTwilioResponse ? 'valid' : 'invalid'} Twilio SMS: ${t.requestBody.SmsMessageSid}`)

    // Only return acknowledgements to Twilio server if the message is authenticated,
    //   otherwise throw an error to both Twilio server and inside the console.
    if (t.isAuthenticTwilioResponse) {
      // Override the response type, and return an empty HTML TwilML response,
      //   to acknowledge the message without follow-up actions to the Twilio server.
      reply.type('text/html').code(200)
      return '<Response></Response>'
    } else {
      // Return an error response to Twilio server,
      //   and also throw error to console and/or log it.
      reply.code(400)
      return { error: 'Invalid Twilio request found.' }
    }
  }

  // Always return the same error message
  return { error: 'Not Authenticated.' }
})

// Listen on specific port or unix path
fastify.listen(FASTIFY_LISTENING_PORT, (err, address) => {
  if (err) throw err
  else console.log('listening on ' + address)
})
