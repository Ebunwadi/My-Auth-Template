import { InferSchemaType, model, Schema } from 'mongoose'

const tokenSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'User',
    unique: true
  },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }
})
type Token = InferSchemaType<typeof tokenSchema>

export default model<Token>('Token', tokenSchema)
