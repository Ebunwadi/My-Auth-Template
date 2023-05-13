import { InferSchemaType, model, Schema } from 'mongoose'

const userSchema = new Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  verified: { type: Boolean, default: false }
})

type User = InferSchemaType<typeof userSchema>

export default model<User>('User', userSchema)
