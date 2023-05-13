import Token from '../models/Token'
import sendEmail from './sendEmail'
import env from '../utils/validateEnv'
import { Response } from 'express'
import crypto from 'crypto'

export default async (id: unknown, username: string, res: Response, email: string) => {
  const token = await new Token({
    userId: id,
    token: crypto.randomBytes(32).toString('hex')
  }).save()
  const url = `${env.BASE_URL}/verifyEmail/${id}/${token.token}`
  sendEmail(
    email,
    'Verify Email',
    `hello ${username}, welcome to our website. please click on this link: ${url} to verify your email, the link expires in 15mins`,
    res
  )
}
