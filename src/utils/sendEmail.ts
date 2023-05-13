import nodemailer from 'nodemailer'
import env from '../utils/validateEnv'
import { Response } from 'express'

export default (email: string, subject: string, text: string, res: Response) => {
  const transporter = nodemailer.createTransport({
    service: env.MAIL_SERVICE,
    auth: {
      user: env.MAIL_USER,
      pass: env.MAIL_PASSWORD
    }
  })
  const mailOptions = {
    from: env.MAIL_USER,
    to: email,
    subject,
    text
  }

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      res.send(error)
      console.log(error)
    } else {
      res.json({
        status: 'success',
        message: `Email sent: ${info.response}`
      })
    }
  })
}
