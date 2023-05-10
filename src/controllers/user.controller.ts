import { RequestHandler } from 'express'
import { errMsg, successMsg } from '../utils/responseMsg'
import User from '../models/User'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import env from '../utils/validateEnv'
import nodemailer from 'nodemailer'

export const signUp: RequestHandler = async (req, res) => {
  const username = req.body.userName
  const email = req.body.email
  const password = req.body.password

  const existingUsername = await User.findOne({ username: username }).exec()

  if (existingUsername) {
    return errMsg(409, 'error', 'username already exist', res)
  }

  const existingEmail = await User.findOne({ email: email }).exec()

  if (existingEmail) {
    return errMsg(409, 'error', 'email already exist', res)
  }

  const passwordHashed = await bcrypt.hash(password, 10)

  const newUser = await User.create({
    username: username,
    email: email,
    password: passwordHashed
  })
  const payload = {
    name: newUser.username,
    email: newUser.email
  }

  successMsg(200, 'success', payload, res)
}

export const login: RequestHandler = async (req, res) => {
  const username = req.body.userName
  const password = req.body.password

  const user = await User.findOne({ username: username }).exec()

  if (!user) {
    return errMsg(400, 'error', 'invalid username', res)
  }

  const passwordMatch = await bcrypt.compare(password, user.password)

  if (!passwordMatch) {
    return errMsg(400, 'error', 'invalid password', res)
  }

  const payload = {
    name: user.username,
    email: user.email
  }
  const accessToken = jwt.sign(payload, env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })

  const refreshToken = jwt.sign({ username: payload.name }, env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' })

  // Create secure cookie with refresh token
  res.cookie('jwt', refreshToken, {
    httpOnly: true, //accessible only by web server
    secure: true, //https
    sameSite: 'none', //cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT
  })
  console.log(res.cookie)

  successMsg(200, 'success', accessToken, res)
}

export const refresh: RequestHandler = (req, res) => {
  const cookies = req.cookies

  if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' })

  const refreshToken = cookies.jwt

  jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET, async (err: unknown, decoded: any) => {
    if (err) return res.status(403).json({ message: 'Forbidden' })

    const foundUser = await User.findOne({ username: decoded.username }).exec()

    if (!foundUser) return res.status(401).json({ message: 'Unauthorized' })

    const payload = {
      name: foundUser.username,
      email: foundUser.email
    }

    const accessToken = jwt.sign(payload, env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })

    res.json({ accessToken })
  })
}

export const logout: RequestHandler = (req, res) => {
  const cookies = req.cookies
  if (!cookies?.jwt) return res.sendStatus(204) //No content
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'none', secure: true })
  res.json({ message: 'Cookie cleared' })
}

// forgot password functionality
export const forgotPassword: RequestHandler = async (req, res) => {
  const { email } = req.body
  const user = await User.findOne({ email: email }).exec()
  if (!user) {
    return res.status(401).json({
      status: 'error',
      error: 'Email doesnt exist'
    })
  }

  const payload = {
    id: user._id,
    name: user.username,
    email: user.email
  }
  const token = jwt.sign(payload, env.JWT_SECRET, { expiresIn: '30m' })
  const link = `https://preeminent-meringue-b5c8b0.netlify.app/resetPassword/${payload.id}/${token}`

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'ebuwonders.ep@gmail.com',
      pass: env.MAIL_PASSWORD
    }
  })
  const mailOptions = {
    from: 'ebuwonders.ep@gmail.com',
    to: email,
    subject: 'Password Reset',
    text: `hello ${payload.name}, you requested a change in your password you can reset it using this link ${link}.
The link expires in ten mins`
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

export const passwordReset: RequestHandler = async (req, res) => {
  const { id, token } = req.params
  const verify: any = jwt.verify(token, env.JWT_SECRET)
  const userid = verify.id
  const { password } = req.body
  const user = await User.findById({ _id: id }).exec()
  const user1 = await User.find()

  console.log(user1)

  if (!user) {
    return res.status(401).json({
      status: 'error',
      error: 'User does not exist'
    })
  }

  if (userid !== id) {
    return res.status(401).json({
      status: 'error',
      error: 'unauthorised user'
    })
  }
  const saltRounds = 10
  const salt = await bcrypt.genSalt(saltRounds)
  const hashedPassword = await bcrypt.hash(password, salt)

  await User.findOneAndUpdate(
    { id },
    {
      password: hashedPassword
    },
    {
      new: true
    }
  )
  return res.status(201).json({
    status: 'success',
    data: {
      message: 'Password Successfully Updated'
    }
  })
}
