import { RequestHandler } from 'express'
import { errMsg, successMsg } from '../utils/responseMsg'
import User from '../models/User'
import Token from '../models/Token'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import env from '../utils/validateEnv'
import axios from 'axios'
import sendEmail from '../utils/sendEmail'
import crypto from 'crypto'

export const signUp: RequestHandler = async (req, res) => {
  if (req.body.googleAccessToken) {
    // gogole-auth
    const { googleAccessToken } = req.body
    const response = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: {
        Authorization: `Bearer ${googleAccessToken}`
      }
    })
    const username = response.data.given_name
    const email = response.data.email

    const existingUser = await User.findOne({ email })

    if (existingUser) return errMsg(409, 'error', 'email already exist, pls login', res)

    const newUser = await User.create({
      username: username,
      email: email
    })
    const token = await new Token({
      userId: newUser._id,
      token: crypto.randomBytes(32).toString('hex')
    }).save()
    const url = `${env.BASE_URL}/verifyEmail/${newUser.id}/${token.token}`
    sendEmail(
      email,
      'Verify Email',
      `hello ${username}, welcome to our website. please click on this link: ${url} to verify your email, the link expires in 15mins`,
      res
    )

    successMsg(200, 'success', 'An Email has been sent to your account please verify', res)
  } else {
    const username = req.body.username
    const email = req.body.email
    const password = req.body.password
    const password2 = req.body.confirmpassword

    const existingEmail = await User.findOne({ email: email }).exec()

    if (existingEmail) {
      return errMsg(409, 'error', 'email already exist', res)
    }

    if (!req.body.googleAccessToken && !password && !password2) {
      return errMsg(400, 'error', 'fill all fields', res)
    }

    const passwordHashed = await bcrypt.hash(password, 10)

    const newUser = await User.create({
      username: username,
      email: email,
      password: passwordHashed
    })
    const token = await new Token({
      userId: newUser._id,
      token: crypto.randomBytes(32).toString('hex')
    }).save()
    const url = `${env.BASE_URL}/verifyEmail/${newUser.id}/${token.token}`
    sendEmail(
      email,
      'Verify Email',
      `hello ${username}, welcome to our website. please click on this link: ${url} to verify your email, the link expires in 15mins`,
      res
    )

    successMsg(200, 'success', 'An Email has been sent to your account please verify', res)
  }
}

export const verifyEmail: RequestHandler = async (req, res) => {
  const user = await User.findOne({ _id: req.params.id })
  if (!user) return errMsg(400, 'error', 'bad request', res)

  const token = await Token.findOne({
    userId: user._id,
    token: req.params.token
  })
  if (!token) return errMsg(400, 'error', 'bad request', res)

  await User.updateOne({ _id: user._id, verified: true })
  await token.deleteOne({ _id: user._id })

  successMsg(200, 'success', 'email verified successfully', res)
}

export const login: RequestHandler = async (req, res) => {
  if (req.body.googleAccessToken) {
    // gogole-auth
    const { googleAccessToken } = req.body
    axios
      .get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
          Authorization: `Bearer ${googleAccessToken}`
        }
      })
      .then(async (response) => {
        const email = response.data.email
        const existingUser = await User.findOne({ email })

        if (!existingUser) return errMsg(400, 'error', 'invalid credentials', res)

        const payload = {
          name: existingUser.username,
          email: existingUser.email
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
      })
  } else {
    const password = req.body.password
    const email = req.body.email

    const user = await User.findOne({ email: email }).exec()

    if (!user) {
      return errMsg(400, 'error', 'invalid username or password', res)
    }
    const checkPwd = user.password
    if (!req.body.googleAccessToken && !password) {
      return errMsg(400, 'error', 'fill all fields', res)
    }
    if (checkPwd) {
      const passwordMatch = await bcrypt.compare(password, checkPwd)
      if (!passwordMatch) {
        return errMsg(400, 'error', 'invalid username or password', res)
      }
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
  const link = `env.BASE_URL/resetPassword/${payload.id}/${token}`

  sendEmail(
    email,
    'Password Reset',
    `hello ${payload.name}, you requested a change in your password you can reset it using this link ${link}.
      The link expires in ten mins`,
    res
  )
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
