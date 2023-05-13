import express from 'express'
import * as UserController from '../controllers/user.controller'

const router = express.Router()

router.post('/signup', UserController.signUp)

router.get('/verifyEmail/:id/:token', UserController.verifyEmail)

router.post('/login', UserController.login)

router.post('/logout', UserController.logout)

router.post('/forgotPassword', UserController.forgotPassword)

router.patch('/resetPassword/:id/:token', UserController.passwordReset)

export default router
