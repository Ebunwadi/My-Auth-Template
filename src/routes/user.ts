import express from 'express'
import * as UserController from '../controllers/user.controller'
import validateSignUp from '../middleware/validations/validate'

const router = express.Router()

router.post('/signup', validateSignUp, UserController.signUp)

router.post('/login', UserController.login)

router.post('/logout', UserController.logout)

router.post('/forgotPassword', UserController.forgotPassword)

router.patch('/resetPassword/:id/:token', UserController.passwordReset)

export default router
