import 'express-async-errors'
import 'dotenv/config'
import express, { Express, Request, Response } from 'express'
import cors from 'cors'
import { errorHandler, notFound } from './middleware/errorHandler'
import env from './utils/validateEnv'
import helmet from 'helmet'
import mongoSanitize from 'express-mongo-sanitize'
import connectDB from './config/dbConn'
import user from './routes/user'

const app: Express = express()
const port = env.PORT

connectDB()
//To hide the tech used by the web server
app.disable('x-powered-by')
//security middlewares
app.use(helmet())
app.use(mongoSanitize())

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

app.get('/', (req: Request, res: Response) => {
  res.send('Express + TypeScript Server')
})

app.use('/api/users', user)

app.use(notFound)
app.use(errorHandler)

app.listen(port, () => {
  console.log(`⚡️[server]: The Server is running at http://localhost:${port}`)
})
